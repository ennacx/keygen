// CDN
import bcryptPbkdf from 'bcrypt-pbkdf';
import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305';
// Local
import { PEM_LABEL } from './const.js';
import { Bytes } from './bytes.js';
import { Helper } from './helper.js';
import { RFC4253 } from './rfc4253.js';
import { PubKey } from './pubkey.js';

/**
 * Provides utilities for generating and managing OpenSSH keys and fingerprints.
 * This class includes methods for creating SHA-256 fingerprints, generating OpenSSH private keys
 * in OpenSSH-key-v1 format, and producing binary private key blocks compatible with OpenSSH specifications.
 */
export class OpenSSH {
	/**
	 * Generates an OpenSSH private key in OpenSSH-key-v1 format.
	 *
	 * @param {string} cipher - The encryption cipher to use (e.g., "cc20p1305", "aes256ctr"). Use "none" for no encryption.
	 * @param {string} keyType - The type of the key (e.g., "ssh-rsa", "ecdsa-sha2-<curve-name>").
	 * @param {object} keyMaterial - The material of the key containing key-specific cryptographic details.
	 * @param {string} passphrase - The passphrase to encrypt the key, or an empty string for no encryption.
	 * @param {string} comment - A comment to append to the key for identification purposes.
	 * @return {Promise<string>} A promise that resolves to the OpenSSH private key in PEM format.
	 */
	static async makeOpenSSHPrivateKeyV1(cipher, keyType, keyMaterial, passphrase, comment) {
		// 1. 公開鍵blobと秘密フィールドblobを作る
		let pubBlob;
		let privBlob;

		const pubkey = new PubKey(keyMaterial.spki);
		const opt = {};

		// RSA
		if(keyType === 'ssh-rsa'){
			const rsa = await pubkey.rsa();
			pubBlob   = rsa.raw;
			privBlob  = keyMaterial.rsaPrivatePart();
		}
		// ECDSA
		else if(keyType.startsWith('ecdsa-sha2-')){
			const ecdsa = await pubkey.ecdsa();
			pubBlob     = ecdsa.raw;
			privBlob    = keyMaterial.ecdsaPrivatePart();
			opt.Q       = keyMaterial.ecdsaQPoint();
		}
		// 不正
		else{
			throw new Error(`Unsupported key type for OpenSSH-key-v1: ${keyType}`);
		}

		// 2. 平文の秘密鍵ブロックを作成
		const plainBlob = this.#makeOpenSshPrivateBlock(
			keyType,
			pubBlob,
			privBlob,
			comment || '',
			opt
		);

		const rounds = 16;

		let buildMaterial;

		// パスフレーズ無しなら暗号化せずにそのまま入れる
		if(!passphrase){
			buildMaterial = {
				cipherName:    'none',
				kdfName:       'none',
				kdfOptions:    new Uint8Array(0),
				publicBlob:    pubBlob,
				encryptedBlob: plainBlob
			};
		}
			// ChaCha20-Poly1305
		// @see https://www.stablelib.com/classes/_stablelib_chacha20poly1305.ChaCha20Poly1305.html
		else if(cipher === 'cc20p1305'){
			// 3. bcrypt-pbkdfでAEADキー導出
			const kdf = this.#bcryptKdf(passphrase, rounds, 16, 32);

			// 4. ChaCha20-Poly1305 で暗号化
			const nonce = crypto.getRandomValues(new Uint8Array(12)); // RFC7539ではノンス(iv)長は12バイトを指定
			const aead  = new ChaCha20Poly1305(kdf.aeadKey); // AEAD (Authenticated Encryption with Associated Data)
			const aad   = new Uint8Array(0); // 現状AADに突っ込むものがないので空のまま

			const sealed = new Uint8Array(plainBlob.length + 16); // ciphertext || tag (末尾16バイトがタグ) FIXME: 必ずpadding後に暗号化
			aead.seal(nonce, plainBlob, aad, sealed);

			// nonce || ciphertext || tag
			const encryptedBlob = Bytes.concat(
				nonce, // 復号時に使うノンスを付与
				sealed
			);

			// 5. KDFOptions & コンテナ
			const kdfOptions = Bytes.concat(
				RFC4253.writeStringBytes(kdf.salt), // string salt
				RFC4253.writeUint32(rounds)         // uint32 rounds
			);

			buildMaterial = {
				cipherName:   'chacha20-poly1305@openssh.com', // FIXME: "@openssh.com"を落とすと即アウト。大文字小文字も区別される
				kdfName:      'bcrypt',
				kdfOptions,
				publicBlob:   pubBlob,
				encryptedBlob
			};
		}
		// AES-256-CTR
		else if(cipher === 'aes256ctr'){
			// 3. bcrypt-pbkdfでAEADキー導出
			const kdf = this.#bcryptKdf(passphrase, rounds, 16, 48);

			// 4. AES-256-CTR で暗号化
			const aesKeyBytes = kdf.aeadKey.slice(0, 32); // 32バイト分
			const aesKey = await crypto.subtle.importKey(
				'raw',
				aesKeyBytes,
				{ name: 'AES-CTR', length: 256 },
				false,
				['encrypt']
			);

			const iv = kdf.aeadKey.slice(32, 48); // 16バイト分

			const encryptedBlob = new Uint8Array(
				await crypto.subtle.encrypt(
					{
						name: 'AES-CTR',
						counter: iv,    // 16bytes
						length: 128     // カウンタ部のビット長
					},
					aesKey,
					plainBlob // openssh-key-v1のcheckintからpaddingまで
				)
			);

			// 5. KDFOptions & コンテナ
			const kdfOptions = Bytes.concat(
				RFC4253.writeStringBytes(kdf.salt), // string salt
				RFC4253.writeUint32(rounds)         // uint32 rounds
			);

			buildMaterial = {
				cipherName:   'aes256-ctr',
				kdfName:      'bcrypt',
				kdfOptions,
				publicBlob:   pubBlob,
				encryptedBlob
			};
		}
		// その他
		else{
			throw new Error(`Unsupported cipher for OpenSSH-key-v1: ${cipher}`);
		}

		const binary = this.#buildOpenSSHKeyV1(buildMaterial);

		return Helper.toPEM(binary, PEM_LABEL.privateKey, 70, PEM_LABEL.opensshAdd);
	}

	/**
	 * Generates an OpenSSH private key block in binary format.
	 * The method constructs the binary structure for an OpenSSH private key by combining the private key fields,
	 * public key blob, comment, and other required metadata according to OpenSSH specifications.
	 * Includes padding to ensure the block size is a multiple of 8 bytes.
	 *
	 * @param {string} keyType - The type of the SSH key (e.g., "ssh-rsa").
	 * @param {Uint8Array} publicBlob - The public key blob in binary format.
	 * @param {Uint8Array} privatePart - The private key fields specific to the key type in binary format.
	 * @param {string} comment - A comment describing the key.
	 * @return {Uint8Array} A Uint8Array representing the complete OpenSSH private key block in binary form.
	 */
	static #makeOpenSshPrivateBlock(keyType, publicBlob, privatePart, comment, opt = {}) {
		const check = crypto.getRandomValues(new Uint32Array(1))[0];

		let core;
		if(keyType === 'ssh-rsa'){
			core = Bytes.concat(
				RFC4253.writeUint32(check),     // uint32     checkint1
				RFC4253.writeUint32(check),     // uint32     checkint2
				RFC4253.writeString(keyType),   // string     key type ("ssh-rsa" など)
				RFC4253.writeStringBytes(publicBlob),
				privatePart,                    // Uint8Array private key fields (鍵種別ごとの生フィールド)
				RFC4253.writeString(comment)    // string     comment
			);
		} else if(keyType.startsWith('ecdsa-sha2-') && opt.Q instanceof Uint8Array){
			core = Bytes.concat(
				RFC4253.writeUint32(check),      // uint32     checkint1
				RFC4253.writeUint32(check),      // uint32     checkint2
				RFC4253.writeString(keyType),    // string     key type ("ecdsa-sha2-nisp256" など)
				RFC4253.writeString(keyType.replace('ecdsa-sha2-', '')),   // string     curve ("nisp256" など)
				RFC4253.writeStringBytes(opt.Q), // Q
				privatePart,                     // Uint8Array private key fields (鍵種別ごとの生フィールド)
				RFC4253.writeString(comment)     // string     comment
			);
		}

		// パディング (OpenSSHはblockSize=8)
		const blockSize = 8;
		const rem = core.length % blockSize;
		const padLen = (rem === 0) ? 0 : (blockSize - rem);
		const out = new Uint8Array(core.length + padLen); // blockSizeで割りきれる数に拡張
		out.set(core, 0);
		for(let i = 0; i < padLen; i++){
			out[core.length + i] = (i + 1) & 0xFF; // 1,2,3,... で埋める慣習
		}

		return out;
	}

	/**
	 * Builds an OpenSSH key in version 1 format by combining specified components into a structured binary representation.
	 *
	 * @param {Object} params - The input parameters for creating the OpenSSH key.
	 * @param {string} params.cipherName - The cipher name used for encryption, e.g., "chacha20-poly1305@openssh.com".
	 * @param {string} params.kdfName - The key derivation function name, e.g., "bcrypt".
	 * @param {Uint8Array} params.kdfOptions - The key derivation function options as a byte array.
	 * @param {Uint8Array} params.publicBlob - The public key data as a byte array.
	 * @param {Uint8Array} params.encryptedBlob - The encrypted private key data as a byte array.
	 * @return {Uint8Array} The combined byte array representing the OpenSSH key in version 1 format.
	 */
	static #buildOpenSSHKeyV1({ cipherName, kdfName, kdfOptions, publicBlob, encryptedBlob }){
		/*
		 * [
		 *   AUTH_MAGIC "openssh-key-v1" 0x00
		 *   string cipherName
		 *   string kdfName
		 *   string kdfOptions
		 *   int    N
		 *   string publicKey1           ← ここは平文
		 *   string encryptedPrivateList ← ここだけ暗号化
		 * ]
		 */

		const magic = Bytes.concat(
			Helper.toUtf8('openssh-key-v1'),
			new Uint8Array([0x00])
		);

		return Bytes.concat(
			magic,
			RFC4253.writeString(cipherName),        // e.g., "aes256-ctr", "chacha20-poly1305@openssh.com"
			RFC4253.writeString(kdfName),           // "bcrypt"
			RFC4253.writeStringBytes(kdfOptions),   // string kdfOptions
			RFC4253.writeUint32(1),                 // 鍵の個数 N=1
			RFC4253.writeStringBytes(publicBlob),   // string publickey1
			RFC4253.writeStringBytes(encryptedBlob) // string encrypted_privates
		);
	}

	/**
	 * Generates a derived key using the bcrypt-PBKDF function.
	 *
	 * This function creates a cryptographic key based on a given passphrase and returns
	 * both the derived key and the randomly generated salt. It uses bcrypt-PBKDF, a
	 * password-based key derivation function, which is a derivation of the bcrypt algorithm,
	 * to securely derive keys for cryptographic purposes.
	 *
	 * @param {string} passphrase - The input passphrase to be used for deriving the key.
	 * @param {number} [rounds=16] - The number of iterations for key derivation.
	 *                               A higher value increases security at the cost of computational performance.
	 * @param {number} [saltLen=16] - The length of the salt to be generated in bytes.
	 * @param {number} [returnBufferLen=32] - The length of the derived key to generate in bytes.
	 * @returns {Object} An object containing the following properties:
	 *   - `salt` {Uint8Array}: The randomly generated salt used in the derivation process.
	 *   - `aeadKey` {Uint8Array}: The derived key in a byte array format.
	 * @throws {Error} If the passphrase is empty or invalid.
	 * @see https://app.unpkg.com/bcrypt-pbkdf@1.0.2/files/README.md
	 */
	static #bcryptKdf = (passphrase, rounds = 16, saltLen = 16, returnBufferLen = 32) => {
		if(!bcryptPbkdf || typeof bcryptPbkdf.pbkdf !== 'function'){
			throw new Error('bcrypt-pbkdf not found');
		} else if(!passphrase){
			throw new Error('Empty passphrase');
		}

		const passBytes = Helper.toUtf8(passphrase);
		const saltBytes = crypto.getRandomValues(new Uint8Array(saltLen));
//		const saltBytes = Uint8Array.from('1234567890abcdef1234567890abcdef'.match(/.{2}/g).map((h) => parseInt(h, 16))); // salt固定のテスト用
		const aeadKey   = new Uint8Array(returnBufferLen);

		// bcrypt-pbkdf.pbkdf(pass, passlen, salt, saltlen, key, keylen, rounds)
		bcryptPbkdf.pbkdf(
			passBytes,
			passBytes.length,
			saltBytes,
			saltBytes.length,
			aeadKey,
			aeadKey.length,
			rounds
		);

		console.log(Helper.implode([
			'AEAD-Key Hex Dump:',
			Helper.hexPad(aeadKey)
		]));

		return { salt: saltBytes, aeadKey };
	};
}