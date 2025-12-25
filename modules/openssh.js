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
			pubBlob  = rsa.raw;
			privBlob = keyMaterial.rsaPrivatePart(); // FIXME: n, e, ..., qのMpint群
		}
		// ECDSA
		else if(keyType.startsWith('ecdsa-sha2-')){
			const ecdsa = await pubkey.ecdsa();
			pubBlob  = ecdsa.raw;
			privBlob = keyMaterial.ecdsaPrivatePart(); // FIXME: dのMpint
			opt.Q    = keyMaterial.ecdsaQPoint();
		}
		// EdDSA
		else if(keyType.startsWith('ssh-ed')){
			pubBlob  = keyMaterial.eddsaPublicKey(); // FIXME: publicBlob(="ssh-ed25519"+len+pub)
			privBlob = keyMaterial.eddsaPrivateKey(); // FIXME: EdDSAでは `seed || pub` を欲しがる
		}
		// 不正
		else{
			throw new Error(`Unsupported key type for OpenSSH-key-v1: ${keyType}`);
		}

		// ブロックサイズの取得
		opt.blockSize = OpenSSH.#getCipherBlockSize((!passphrase) ? 'none' : cipher);

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

		// EdDSAはouter publicの中身がblobに変わる
		if(keyType.startsWith('ssh-ed')){
			pubBlob = keyMaterial.eddsaPublicBlob();
		}

		// パスフレーズ無しなら暗号化せずにそのまま入れる
		if(!passphrase){
			buildMaterial = {
				cipherName:  'none',
				kdfName:     'none',
				kdfOptions:  new Uint8Array(0),
				publicBlob:  pubBlob,
				privateBlob: plainBlob
			};
		}
		// ChaCha20-Poly1305
		// @see https://www.stablelib.com/classes/_stablelib_chacha20poly1305.ChaCha20Poly1305.html
		else if(cipher === 'cc20p1305'){
			// salt生成
			const saltLen = 16;
			const salt = Bytes.generateSalt(saltLen);

			// 3. bcrypt-pbkdfでKDF導出
			const kdf = this.#bcryptKdf(passphrase, salt, rounds, 32);

			// 4. ChaCha20-Poly1305 で暗号化
			const nonce = Bytes.generateSalt(12);    // RFC7539ではノンス(iv)長は12byteを指定
			const aead  = new ChaCha20Poly1305(kdf); // AEAD (Authenticated Encryption with Associated Data)
			const aad   = new Uint8Array(0);         // FIXME: 現状AADに突っ込むものがないので空のまま

			const sealed = new Uint8Array(plainBlob.length + 16); // ciphertext || tag (末尾16バイトがタグ) FIXME: 必ずpadding後に暗号化
			aead.seal(nonce, plainBlob, aad, sealed);

			// nonce || ciphertext || tag
			const encryptedBlob = Bytes.concat(
				nonce, // 復号時に使うノンスを付与
				sealed
			);

			// 5. KDFOptions & コンテナ
			const kdfOptions = Bytes.concat(
				RFC4253.writeStringBytes(salt), // string salt
				RFC4253.writeUint32(rounds)     // uint32 rounds
			);

			buildMaterial = {
				cipherName: 'chacha20-poly1305@openssh.com', // FIXME: "@openssh.com"を落とすと即アウト。大文字小文字も区別される
				kdfName:    'bcrypt',
				kdfOptions,
				publicBlob:  pubBlob,
				privateBlob: encryptedBlob
			};
		}
		// AES-256-CTR
		else if(cipher === 'aes256ctr'){
			// salt生成
			const saltLen = 16;
			const salt = Bytes.generateSalt(saltLen);

			// 3. bcrypt-pbkdfでKDF導出
			const kdf = this.#bcryptKdf(passphrase, salt, rounds, 48);

			// 32/16バイトで切り出し
			const aesKeyBytes = kdf.slice(0, 32);  // 32byte
			const iv          = kdf.slice(32, 48); // 16byte

			// 4. AES-256-CTR で暗号化
			const aesKey = await crypto.subtle.importKey(
				'raw',
				aesKeyBytes,
				{
					name: 'AES-CTR',
					length: 256
				},
				false,
				['encrypt']
			);
			const encryptedBlob = new Uint8Array(
				await crypto.subtle.encrypt(
					{
						name:    'AES-CTR',
						counter: iv,        // 16byte
						length:  128        // カウンタ部のビット長 (16byte x8)
					},
					aesKey,
					plainBlob // checkintからpaddingまで
				)
			);

			// 5. KDFOptions & コンテナ
			const kdfOptions = Bytes.concat(
				RFC4253.writeStringBytes(salt), // string salt
				RFC4253.writeUint32(rounds)     // uint32 rounds
			);

			buildMaterial = {
				cipherName: 'aes256-ctr',
				kdfName:    'bcrypt',
				kdfOptions,
				publicBlob:  pubBlob,
				privateBlob: encryptedBlob
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
	 * Constructs an OpenSSH private key block with the specified parameters.
	 * This method handles different key types (`ssh-rsa`, `ecdsa-sha2-*`, `ssh-ed25519`)
	 * and includes padding for the resulting key block.
	 *
	 * @param {string} keyType The type of the key (e.g., "ssh-rsa", "ecdsa-sha2-*", "ssh-ed25519").
	 * @param {Uint8Array} publicBlob The public key data specific to the key type. Required for certain key types.
	 * @param {Uint8Array} privatePart The private key data, in the required format for the specified key type.
	 * @param {string} comment A comment string associated with the key.
	 * @param {Object} [opt] Optional parameters for configuring key block generation.
	 * @param {Uint8Array} [opt.Q] The public coordinate (Q) for ECDSA keys.
	 * @param {number} [opt.blockSize=16] The block size used for padding (defaults to 16).
	 * @return {Uint8Array} The resulting OpenSSH private key block, padded as necessary.
	 * @throws {Error} If the specified `keyType` is unsupported.
	 */
	static #makeOpenSshPrivateBlock(keyType, publicBlob, privatePart, comment, opt = {}) {
		const check = Bytes.getRandomUint32();

		let core;
		if(keyType === 'ssh-rsa'){
			core = Bytes.concat(
				RFC4253.writeUint32(check),           // uint32     checkint1
				RFC4253.writeUint32(check),           // uint32     checkint2
				RFC4253.writeString(keyType),         // string     key type ("ssh-rsa" など)
				privatePart,                          // Uint8Array private key part (concatenated mpint)
				RFC4253.writeString(comment)          // string     comment
			);
		} else if(keyType.startsWith('ecdsa-sha2-') && opt.Q instanceof Uint8Array){
			const curve = keyType.replace('ecdsa-sha2-', '');
			core = Bytes.concat(
				RFC4253.writeUint32(check),      // uint32     checkint1
				RFC4253.writeUint32(check),      // uint32     checkint2
				RFC4253.writeString(keyType),    // string     key type ("ecdsa-sha2-nisp256" など)
				RFC4253.writeString(curve),      // string     curve ("nisp256" など)
				RFC4253.writeStringBytes(opt.Q), // Uint8Array Q point
				privatePart,                     // Uint8Array private key part (concatenated mpint)
				RFC4253.writeString(comment)     // string     comment
			);
		} else if(keyType.startsWith('ssh-ed')){
			core = Bytes.concat(
				RFC4253.writeUint32(check),            // uint32     checkint1
				RFC4253.writeUint32(check),            // uint32     checkint2
				RFC4253.writeString(keyType),          // string     key type ("ssh-ed25519" など)
				RFC4253.writeStringBytes(publicBlob),  // Uint8Array pubkey
				RFC4253.writeStringBytes(privatePart), // Uint8Array private key part (seed || pub)
				RFC4253.writeString(comment)           // string     comment
			);
		} else{
			throw new Error(`Unsupported key type for OpenSSH private key block: ${keyType}`);
		}

		// パディングで埋めて返却
		return this.#addPadding(core, opt.blockSize || 16);
	}

	/**
	 * Builds an OpenSSH key in version 1 format by combining specified components into a structured binary representation.
	 *
	 * @param {Object} params - The input parameters for creating the OpenSSH key.
	 * @param {string} params.cipherName - The cipher name used for encryption, e.g., "chacha20-poly1305@openssh.com".
	 * @param {string} params.kdfName - The key derivation function name, e.g., "bcrypt".
	 * @param {Uint8Array} params.kdfOptions - The key derivation function options as a byte array.
	 * @param {Uint8Array} params.publicBlob - The public key data as a byte array.
	 * @param {Uint8Array} params.privateBlob - The encrypted(or plain) private key data as a byte array.
	 * @return {Uint8Array} The combined byte array representing the OpenSSH key in version 1 format.
	 */
	static #buildOpenSSHKeyV1({ cipherName, kdfName, kdfOptions, publicBlob, privateBlob }){
		/*
		 * [
		 *   AUTH_MAGIC "openssh-key-v1\0"
		 *   string cipherName
		 *   string kdfName
		 *   string kdfOptions
		 *   int    N
		 *   string publicKey1  ← ここは平文
		 *   string privateList ← ここだけ暗号化
		 * ]
		 */

		const magic = Bytes.concat(
			Helper.toUtf8('openssh-key-v1'),
			Uint8Array.from([0x00])
		);

		return Bytes.concat(
			magic,
			RFC4253.writeString(cipherName),      // e.g., "aes256-ctr", "chacha20-poly1305@openssh.com"
			RFC4253.writeString(kdfName),         // "bcrypt"
			RFC4253.writeStringBytes(kdfOptions), // string kdfOptions
			RFC4253.writeUint32(1),               // 鍵の個数 N=1
			RFC4253.writeStringBytes(publicBlob), // string publickey1
			RFC4253.writeStringBytes(privateBlob) // string encrypted(or plain) privates
		);
	}

	/**
	 * Generates a key derivation based on the bcrypt-PBKDF algorithm.
	 *
	 * @param {string} passphrase - The passphrase to derive the key from.
	 * @param {Uint8Array} salt - The cryptographic salt for the key derivation process.
	 * @param {number} [rounds=16] - The number of iterations to use for the key derivation (higher values increase computational cost).
	 * @param {number} [kdfBytesLen=32] - The desired length in bytes of the derived key.
	 * @throws {Error} Throws an error if the bcrypt-pbkdf implementation is not found.
	 * @throws {Error} Throws an error if the given passphrase is empty.
	 * @returns {Uint8Array} Returns a Uint8Array containing the derived key bytes.
	 */
	static #bcryptKdf = (passphrase, salt, rounds = 16, kdfBytesLen = 32) => {
		if(!bcryptPbkdf || typeof bcryptPbkdf.pbkdf !== 'function'){
			throw new Error('bcrypt-pbkdf not found');
		} else if(!passphrase){
			throw new Error('Empty passphrase');
		}

		const passBytes = Helper.toUtf8(passphrase);
		const kdfBytes  = new Uint8Array(kdfBytesLen);

		// bcrypt-pbkdf.pbkdf(pass, passlen, salt, saltlen, key, keylen, rounds)
		bcryptPbkdf.pbkdf(
			passBytes,
			passBytes.length,
			salt,
			salt.length,
			kdfBytes,
			kdfBytes.length,
			rounds
		);

		console.log(Helper.implode([
			'bcrypt-pbkdf Key Hex-Dump:',
			Helper.hexPad(kdfBytes)
		]));

		return kdfBytes;
	}

	/**
	 * Determines the block size for a given cipher based on its name.
	 *
	 * @param {string} cipherName - The name of the cipher whose block size is to be determined.
	 * @return {number} The block size of the cipher in bytes.
	 */
	static #getCipherBlockSize(cipherName) {
		// パスワード無しの場合
		if(cipherName === 'none'){
			return 8;
		}
		// aes256-ctr等
		else if(cipherName.endsWith('ctr')){
			return 16;
		}
		// aes256-cbc等
		else if(cipherName.endsWith('cbc')){
			return 16;
		}
		// ChaCha20はひとまず
		else if(cipherName.includes('cc20p1305')){
			return 8;
		}

		// 迷ったら16
		return 16;
	}

	/**
	 * Adds padding to a given buffer to ensure its length becomes a multiple of the specified block size.
	 * The method appends padding bytes at the end of the buffer, where each byte contains incremental values starting from 1.
	 *
	 * @param {Uint8Array} buffer - The input buffer that needs to be padded.
	 * @param {number} blockSize - The block size to which the buffer's length should be aligned.
	 * @return {Uint8Array} A new buffer with the required padding, ensuring the total length is a multiple of the block size.
	 */
	static #addPadding(buffer, blockSize) {
		const bufferLen = buffer.length;
		const remain    = bufferLen % blockSize;

		let padLen = blockSize - remain;

		// 割り切れる場合でもパディングは必要
		if(padLen === 0){
			padLen = blockSize;
		}

		// blockSizeで割りきれる数に拡張
		const out = new Uint8Array(bufferLen + padLen);

		// 先頭に入力バッファをセット
		out.set(buffer, 0);

		// 末尾にパディングを突っ込んでいく
		for(let i = 0; i < padLen; i++){
			// 1,2,3,... とインクリメントで埋める慣習
			out[bufferLen + i] = (i + 1) & 0xFF;
		}

		return out;
	}
}