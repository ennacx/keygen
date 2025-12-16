/**
 * Helper variable serves as the reference to the `App.Helper` module or object,
 * providing access to various utility functions, constants, and methods that
 * support the application in performing helper operations.
 *
 * This variable is initialized from the `App.Helper` and is globally available
 * where the `Helper` is imported or defined.
 *
 * It is commonly used to group auxiliary or shared functionalities that
 * assist in the main business logic of the application, enhancing code
 * readability and maintainability.
 */
const Helper = App.Helper;

/**
 * The `Parser` is a reference to the `App.Parser` object.
 * It is used to handle and process data parsing operations within the application.
 * This object provides methods and utilities for parsing various types of data.
 */
const Parser = App.Parser;

/**
 * Represents an implementation or reference to the RFC 4253 specification,
 * which defines the SSH Transport Layer Protocol.
 *
 * The RFC 4253 outlines the structure and behavior of the transport layer in the SSH protocol,
 * including algorithms for key exchange, server authentication, encryption, and message integrity.
 *
 * This variable may encapsulate methods, constants, or configurations that adhere to the
 * rules and mechanisms specified in RFC 4253.
 */
const rfc4253 = App.RFC4253;

let keygenReduceNum = -1;

/**
 * Represents the cryptographic key material used in encryption and decryption processes.
 * This variable typically holds data required for performing cryptographic key operations
 * such as generating, importing, or using keys for secure data storage or transmission.
 */
let keyMaterial;

/**
 * Generates a SHA-256 fingerprint of the given data and converts it to a base64-encoded string without trailing equals signs.
 *
 * @async
 * @param {ArrayBuffer} blob - The input data to generate the fingerprint for.
 * @return {Promise<string>} A promise that resolves to the base64-encoded SHA-256 fingerprint.
 */
async function makeFingerprint(blob) {
	const digest = await crypto.subtle.digest("SHA-256", blob);

	return App.Bytes.toBase64(digest)
		// OpenSSH風に末尾の=を削る
		.replace(/=+$/, "");
}

/**
 * Generates an OpenSSH public key in RSA format from a given SPKI buffer.
 *
 * @async
 * @param {Uint8Array} spkiBuf - A buffer containing the SPKI (Subject Public Key Info) data.
 * @return {Promise<{raw: Uint8Array, pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
 *  - `raw`: RSA public key in OpenSSH format.
 *  - `pubkey`: The Base64-encoded RSA public key in OpenSSH format.
 *  - `fingerprint`: The fingerprint of the RSA public key.
 */
async function makeRsaOpenSSHPubKey(spkiBuf) {
	const parser = new Parser(spkiBuf);
	const rsa = parser.rsaSpki();
	const blob = App.Bytes.concat(
		rfc4253.writeString(rsa.name),
		rfc4253.writeMpint(rsa.e),
		rfc4253.writeMpint(rsa.n)
	);

	return {
		raw: blob,
		pubkey: App.Bytes.toBase64(blob),
		fingerprint: await makeFingerprint(blob)
	};
}

/**
 * Generates an OpenSSH ECDSA public key from the provided SPKI (Subject Public Key Information) buffer.
 *
 * @async
 * @param {Uint8Array} spkiBuf The buffer containing the SPKI data to parse the ECDSA public key from.
 * @return {Promise<{raw: Uint8Array, pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
 *  - `raw`: ECDSA public key in OpenSSH format.
 *  - `pubkey`: The Base64-encoded ECDSA public key in OpenSSH format.
 *  - `fingerprint`: The fingerprint of the ECDSA public key.
 */
async function makeEcdsaOpenSSHPubKey(spkiBuf) {
	const parser = new Parser(spkiBuf);
	const ecdsa = parser.ecdsaSpki();
	const blob = App.Bytes.concat(
		rfc4253.writeString(`ecdsa-sha2-${ecdsa.curveName}`), //string  ex. "ecdsa-sha2-nistp256"
		rfc4253.writeString(ecdsa.curveName), // string "nistp256"
		rfc4253.writeStringBytes(ecdsa.Q),    // string Q (0x04 || X || Y)
	);

	return {
		raw: blob,
		pubkey: App.Bytes.toBase64(blob),
		fingerprint: await makeFingerprint(blob)
	};
}

/**
 * Encrypts a PKCS#8 private key buffer using PBES2 with PBKDF2 and AES-256-CBC.
 *
 * @async
 * @param {ArrayBuffer|Uint8Array} pkcs8Buf The PKCS#8 private key buffer to be encrypted.
 * @param {string} passphrase The passphrase to derive the encryption key.
 * @param {Object} [opt={}] Optional parameters for encryption.
 * @param {number} [opt.iterations=100000] The number of PBKDF2 iterations.
 * @param {number} [opt.saltSize=16] The size of the salt for key derivation.
 * @return {Promise<Object>} An object containing the DER-encoded encrypted key and encryption parameters:
 *     - `der` (Uint8Array): The DER-encoded encrypted private key.
 *     - `params` (Object): The parameters used for encryption, including:
 *         - `salt` (Uint8Array): The random salt.
 *         - `iterations` (number): The PBKDF2 iteration count.
 *         - `keyLength` (number): The AES key length (default is 32 bytes for AES-256).
 *         - `iv` (Uint8Array): The initialization vector (IV) used for AES-CBC encryption.
 */
async function encryptPkcs8WithPBES2(pkcs8Buf, passphrase, opt = {}) {
	const buffer = (pkcs8Buf instanceof Uint8Array) ? pkcs8Buf : new Uint8Array(pkcs8Buf);

	const iterations = opt.iterations ?? 100_000;
	const saltSize   = opt.saltSize   ?? 16;
	const keyLength  = 32;   // AES-256
	const hash       = "SHA-256";

	// RandomSaltとIVの生成
	const salt = crypto.getRandomValues(new Uint8Array(saltSize));
	const iv   = crypto.getRandomValues(new Uint8Array(16));

	// ---- PBKDF2でAES-256キーを導出 (PBKDF2-HMAC-SHA256)
	const baseKey = await crypto.subtle.importKey("raw", Helper.toUtf8(passphrase), "PBKDF2", false, ["deriveKey"]);
	const aesKey = await crypto.subtle.deriveKey(
		{ name: "PBKDF2", salt, iterations, hash },
		baseKey,
		{ name: "AES-CBC", length: 256 },
		false,
		["encrypt"]
	);

	// ---- AES-256-CBC + PKCS#7 padding (WebCrypto Standard)
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, buffer));

	// ====== ここから ASN.1 (Abstract Syntax Notation 1) 組み立て ======

	// PRF AlgorithmIdentifier (hmacWithSHA256, NULL)
	const prfAlgId = App.PKCS8withPBES2.derSequence(
		App.PKCS8withPBES2.derConcat(
			App.PKCS8withPBES2.derOid(Helper.OID.HMAC_SHA256),
			App.PKCS8withPBES2.derNull()
		)
	);

	/*
	 * PBKDF2-params ::= SEQUENCE {
	 *   salt OCTET STRING,
	 *   iterationCount INTEGER,
	 *   keyLength INTEGER OPTIONAL,
	 *   prf AlgorithmIdentifier DEFAULT
	 * }
	 */
	const pbkdf2Params = App.PKCS8withPBES2.derSequence(
		App.PKCS8withPBES2.derConcat(
			App.PKCS8withPBES2.derOctetString(salt),
			App.PKCS8withPBES2.derInt(iterations),
			App.PKCS8withPBES2.derInt(keyLength),
			prfAlgId
		)
	);

	// KeyDerivationFunction AlgorithmIdentifier (PBKDF2)
	const kdfAlgId = App.PKCS8withPBES2.derSequence(
		App.PKCS8withPBES2.derConcat(
			App.PKCS8withPBES2.derOid(Helper.OID.PBKDF2),
			pbkdf2Params
		)
	);

	// EncryptionScheme AlgorithmIdentifier (AES-256-CBC, params=IV)
	const encSchemeAlgId = App.PKCS8withPBES2.derSequence(
		App.PKCS8withPBES2.derConcat(
			App.PKCS8withPBES2.derOid(Helper.OID.AES256_CBC),
			App.PKCS8withPBES2.derOctetString(iv)
		)
	);

	/*
	 * PBES2-params ::= SEQUENCE {
	 *   keyDerivationFunc,
	 *   encryptionScheme
	 * }
	 */
	const pbes2Params = App.PKCS8withPBES2.derSequence(
		App.PKCS8withPBES2.derConcat(
			kdfAlgId,
			encSchemeAlgId
		)
	);

	// encryptionAlgorithm AlgorithmIdentifier (PBES2 + params)
	const encryptionAlgorithm = App.PKCS8withPBES2.derSequence(
		App.PKCS8withPBES2.derConcat(
			App.PKCS8withPBES2.derOid(Helper.OID.PBES2),
			pbes2Params
		)
	);

	// encryptedData OCTET STRING
	const encryptedData = App.PKCS8withPBES2.derOctetString(ciphertext);

	/*
	 * EncryptedPrivateKeyInfo ::= SEQUENCE {
	 *   encryptionAlgorithm,
	 *   encryptedData
	 * }
	 */
	const encryptedPrivateKeyInfo = App.PKCS8withPBES2.derSequence(
		App.PKCS8withPBES2.derConcat(
			encryptionAlgorithm,
			encryptedData
		)
	);

	return {
		der: encryptedPrivateKeyInfo,
		params: { salt, iterations, keyLength, iv }
	};
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
 *                   - `salt` {Uint8Array}: The randomly generated salt used in the derivation process.
 *                   - `aeadKey` {Uint8Array}: The derived key in a byte array format.
 * @throws {Error} If the passphrase is empty or invalid.
 * @see https://app.unpkg.com/bcrypt-pbkdf@1.0.2/files/README.md
 */
const bcryptKdf = (passphrase, rounds = 16, saltLen = 16, returnBufferLen = 32) => {
	if(!passphrase){
		throw new Error("Empty passphrase");
	}

	const passBytes = Helper.toUtf8(passphrase);
	const saltBytes = crypto.getRandomValues(new Uint8Array(saltLen));
//	const saltBytes = Uint8Array.from("1234567890abcdef1234567890abcdef".match(/.{2}/g).map((h) => parseInt(h, 16))); // salt固定のテスト用
	const aeadKey   = new Uint8Array(returnBufferLen);

	// bcrypt-pbkdf.pbkdf(pass, passlen, salt, saltlen, key, keylen, rounds)
	CdnApp.bcryptPbkdf.pbkdf(
		passBytes,
		passBytes.length,
		saltBytes,
		saltBytes.length,
		aeadKey,
		aeadKey.length,
		rounds
	);

	console.log(Helper.implode([
		"AEAD-Key Hex Dump:",
		[...aeadKey].map((b) => b.toString(16).padStart(2, "0")).join("")
	]));

	return { salt: saltBytes, aeadKey };
};

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
function makeOpenSshPrivateBlock(keyType, publicBlob, privatePart, comment, opt = {}) {
	const check = crypto.getRandomValues(new Uint32Array(1))[0];

	let core;
	if(keyType === "ssh-rsa"){
		core = App.Bytes.concat(
			rfc4253.writeUint32(check),     // uint32     checkint1
			rfc4253.writeUint32(check),     // uint32     checkint2
			rfc4253.writeString(keyType),   // string     key type ("ssh-rsa" など)
			rfc4253.writeStringBytes(publicBlob),
			privatePart,                    // Uint8Array private key fields (鍵種別ごとの生フィールド)
			rfc4253.writeString(comment)    // string     comment
		);
	} else if(keyType.startsWith("ecdsa-sha2-") && opt.Q instanceof Uint8Array){
		core = App.Bytes.concat(
			rfc4253.writeUint32(check),      // uint32     checkint1
			rfc4253.writeUint32(check),      // uint32     checkint2
			rfc4253.writeString(keyType),    // string     key type ("ecdsa-sha2-nisp256" など)
			rfc4253.writeString(keyType.replace("ecdsa-sha2-", "")),   // string     curve ("nisp256" など)
			rfc4253.writeStringBytes(opt.Q), // Q
			privatePart,                     // Uint8Array private key fields (鍵種別ごとの生フィールド)
			rfc4253.writeString(comment)     // string     comment
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
function buildOpenSSHKeyV1({ cipherName, kdfName, kdfOptions, publicBlob, encryptedBlob }){
	/*
	 * AUTH_MAGIC "openssh-key-v1" 0x00
	 * string cipherName
	 * string kdfName
	 * string kdfOptions
	 * int    N
	 * string publicKey1           ← ここは平文
	 * string encryptedPrivateList ← ここだけ暗号化
	 */

	const magic = App.Bytes.concat(
		Helper.toUtf8("openssh-key-v1"),
		new Uint8Array([0x00])
	);

	return App.Bytes.concat(
		magic,
		rfc4253.writeString(cipherName),        // e.g., "aes256-ctr", "chacha20-poly1305@openssh.com"
		rfc4253.writeString(kdfName),           // "bcrypt"
		rfc4253.writeStringBytes(kdfOptions),   // string kdfOptions
		rfc4253.writeUint32(1),                 // 鍵の個数 N=1
		rfc4253.writeStringBytes(publicBlob),   // string publickey1
		rfc4253.writeStringBytes(encryptedBlob) // string encrypted_privates
	);
}

/**
 * Generates an OpenSSH private key in the "openssh-key-v1" format,
 * using the bcrypt-pbkdf key derivation function for optional encryption and ChaCha20-Poly1305 sealing.
 *
 * @async
 * @param {string} cipher - The encryption cipher for securing the private key (e.g., "aes256ctr", "cc20p1305").
 * @param {string} keyType - The type of key to generate, such as "ssh-rsa" or "ecdsa-sha2-<curve-name>".
 * @param {string} [passphrase] - An optional passphrase to encrypt the private key. If not provided, the key will be unencrypted.
 * @param {string} [comment] - An optional comment to include in the private key.
 * @return {Promise<string>} A Promise that resolves to the OpenSSH private key in PEM (Base64-encoded) format.
 * @throws {Error} If an unsupported key type is provided.
 */
async function makeOpenSSHPrivateKeyV1(cipher, keyType, passphrase, comment) {
	// 1. 公開鍵blobと秘密フィールドblobを作る
	let pubBlob;
	let privBlob;

	const opt = {};

	// RSA
	if(keyType === "ssh-rsa"){
		const rsa = await makeRsaOpenSSHPubKey(keyMaterial.spki); // SPKI → OpenSSH blob
		pubBlob   = rsa.raw;
		privBlob = keyMaterial.rsaPrivatePart();
	}
	// ECDSA
	else if(keyType.startsWith("ecdsa-sha2-")){
		const ecdsa = await makeEcdsaOpenSSHPubKey(keyMaterial.spki);
		pubBlob     = ecdsa.raw;

		privBlob = keyMaterial.ecdsaPrivatePart();
		opt.Q = keyMaterial.ecdsaQPoint();
	}
	// 不正
	else{
		throw new Error(`Unsupported key type for OpenSSH-key-v1: ${keyType}`);
	}

	// 2. 平文の秘密鍵ブロックを作成
	const plainBlob = makeOpenSshPrivateBlock(
		keyType,
		pubBlob,
		privBlob,
		comment || "",
		opt
	);

	const rounds = 16;

	let buildMaterial;

	// パスフレーズ無しなら暗号化せずにそのまま入れる
	if(!passphrase){
		buildMaterial = {
			cipherName:    "none",
			kdfName:       "none",
			kdfOptions:    new Uint8Array(0),
			publicBlob:    pubBlob,
			encryptedBlob: plainBlob
		};
	}
	// ChaCha20-Poly1305
	// @see https://www.stablelib.com/classes/_stablelib_chacha20poly1305.ChaCha20Poly1305.html
	else if(cipher === "cc20p1305"){
		// 3. bcrypt-pbkdfでAEADキー導出
		const kdf = bcryptKdf(passphrase, rounds, 16, 32);

		// 4. ChaCha20-Poly1305 で暗号化
		const nonce = crypto.getRandomValues(new Uint8Array(12)); // RFC7539ではノンス(iv)長は12バイトを指定
		const aead  = new CdnApp.Chacha20poly1305(kdf.aeadKey); // AEAD (Authenticated Encryption with Associated Data)
		const aad   = new Uint8Array(0); // 現状AADに突っ込むものがないので空のまま

		const sealed = new Uint8Array(plainBlob.length + 16); // ciphertext || tag (末尾16バイトがタグ) FIXME: 必ずpadding後に暗号化
		aead.seal(nonce, plainBlob, aad, sealed);

		// nonce || ciphertext || tag
		const encryptedBlob = App.Bytes.concat(
			nonce, // 復号時に使うノンスを付与
			sealed
		);

		// 5. KDFOptions & コンテナ
		const kdfOptions = App.Bytes.concat(
			rfc4253.writeStringBytes(kdf.salt), // string salt
			rfc4253.writeUint32(rounds)         // uint32 rounds
		);

		buildMaterial = {
			cipherName:   "chacha20-poly1305@openssh.com", // FIXME: "@openssh.com"を落とすと即アウト。大文字小文字も区別される
			kdfName:      "bcrypt",
			kdfOptions,
			publicBlob:   pubBlob,
			encryptedBlob
		};
	}
	// AES-256-CTR
	else if(cipher === "aes256ctr"){
		// 3. bcrypt-pbkdfでAEADキー導出
		const kdf = bcryptKdf(passphrase, rounds, 16, 48);

		// 4. AES-256-CTR で暗号化
		const aesKeyBytes = kdf.aeadKey.slice(0, 32); // 32バイト分
		const aesKey = await crypto.subtle.importKey(
			"raw",
			aesKeyBytes,
			{ name: "AES-CTR", length: 256 },
			false,
			["encrypt"]
		);

		const iv = kdf.aeadKey.slice(32, 48); // 16バイト分

		const encryptedBlob = new Uint8Array(
			await crypto.subtle.encrypt(
				{
					name: "AES-CTR",
					counter: iv,    // 16bytes
					length: 128     // カウンタ部のビット長
				},
				aesKey,
				plainBlob // openssh-key-v1のcheckintからpaddingまで
			)
		);

		// 5. KDFOptions & コンテナ
		const kdfOptions = App.Bytes.concat(
			rfc4253.writeStringBytes(kdf.salt), // string salt
			rfc4253.writeUint32(rounds)         // uint32 rounds
		);

		buildMaterial = {
			cipherName:   "aes256-ctr",
			kdfName:      "bcrypt",
			kdfOptions,
			publicBlob:   pubBlob,
			encryptedBlob
		};
	}
	// その他
	else{
		throw new Error(`Unsupported cipher for OpenSSH-key-v1: ${cipher}`);
	}

	const binary = buildOpenSSHKeyV1(buildMaterial);

	return Helper.toPEM(binary, App.Helper.PEM_LABEL.privateKey, 70, App.Helper.PEM_LABEL.opensshAdd);
}

/**
 * Adds random padding to the given data to align its length with the specified block size.
 *
 * This function ensures that the returned data is a multiple of the specified block size
 * by appending randomly generated padding bytes when necessary. If the input data length
 * is already a multiple of the block size, no padding is added, and the original data is returned.
 *
 * The padding bytes are generated using a cryptographically secure random number generator.
 *
 * @param {Uint8Array} plain - The input data to which padding will be added.
 * @param {number} [blockSize=16] - The block size to align the length of the data. Default is 16 bytes.
 * @returns {Uint8Array} The input data with random padding added, ensuring its length is a multiple of the block size.
 */
const addRandomPadding = (plain, blockSize = 16) => {
	const len = plain.length;
	const rem = len % blockSize;
	const padLen = (blockSize - rem) % blockSize; // 0～15

	// すでに`blockSize`の倍数ならパディング無しでOK
	if(padLen === 0){
		return plain;
	}

	const pad = crypto.getRandomValues(new Uint8Array(padLen));
	return App.Bytes.concat(plain, pad);
};

/**
 * Encrypts the given plaintext using AES-CBC encryption
 * with the provided key and initialization vector (IV) within PKCS#7 padding.
 *
 * @async
 * @param {Uint8Array} keyBytes - The encryption key as a sequence of bytes.
 * @param {Uint8Array} ivBytes - The initialization vector as a sequence of bytes.
 * @param {Uint8Array} plaintext - The plaintext data to be encrypted as a sequence of bytes.
 * @returns {Promise<Uint8Array>} A promise that resolves to the ciphertext as a sequence of bytes.
 */
const aesCbcEncryptRaw = async (keyBytes, ivBytes, plaintext) => {
	const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt"]);
	const ciphertext = await crypto.subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key, plaintext);

	return new Uint8Array(ciphertext);
};

/**
 * Encrypts the given plaintext using AES-CBC
 * with the provided key and initialization vector (IV) without padding.
 *
 * @param {Uint8Array} keyBytes - The encryption key as a sequence of bytes.
 * @param {Uint8Array} ivBytes - The initialization vector as a sequence of bytes.
 * @param {Uint8Array} plaintext - The plaintext data to be encrypted as a sequence of bytes.
 * @returns {Uint8Array} The encrypted ciphertext as a byte array.
 * @throws {Error} If the CryptoJS library is not available or properly initialized.
 */
const aesCbcEncryptRawNoPadding = (keyBytes, ivBytes, plaintext) => {
	if(!CryptoJS || !CryptoJS.lib.WordArray || typeof CryptoJS.lib.WordArray.create !== 'function'){
		throw new Error("CryptoJS is required for aesCbcEncryptNoPadding");
	}

	const keyWA = CryptoJS.lib.WordArray.create(keyBytes);
	const ivWA  = CryptoJS.lib.WordArray.create(ivBytes);
	const ptWA  = CryptoJS.lib.WordArray.create(plaintext);

	const enc = CryptoJS.AES.encrypt(ptWA, keyWA, {
		iv: ivWA,
		mode: CryptoJS.mode.CBC,
		padding: CryptoJS.pad.NoPadding // 必ずNoPaddingで！
	});

	// Crypto-JSはWord単位(32bit BigEndian)なので、Byteで分けていく (e.g., 0x11223344 → [0x11, 0x22, 0x33, 0x44])
	const ctWA = enc.ciphertext;
	const out = new Uint8Array(ctWA.sigBytes);
	for(let i = 0; i < ctWA.sigBytes; i++){
		out[i] = (ctWA.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
	}

	return out;
}

/**
 * Generates a cryptographic key pair based on the specified algorithm and options.
 *
 * @async
 * @param {string} name - The name of the cryptographic algorithm to use, such as 'RSA' or 'ECDSA'.
 * @param {Object} opt - An object containing options for key generation. This may include properties such as:
 *  - `len`: The key size for RSA keys.
 *  - `nist`: The named curve for ECDSA keys.
 *  - `comment`: An optional comment to include in the generated key.
 *  - `passphrase`: An optional passphrase for the keys.
 *  - `prefix`: A prefix string for keys.
 * @param {Function} [onProgress] - An optional callback function that receives progress updates. The function is called with two arguments: the current progress and the total steps.
 * @return {Promise<Object>} A promise that resolves to an object containing the generated key information:
 *  - `raw`: The generated raw key pair
 *  - `public`: The public key in SPKI encoded format.
 *  - `private`: The private key in PKCS#8 encoded format.
 *  - `openssh`: The public key in OpenSSH format.
 *  - `ppk`: The private key in PuTTY private key format.
 *  - `fingerprint`: The fingerprint of the generated public key.
 * @throws {Error} If an invalid algorithm name is provided, or if key generation fails.
 */
async function generateKey(name, opt, onProgress) {
	const comment    = (opt.comment && opt.comment !== '') ? opt.comment : "";
	const passphrase = (opt.passphrase && opt.passphrase !== '') ? opt.passphrase : null;
	const encryption = (passphrase !== null) ? "aes256-cbc" : "none";

	const kmCallback = async () => KeyMaterial.getInstance(name, { len: opt.len, curve: opt.nist });
	if(keygenReduceNum >= 0){
		const count = 7;
		let done = 0;
		const wrapWithProgress = (p) =>
			p.then((result) => {
				if(typeof onProgress === 'function'){
					onProgress(++done, count);
				}

				return result;
			});

		const kmBuffer = await Promise.all(
			Array.from(
				{ length: count },
				() => wrapWithProgress(kmCallback())
			)
		);

		keyMaterial = kmBuffer[keygenReduceNum % count];
	} else{
		keyMaterial = await kmCallback();

		if(typeof onProgress === 'function'){
			onProgress(1, 1);
		}
	}

	const makeOpenSshPubKey = (opt, pubkey, comment) =>
		`${opt.prefix} ${pubkey}` + ((comment !== undefined && comment !== '') ? ` ${comment}` : "");

	// 公開鍵・フィンガープリント・PuTTY-Private-Key
	let opensshPubkey;
	let opensshFingerprint;
	let ppk;
	switch(name){
		case "RSA":
			const rsaOpenssh = await makeRsaOpenSSHPubKey(keyMaterial.spki);

			opensshPubkey = makeOpenSshPubKey(opt, rsaOpenssh.pubkey, comment);
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${rsaOpenssh.fingerprint}`;
			ppk = await App.PPKv3.makeRsaPpkV3(opt.prefix, keyMaterial, comment, rsaOpenssh.raw, encryption, passphrase);
			break;

		case "ECDSA":
			const ecdsaOpenssh = await makeEcdsaOpenSSHPubKey(keyMaterial.spki);

			opensshPubkey = makeOpenSshPubKey(opt, ecdsaOpenssh.pubkey, comment);
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${ecdsaOpenssh.fingerprint}`;
			ppk = await App.PPKv3.makeEcdsaPpkV3(opt.prefix, keyMaterial, comment, ecdsaOpenssh.raw, encryption, passphrase);
			break;
	}

	return {
		material: keyMaterial,
		openssh: opensshPubkey,
		ppk: ppk,
		fingerprint: opensshFingerprint
	};
}
