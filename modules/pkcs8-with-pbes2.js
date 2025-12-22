import { OID } from './const.js';
import { DerHelper } from "./der-helper.js";

/**
 * PKCS8withPBES2 class provides functionality for encrypting PKCS#8 private keys
 * using PBES2 with PBKDF2 and AES-256-CBC.
 *
 * It supports secure handling of cryptographic parameters such as passphrase,
 * iterations, salt size, and key length to ensure high-security compliance.
 */
export class PKCS8withPBES2 {
	/**
	 * A variable used to store a secure passphrase.
	 * The passphrase is typically used for authentication or encryption purposes.
	 * Ensure the value assigned to this variable is kept confidential and adheres to
	 * security best practices, such as appropriate length and complexity.
	 */
	#passphrase;

	/**
	 * Represents the number of times a specific operation or process should be repeated.
	 *
	 * This variable is commonly used in loops or iterative processes to dictate
	 * how many iterations are required. The value assigned should be a positive integer
	 * unless otherwise specified by the context where it is used.
	 */
	#iterations;

	/**
	 * Represents the size of the cryptographic salt used in a hashing or encryption process.
	 * This value determines the length of the randomly generated salt string in bytes.
	 * A larger salt size increases the complexity and security of the cryptographic operation.
	 */
	#saltSize;

	/**
	 * Represents the length of a cryptographic key.
	 *
	 * This variable defines the size of the key in bits or bytes, depending on the context.
	 * It is typically used in encryption algorithms to determine the strength and security
	 * of the encryption key.
	 *
	 * @type {number}
	 * @constant
	 */
	#keyLength = 32; // AES-256

	/**
	 * Represents the hash algorithm used for cryptographic operations.
	 *
	 * This variable defines the specific hashing algorithm to be applied,
	 * which determines the method of encoding and how data integrity is maintained.
	 *
	 * @type {string}
	 * @constant
	 */
	#hash = 'SHA-256';

	constructor(passphrase, iterations = 100_000, saltSize = 16) {
		this.#passphrase = passphrase;
		this.#iterations = iterations;
		this.#saltSize   = saltSize;
	}

	/**
	 * Encrypts a PKCS#8 private key buffer using PBES2 with PBKDF2 and AES-256-CBC.
	 *
	 * @async
	 * @param {ArrayBuffer|Uint8Array} privDer The PKCS#8 private key buffer to be encrypted.
	 * @return {Promise<Object>} An object containing the DER-encoded encrypted key and encryption parameters:
	 *     - `encrypted` (Uint8Array): The DER-encoded encrypted private key.
	 *     - `params` (Object): The parameters used for encryption, including:
	 *         - `salt` (Uint8Array): The random salt.
	 *         - `iterations` (number): The PBKDF2 iteration count.
	 *         - `keyLength` (number): The AES key length (default is 32 bytes for AES-256).
	 *         - `iv` (Uint8Array): The initialization vector (IV) used for AES-CBC encryption.
	 */
	async encrypt(privDer) {
		const buffer = (privDer instanceof Uint8Array) ? privDer : new Uint8Array(privDer);

		// RandomSaltとIVの生成
		const salt = crypto.getRandomValues(new Uint8Array(this.#saltSize));
		const iv   = crypto.getRandomValues(new Uint8Array(16));

		// ---- PBKDF2でAES-256キーを導出 (PBKDF2-HMAC-SHA256)
		const utf8Passphrase = new TextEncoder().encode(this.#passphrase);
		const baseKey = await crypto.subtle.importKey('raw', utf8Passphrase, 'PBKDF2', false, ['deriveKey']);
		const aesKey = await crypto.subtle.deriveKey(
			{ name: 'PBKDF2', salt, iterations: this.#iterations, hash: this.#hash },
			baseKey,
			{ name: 'AES-CBC', length: 256 },
			false,
			['encrypt']
		);

		// ---- AES-256-CBC + PKCS#7 padding (WebCrypto Standard)
		const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, buffer));

		// ====== ここから ASN.1 (Abstract Syntax Notation 1) 組み立て ======

		// PRF AlgorithmIdentifier (hmacWithSHA256, NULL)
		const prfAlgId = DerHelper.concatSequence(
			DerHelper.oid(OID.HMAC_SHA256),
			DerHelper.nul()
		);

		/*
		 * PBKDF2-params ::= SEQUENCE {
		 *   salt OCTET STRING,
		 *   iterationCount INTEGER,
		 *   keyLength INTEGER OPTIONAL,
		 *   prf AlgorithmIdentifier DEFAULT
		 * }
		 */
		const pbkdf2Params = DerHelper.concatSequence(
			DerHelper.oct(salt),
			DerHelper.int(this.#iterations),
			DerHelper.int(this.#keyLength),
			prfAlgId
		);

		// KeyDerivationFunction AlgorithmIdentifier (PBKDF2)
		const kdfAlgId = DerHelper.concatSequence(
			DerHelper.oid(OID.PBKDF2),
			pbkdf2Params
		);

		// EncryptionScheme AlgorithmIdentifier (AES-256-CBC, params=IV)
		const encSchemeAlgId = DerHelper.concatSequence(
			DerHelper.oid(OID.AES256_CBC),
			DerHelper.oct(iv)
		);

		/*
		 * PBES2-params ::= SEQUENCE {
		 *   keyDerivationFunc,
		 *   encryptionScheme
		 * }
		 */
		const pbes2Params = DerHelper.concatSequence(
			kdfAlgId,
			encSchemeAlgId
		);

		// encryptionAlgorithm AlgorithmIdentifier (PBES2 + params)
		const encryptionAlgorithm = DerHelper.concatSequence(
			DerHelper.oid(OID.PBES2),
			pbes2Params
		);

		// encryptedData OCTET STRING
		const encryptedData = DerHelper.oct(ciphertext);

		/*
		 * EncryptedPrivateKeyInfo ::= SEQUENCE {
		 *   encryptionAlgorithm,
		 *   encryptedData
		 * }
		 */
		const encryptedPrivateKeyInfo = DerHelper.concatSequence(
			encryptionAlgorithm,
			encryptedData
		);

		return {
			encrypted: encryptedPrivateKeyInfo,
			salt: salt,
			iv: iv
		};
	}
}