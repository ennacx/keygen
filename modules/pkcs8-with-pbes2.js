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
	#hash = "SHA-256";

	constructor(passphrase, iterations = 100_000, saltSize = 16) {
		this.#passphrase = passphrase;
		this.#iterations = iterations;
		this.#saltSize = saltSize;
	}

	/**
	 * Encrypts a PKCS#8 private key buffer using PBES2 with PBKDF2 and AES-256-CBC.
	 *
	 * @async
	 * @param {ArrayBuffer|Uint8Array} privDer The PKCS#8 private key buffer to be encrypted.
	 * @return {Promise<Object>} An object containing the DER-encoded encrypted key and encryption parameters:
	 *     - `der` (Uint8Array): The DER-encoded encrypted private key.
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
		const baseKey = await crypto.subtle.importKey("raw", Helper.toUtf8(this.#passphrase), "PBKDF2", false, ["deriveKey"]);
		const aesKey = await crypto.subtle.deriveKey(
			{ name: "PBKDF2", salt, iterations: this.#iterations, hash: this.#hash },
			baseKey,
			{ name: "AES-CBC", length: 256 },
			false,
			["encrypt"]
		);

		// ---- AES-256-CBC + PKCS#7 padding (WebCrypto Standard)
		const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, buffer));

		// ====== ここから ASN.1 (Abstract Syntax Notation 1) 組み立て ======

		// PRF AlgorithmIdentifier (hmacWithSHA256, NULL)
		const prfAlgId = this.#concatSequence(
			this.#derOid(Helper.OID.HMAC_SHA256),
			this.#derNull()
		);

		/*
		 * PBKDF2-params ::= SEQUENCE {
		 *   salt OCTET STRING,
		 *   iterationCount INTEGER,
		 *   keyLength INTEGER OPTIONAL,
		 *   prf AlgorithmIdentifier DEFAULT
		 * }
		 */
		const pbkdf2Params = this.#concatSequence(
			this.#derOctetString(salt),
			this.#derInt(this.#iterations),
			this.#derInt(this.#keyLength),
			prfAlgId
		);

		// KeyDerivationFunction AlgorithmIdentifier (PBKDF2)
		const kdfAlgId = this.#concatSequence(
			this.#derOid(Helper.OID.PBKDF2),
			pbkdf2Params
		);

		// EncryptionScheme AlgorithmIdentifier (AES-256-CBC, params=IV)
		const encSchemeAlgId = this.#concatSequence(
			this.#derOid(Helper.OID.AES256_CBC),
			this.#derOctetString(iv)
		);

		/*
		 * PBES2-params ::= SEQUENCE {
		 *   keyDerivationFunc,
		 *   encryptionScheme
		 * }
		 */
		const pbes2Params = this.#concatSequence(
			kdfAlgId,
			encSchemeAlgId
		);

		// encryptionAlgorithm AlgorithmIdentifier (PBES2 + params)
		const encryptionAlgorithm = this.#concatSequence(
			this.#derOid(Helper.OID.PBES2),
			pbes2Params
		);

		// encryptedData OCTET STRING
		const encryptedData = this.#derOctetString(ciphertext);

		/*
		 * EncryptedPrivateKeyInfo ::= SEQUENCE {
		 *   encryptionAlgorithm,
		 *   encryptedData
		 * }
		 */
		const encryptedPrivateKeyInfo = this.#concatSequence(
			encryptionAlgorithm,
			encryptedData
		);

		return {
			der: encryptedPrivateKeyInfo,
			salt: salt,
			iv: iv
		};
	}

	/**
	 * Concatenates multiple Uint8Array arrays into a single Uint8Array.
	 *
	 * This function takes any number of Uint8Array instances as arguments,
	 * calculates the total length, and creates a new Uint8Array to hold
	 * the concatenated result. It iteratively copies each array into the
	 * created output array.
	 *
	 * @param {...Uint8Array} arrays - One or more Uint8Array instances to concatenate.
	 * @returns {Uint8Array} A new Uint8Array containing the concatenation of all input arrays.
	 */
	#derConcat(...arrays) {
		const len = arrays.reduce((n, a) => n + a.length, 0);
		const out = new Uint8Array(len);

		let off = 0;
		for(const a of arrays){
			out.set(a, off);
			off += a.length;
		}

		return out;
	}

	/**
	 * Generates DER-encoded length encoding for a given length.
	 *
	 * If the length is less than 128, it uses the short form encoding.
	 * For lengths equal to or greater than 128, it employs the long form encoding.
	 *
	 * @param {number} len The length value to encode.
	 * @returns {Uint8Array} A Uint8Array containing the DER-encoded length.
	 * @throws {TypeError} Throws if the input length is not a number.
	 */
	#derLen(len) {
		if(len < 0x80){
			return new Uint8Array([len]);
		}

		// long form
		const bytes = [];

		let v = len;
		while(v > 0){
			bytes.unshift(v & 0xFF);
			v >>= 8;
		}

		return new Uint8Array([0x80 | bytes.length, ...bytes]);
	}

	/**
	 * Constructs a DER (Distinguished Encoding Rules) encoded sequence.
	 *
	 * This function takes a content input, ensures it is of type Uint8Array,
	 * and constructs a DER encoded sequence by concatenating a prefix byte (0x30),
	 * the DER encoded length of the content, and the content itself.
	 *
	 * @param {Uint8Array|Array|ArrayBuffer} content - The content to be included in the DER sequence. If not a Uint8Array, it will be converted.
	 * @returns {Uint8Array} - The resulting DER encoded sequence.
	 */
	#derSequence(content) {
		const c = (content instanceof Uint8Array) ? content : new Uint8Array(content);

		return this.#derConcat(new Uint8Array([0x30]), this.#derLen(c.length), c);
	}

	/**
	 * Encodes the given input bytes as a DER-encoded Octet String.
	 *
	 * The function takes an array of bytes, either as a regular array or a `Uint8Array`,
	 * and constructs a DER-encoded Octet String. This involves adding the appropriate
	 * identifier byte (0x04), a length indicator, and the byte content.
	 *
	 * @param {Uint8Array | Array} bytes - The input bytes to encode as a DER Octet String. If the input is not a `Uint8Array`, it will be converted into one.
	 * @returns {Uint8Array} A new `Uint8Array` containing the DER-encoded Octet String representation of the input.
	 */
	#derOctetString(bytes) {
		const b = (bytes instanceof Uint8Array) ? bytes : new Uint8Array(bytes);

		return this.#derConcat(new Uint8Array([0x04]), this.#derLen(b.length), b);
	}

	/**
	 * Generates a DER-encoded integer representation of the given number. (`iterationCount / keyLength`用。32bitくらい想定)
	 *
	 * The function converts a number to its big-endian byte array representation.
	 * Handles edge cases such as zero and ensures that the DER encoding rules
	 * for signed integers are followed (e.g., avoids leading bits being misinterpreted
	 * as a sign bit by adding a leading 0x00 byte if necessary).
	 *
	 * @param {number} num - The unsigned integer to be converted into DER format.
	 * @returns {Uint8Array} The DER-encoded representation of the integer.
	 */
	#derInt(num) {
		if(num === 0){
			return new Uint8Array([0x02, 0x01, 0x00]);
		}

		const bytes = [];
		let v = num >>> 0;
		while(v > 0){
			bytes.unshift(v & 0xFF);
			v >>>= 8;
		}

		// 先頭bitが1なら符号ビット回避のため0x00を追加
		if(bytes[0] & 0x80){
			bytes.unshift(0x00);
		}

		return this.#derConcat(
			new Uint8Array([0x02]),
			this.#derLen(bytes.length),
			new Uint8Array(bytes)
		);
	}

	/**
	 * Creates and returns a new Uint8Array representing a DER Null object.
	 * The DER Null object is encoded as a two-byte sequence with an object identifier of 0x05 and a zero-length content of 0x00.
	 *
	 * @returns {Uint8Array} A Uint8Array containing the DER Null encoding.
	 */
	#derNull() {
		return new Uint8Array([0x05, 0x00]);
	}

	/**
	 * Encodes an Object Identifier (OID e.g., 1.2.840.113549.1.5.13) string into its DER (Distinguished Encoding Rules) representation.
	 *
	 * This function converts an OID string of the format "x.y.z..." into its binary DER-encoded form.
	 * The first two components (x and y) are encoded as `40 * x + y`, and subsequent components are encoded
	 * using a base-128 representation where each byte has its highest bit set, except for the last byte.
	 *
	 * @param {string} oidStr - The OID string to be encoded, in the form "x.y.z...".
	 * @throws {Error} If the input string has fewer than two components or contains invalid numeric values.
	 * @returns {Uint8Array} A Uint8Array containing the DER-encoded representation of the OID.
	 */
	#derOid(oidStr) {
		const parts = oidStr.split('.').map((x) => parseInt(x, 10));
		if(parts.length < 2){
			throw new Error("Invalid OID");
		}

		const first = 40 * parts[0] + parts[1];
		const body = [first];

		for(let i = 2; i < parts.length; i++){
			let v = parts[i];
			const stack = [];
			do {
				stack.push(v & 0x7F);
				v >>= 7;
			} while(v > 0);

			for(let j = stack.length - 1; j >= 0; j--){
				let b = stack[j];
				if(j !== 0){
					b |= 0x80;
				}

				body.push(b);
			}
		}

		const b = new Uint8Array(body);

		return this.#derConcat(new Uint8Array([0x06]), this.#derLen(b.length), b);
	}

	/**
	 * Concatenates multiple input arrays and processes the resulting sequence.
	 *
	 * @param {...Uint8Array} arrays - The arrays to be concatenated and processed.
	 * @return {Uint8Array} The processed sequence derived from the concatenated input arrays.
	 */
	#concatSequence(...arrays) {
		return this.#derSequence(this.#derConcat(...arrays));
	}
}