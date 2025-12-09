/**
 * Object containing Object Identifiers (OIDs) used in cryptographic operations.
 * These identifiers are defined in various cryptographic standards and specifications.
 *
 * @property {string} PBES2       OID for Password-Based Encryption Scheme (PBES2) as defined in PKCS#5.
 * @property {string} PBKDF2      OID for Password-Based Key Derivation Function 2 (PBKDF2) as defined in PKCS#5.
 * @property {string} HMAC_SHA256 OID for HMAC with SHA-256 hashing algorithm.
 * @property {string} AES256_CBC  OID for AES with 256-bit key in CBC (Cipher Block Chaining) mode.
 * @property {string} ECDSA_SPKI  OID for Elliptic Curve Digital Signature Algorithm (ECDSA) Subject Public Key Information.
 */
const OID = {
	PBES2:       "1.2.840.113549.1.5.13",
	PBKDF2:      "1.2.840.113549.1.5.12",
	HMAC_SHA256: "1.2.840.113549.2.9",
	AES256_CBC:  "2.16.840.1.101.3.4.1.42",
	ECDSA_SPKI:  "1.2.840.10045.2.1"
};

const PUBKEY_LABEL = "PUBLIC KEY";
const PRIVKEY_LABEL = "PRIVATE KEY";
const OPENSSH_ADD_LABEL = "OPENSSH";
const ENCRYPTED_ADD_LABEL = "ENCRYPTED";

let keygenReduceNum = -1;

/**
 * Represents a parser for decoding RSA and ECDSA SubjectPublicKeyInfo structures.
 * This class provides methods to extract relevant public key components such as
 * modulus, exponent, curve name, and EC points from their respective binary formats.
 */
class Parser {
	#bytes;
	#offset = 0;

	/**
	 * Constructs an instance with the specified SPKI (Subject Public Key Info) buffer.
	 *
	 * @param {Uint8Array|ArrayBuffer} spkiBuf - The Subject Public Key Info buffer used for initialization. Can be either a Uint8Array or an ArrayBuffer.
	 * @return {void} This constructor does not return a value.
	 */
	constructor(spkiBuf){
		this.#bytes = (spkiBuf instanceof Uint8Array) ? spkiBuf : new Uint8Array(spkiBuf);
		this.#offset = 0;
	}

	/**
	 * Parses an RSA SubjectPublicKeyInfo structure to extract the modulus and exponent components of an RSA public key.
	 *
	 * @return {Object} An object containing the RSA public key details:
	 *  - `name`: The key algorithm name (always "ssh-rsa" for RSA keys).
	 *  - `n`: The modulus as a byte array.
	 *  - `e`: The exponent as a byte array.
	 */
	rsaSpki() {
		try {
			// SubjectPublicKeyInfo
			this.#expect(0x30);           // SEQUENCE
			this.#readLen();              // 全体長

			// AlgorithmIdentifier
			this.#expect(0x30);           // SEQUENCE
			const algLen = this.#readLen();
			this.#offset += algLen;       // ざっくりスキップ（rsaEncryption前提）

			// subjectPublicKey (BIT STRING)
			this.#expect(0x03);
			const bitLen = this.#readLen();
			this.#offset++;               // unused bits = 0

			// RSAPublicKey
			this.#expect(0x30);           // SEQUENCE
			this.#readLen();

			// modulus (INTEGER)
			this.#expect(0x02);
			let nLen = this.#readLen();
			let nStart = this.#offset;
			this.#offset += nLen;

			// exponent (INTEGER)
			this.#expect(0x02);
			let eLen = this.#readLen();
			let eStart = this.#offset;
			this.#offset += eLen;

			// 先頭 0x00 は符号ビット用の場合があるので取り除く
			while(nLen > 0 && this.#bytes[nStart] === 0x00){
				nStart++;
				nLen--;
			}
			while(eLen > 0 && this.#bytes[eStart] === 0x00){
				eStart++;
				eLen--;
			}

			// 元のバイト列からmodulus, exponentを切り出す
			const n = this.#bytes.slice(nStart, nStart + nLen);
			const e = this.#bytes.slice(eStart, eStart + eLen);

			return {
				name: "ssh-rsa",
				n: n,
				e: e
			};
		} finally {
			this.#reset();
		}
	}

	/**
	 * Parses an ECDSA key in the SubjectPublicKeyInfo format, extracting the curve name
	 * and public key point (Q) as used in the ECDSA algorithm.
	 *
	 * @return {Object} An object containing the parsed information:
	 *  - `curveName`: The name of the curve in OpenSSH format (e.g., "nistp256").
	 *  - `Q`: A Uint8Array representing the public key point (EC Point).
	 * @throws {Error} If the input is not an EC public key, contains unexpected OIDs,
	 *                 or unsupported EC curves are encountered.
	 */
	ecdsaSpki() {
		try {
			// SubjectPublicKeyInfo
			this.#expect(0x30);              // SEQUENCE
			this.#readLen();                 // 全体長は使わない

			// AlgorithmIdentifier
			this.#expect(0x30);              // SEQUENCE
			const algLen = this.#readLen();
			const algEnd = this.#offset + algLen;

			// id-ecPublicKeyのはず
			const algOid = this.#readOidAsString();
			if(algOid !== OID.ECDSA_SPKI){
				throw new Error(`Not an EC public key (unexpected algorithm OID: ${algOid})`);
			}

			// 曲線OID
			const curveOid = this.#readOidAsString();

			// 残りはスキップ
			this.#offset = algEnd;

			// subjectPublicKey (BIT STRING)
			this.#expect(0x03);
			const bitStrLen = this.#readLen();
			const unusedBits = this.#bytes[this.#offset++];  // たいてい 0
			if(unusedBits !== 0){
				throw new Error("Unexpected unused bits in EC public key");
			}

			// 残り全部が Q（EC Point）
			const q = this.#bytes.slice(this.#offset, this.#offset + (bitStrLen - 1));

			// OID → OpenSSHのcurve名にマップ
			let curveName;
			switch(curveOid){
				case "1.2.840.10045.3.1.7":   // secp256r1
					curveName = "nistp256";
					break;
				case "1.3.132.0.34":          // secp384r1
					curveName = "nistp384";
					break;
				case "1.3.132.0.35":          // secp521r1
					curveName = "nistp521";
					break;
				default:
					throw new Error(`Unsupported EC curve OID: ${curveOid}`);
			}

			return {
				curveName: curveName,
				Q: q
			};
		} finally {
			this.#reset();
		}
	}

	/**
	 * Reads a length value from a byte array, interpreting the value based on the first byte.
	 *
	 * If the most significant bit (MSB) of the first byte is not set, the value of the first byte
	 * directly represents the length. If the MSB is set, the remaining 7 bits of the first byte
	 * indicate the number of subsequent bytes that represent the length in a big-endian manner.
	 *
	 * The function advances the offset position with each byte processed.
	 *
	 * @function
	 * @returns {number} The decoded length value derived from the bytes at the current offset.
	 */
	#readLen() {
		let len = this.#bytes[this.#offset++];
		if(len & 0x80){
			const nBytes = len & 0x7F;

			len = 0;
			for(let i = 0; i < nBytes; i++){
				len = (len << 8) | this.#bytes[this.#offset++];
			}
		}

		return len;
	};

	/**
	 * Validates that the current byte from the input buffer matches the expected ASN.1 tag.
	 * Increments the offset after reading the byte.
	 *
	 * @param {number} tag - The expected ASN.1 tag value to match.
	 * @throws {Error} If the current byte does not match the expected tag value, an error is thrown with a message including the expected tag.
	 */
	#expect(tag) {
		if(this.#bytes[this.#offset++] !== tag){
			throw new Error(`Unexpected ASN.1 tag, expected 0x${tag.toString(16).padStart(2, '0')}`);
		}
	};

	/**
	 * Resets the internal state of the object by clearing the byte array and resetting the offset to zero.
	 *
	 * @return {void} Does not return a value.
	 */
	#reset() {
		this.#bytes = new Uint8Array(0);
		this.#offset = 0;
	}

	/**
	 * Reads an Object Identifier (OID) from the byte stream and decodes it into its standard dot-separated string representation.
	 *
	 * The method processes the bytes from the stream, calculates the OID components (including using the special logic for the first two components),
	 * and concatenates the values into a string format commonly used for OIDs.
	 *
	 * @return {string} The decoded OID as a dot-separated string.（1.2.840... の形式）
	 */
	#readOidAsString() {
		this.#expect(0x06);
		const len = this.#readLen();
		const end = this.#offset + len;
		const out = [];

		// 先頭1byteは (first * 40 + second)
		const first = this.#bytes[this.#offset++];
		out.push(Math.floor(first / 40));
		out.push(first % 40);

		let value = 0;
		while(this.#offset < end){
			const b = this.#bytes[this.#offset++];
			value = (value << 7) | (b & 0x7F);
			if((b & 0x80) === 0){
				out.push(value);
				value = 0;
			}
		}

		return out.join(".");
	}
}

/**
 * Generates a SHA-256 fingerprint of the given data and converts it to a base64-encoded string without trailing equals signs.
 *
 * @async
 * @param {ArrayBuffer} blob - The input data to generate the fingerprint for.
 * @return {Promise<string>} A promise that resolves to the base64-encoded SHA-256 fingerprint.
 */
async function makeFingerprint(blob) {
	const digest = await crypto.subtle.digest("SHA-256", blob);
	return helper.toBase64(digest)
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
	const blob = rfc4253.concatBytes(
		rfc4253.writeString(rsa.name),
		rfc4253.writeMpint(rsa.e),
		rfc4253.writeMpint(rsa.n)
	);

	return {
		raw: blob,
		pubkey: helper.toBase64(blob),
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
	const blob = rfc4253.concatBytes(
		rfc4253.writeString(`ecdsa-sha2-${ecdsa.curveName}`), //string  ex. "ecdsa-sha2-nistp256"
		rfc4253.writeString(ecdsa.curveName), // string "nistp256"
		rfc4253.writeStringBytes(ecdsa.Q),    // string Q (0x04 || X || Y)
	);

	return {
		raw: blob,
		pubkey: helper.toBase64(blob),
		fingerprint: await makeFingerprint(blob)
	};
}

/**
 * Generates an RSA private key blob in the appropriate format.
 *
 * This method exports the provided private key to JWK format, extracts the components
 * required for the blob (d, p, q, and qi), and concatenates them into a byte array
 * according to the RFC 4253 specification.
 *
 * @async
 * @param {CryptoKey} privateKey - The RSA private key to be converted into a private key blob.
 * @return {Promise<Uint8Array>} A promise that resolves to the RSA private key blob represented as a byte array.
 */
async function makeRsaPrivateBlob(privateKey) {
	const jwk = await crypto.subtle.exportKey("jwk", privateKey);

	// RSAでは d, p, q, qinv
	const d  = helper.fromBase64(jwk.d);
	const p  = helper.fromBase64(jwk.p);
	const q  = helper.fromBase64(jwk.q);
	const qi = helper.fromBase64(jwk.qi); // qinv (q⁻¹ mod p)

	return rfc4253.concatBytes(
		rfc4253.writeMpint(d),
		rfc4253.writeMpint(p),
		rfc4253.writeMpint(q),
		rfc4253.writeMpint(qi),
	);
}

/**
 * Generates an ECDSA private key blob in the appropriate format.
 *
 * @async
 * @param {CryptoKey} privateKey - The ECDSA private key to be exported and processed.
 * @return {Promise<Uint8Array>} A promise that resolves to the ECDSA private key blob represented as a byte array.
 */
async function makeEcdsaPrivateBlob(privateKey) {
	const jwk = await crypto.subtle.exportKey("jwk", privateKey);

	// ECDSAでは d だけ
	const d = helper.fromBase64(jwk.d);

	// PPKv3の`C.3.3: NIST EC keys`は`mpint(d)`だけ
	return rfc4253.writeMpint(d);
}

/**
 * A helper object providing utility methods for data transformation and encoding operations.
 *
 * @typedef {Object} helper
 * @property {function(Iterable<number>): string} hexPad Converts an iterable of numeric values into a hexadecimal string.
 * @property {function(string, number=): string} stringWrap Formats a given string by wrapping it to the specified width.
 * @property {function(ArrayBuffer|TypedArray): string} toBase64 Converts an ArrayBuffer or TypedArray to a Base64-encoded string.
 * @property {function(string): Uint8Array|null} fromBase64 Decodes a Base64-encoded string into a Uint8Array.
 * @property {function(Buffer, string): string} toPEM Converts a given buffer into a PEM formatted string.
 */
const helper = {
	/**
	 * Converts an iterable of numeric values into a hexadecimal string.
	 *
	 * The function takes an input array or iterable containing numeric values (such as bytes),
	 * converts each value to its two-character hexadecimal representation (adding leading zeros
	 * if necessary), and concatenates the results into a single string.
	 *
	 * @param {Iterable<number>} arr - An iterable of numeric values to be converted.
	 * @returns {string} A concatenated hexadecimal string representing the numeric values.
	 */
	hexPad: (arr) => [...arr].map((b) => b.toString(16).padStart(2, "0")).join(""),


	/**
	 * Encodes a given string into its corresponding UTF-8 byte representation.
	 *
	 * @function
	 * @param {string} s - The input string to be encoded.
	 * @returns {Uint8Array} The UTF-8 encoded byte array of the input string.
	 */
	toUtf8: (s) => new TextEncoder().encode(s),

	/**
	 * Formats a given string by wrapping it to the specified width.
	 * Breaks the string into lines not exceeding the provided width, appending a newline character
	 * at the end of each line, except for the last one. Trims any trailing whitespace characters
	 * from the resulting string.
	 *
	 * @param {string} str - The input string to be wrapped.
	 * @param {number} [width=64] - The maximum width of a line before wrapping. Defaults to 64 if not provided.
	 * @returns {string} The string formatted with line breaks.
	 */
	stringWrap: (str, width = 64) => str.replace(new RegExp(`(.{1,${width}})`, "g"), (match, grp1) => (grp1) ? `${grp1}\n` : "").trimEnd(),

	/**
	 * Converts an ArrayBuffer or TypedArray to a Base64-encoded string.
	 *
	 * @param {ArrayBuffer|TypedArray} buffer - The buffer or typed array that is to be converted to a Base64 string.
	 * @returns {string} The Base64-encoded string representation of the input buffer.
	 */
	toBase64: (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))),

	/**
	 * Decodes a Base64-encoded string into a Uint8Array.
	 *
	 * @param {string} b64 - The Base64-encoded string to decode. This string should not include
	 *                       characters that are invalid in Base64 encoding, such as newline or whitespace.
	 * @returns {Uint8Array|null} Returns a Uint8Array representing the decoded binary data, or null if the input is not a valid string.
	 */
	fromBase64: (b64) => {
		if(typeof b64 !== 'string'){
			return null;
		}

		let s = b64.replace(/\-/g, '+').replace(/_/g, '/');
		while(s.length % 4 > 0){
			s += "=";
		}

		const decoded = atob(s);
		const buffer = new Uint8Array(decoded.length);
		for(let i = 0; i < b64.length; i++){
			buffer[i] = decoded.charCodeAt(i);
		}

		return buffer;
	},

	/**
	 * Converts a given buffer into a PEM formatted string.
	 *
	 * @param {Buffer} buffer - The input buffer to be converted.
	 * @param {string} label - The label to prepend and append to the PEM formatted string.
	 * @returns {string} A PEM formatted string containing the base64 representation of the buffer, wrapped by the specified label.
	 */
	toPEM: (buffer, label) => {
		const base64 = helper.stringWrap(helper.toBase64(buffer), 64);

		return [
			`-----BEGIN ${label}-----`,
			base64
			,`-----END ${label}-----`
		].join("\n");
	},

	/**
	 * Converts an OpenSSH-key-v1 buffer to a PEM formatted string.
	 *
	 * Encodes the given buffer into a base64 string and breaks it into 70-character
	 * lines. Wraps the base64 encoded string with proper PEM headers and footers.
	 *
	 * @param {Buffer} opesshBuf - The OpenSSH formatted buffer to be converted.
	 * @returns {string} A PEM formatted string containing the base64 encoded data
	 * wrapped with appropriate headers and footers.
	 */
	toOpenSSHPem: (opesshBuf) => {
		const base64 = helper.stringWrap(helper.toBase64(opesshBuf), 70);

		return [
			`-----BEGIN ${OPENSSH_ADD_LABEL} ${PRIVKEY_LABEL}-----`,
			base64,
			`-----END ${OPENSSH_ADD_LABEL} ${PRIVKEY_LABEL}-----`,
			""
		].join("\n");
	},

	/**
	 * Converts a PKCS#8 private key buffer into an encrypted PKCS#8 PEM format string.
	 *
	 * @async
	 * @function
	 * @param {Buffer} pkcs8Buf - The PKCS#8 private key buffer to be encrypted.
	 * @param {string} passphrase - The passphrase used for encrypting the private key.
	 * @param {Object} [opt={}] - Options for the encryption process.
	 * @param {string} [opt.cipher='aes256'] - The encryption algorithm to use (default is 'aes256').
	 * @param {number} [opt.iterations=2048] - The number of iterations for the encryption (default is 2048).
	 * @returns {Promise<string>} A promise that resolves to the encrypted PKCS#8 PEM formatted string.
	 * @throws {Error} If the encryption process fails or if the inputs are invalid.
	 */
	toEncryptedPkcs8PEM: async (pkcs8Buf, passphrase, opt = {}) => {
		const { der } = await encryptPkcs8WithPBES2(pkcs8Buf, passphrase, opt);
		const base64 = helper.stringWrap(helper.toBase64(der), 64);

		return [
			`-----BEGIN ${ENCRYPTED_ADD_LABEL} ${PRIVKEY_LABEL}-----`,
			`${base64}`,
			`-----END ${ENCRYPTED_ADD_LABEL} ${PRIVKEY_LABEL}-----`
		].join("\n");
	}
};

/**
 * A utility object for encoding data into DER (Distinguished Encoding Rules) format,
 * commonly used in PKCS8 cryptographic data structures. Contains functions for
 * creating various DER-encoded elements like sequences, integers, octet strings,
 * and object identifiers. Primarily utilized for constructing and managing cryptographic
 * data formats.
 *
 * @property {function(...Uint8Array): Uint8Array} derConcat Concatenates multiple Uint8Array instances into a single array.
 * @property {function(number): Uint8Array} derLen Encodes a given length into the DER length format.
 * @property {function(Uint8Array|Array|ArrayBuffer): Uint8Array} derSequence Constructs a DER-encoded sequence.
 * @property {function(Uint8Array|Array): Uint8Array} derOctetString Creates a DER-encoded Octet String from the input.
 * @property {function(number): Uint8Array} derInt Produces a DER-encoded representation of an integer.
 * @property {function(): Uint8Array} derNull Creates a DER Null object encoding.
 * @property {function(string): Uint8Array} derOid Encodes an Object Identifier (OID) string into DER format.
 */
const pkcs8 = {
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
	derConcat: (...arrays) => {
		const len = arrays.reduce((n, a) => n + a.length, 0);
		const out = new Uint8Array(len);
		let off = 0;
		for(const a of arrays){
			out.set(a, off);
			off += a.length;
		}

		return out;
	},

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
	derLen: (len) => {
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
	},

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
	derSequence: (content) => {
		const c = (content instanceof Uint8Array) ? content : new Uint8Array(content);
		return pkcs8.derConcat(new Uint8Array([0x30]), pkcs8.derLen(c.length), c);
	},

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
	derOctetString: (bytes) => {
		const b = (bytes instanceof Uint8Array) ? bytes : new Uint8Array(bytes);
		return pkcs8.derConcat(new Uint8Array([0x04]), pkcs8.derLen(b.length), b);
	},

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
	derInt: (num) => {
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

		return pkcs8.derConcat(
			new Uint8Array([0x02]),
			pkcs8.derLen(bytes.length),
			new Uint8Array(bytes)
		);
	},

	/**
	 * Creates and returns a new Uint8Array representing a DER Null object.
	 * The DER Null object is encoded as a two-byte sequence with an object identifier of 0x05 and a zero-length content of 0x00.
	 *
	 * @returns {Uint8Array} A Uint8Array containing the DER Null encoding.
	 */
	derNull: () => new Uint8Array([0x05, 0x00]),

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
	derOid: (oidStr) => {
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
		return pkcs8.derConcat(new Uint8Array([0x06]), pkcs8.derLen(b.length), b);
	}
};

/**
 * A set of utility functions for handling data formats and operations
 * specified in RFC 4253, focusing on SSH Binary Packet Protocol.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc4253
 */
const rfc4253 = {
	/**
	 * Encodes an array of bytes into a Uint8Array, prefixed with its length as a 32-bit unsigned integer.
	 *
	 * @param {Uint8Array} array - The input array of bytes to encode.
	 * @returns {Uint8Array} A new Uint8Array containing the 32-bit unsigned length followed by the input array's data.
	 */
	writer: (array) => {
		const out = new Uint8Array(4 + array.length);
		const view = new DataView(out.buffer);
		view.setUint32(0, array.length);
		out.set(array, 4);

		return out;
	},

	/**
	 * Encodes a 32-bit unsigned integer into a 4-byte Uint8Array
	 * in big-endian byte order.
	 *
	 * @param {number} value - The 32-bit unsigned integer to encode.
	 * @returns {Uint8Array} A Uint8Array containing the big-endian representation of the input value.
	 */
	writeUint32: (value) => {
		const buf = new Uint8Array(4);
		const view = new DataView(buf.buffer);
		view.setUint32(0, value >>> 0, false); // big endian

		return buf;
	},

	/**
	 * Encodes a given string into a Uint8Array format with a prepended 4-byte unsigned integer
	 * representing the length of the string in bytes.
	 *
	 * @param {string} str - The string to be encoded.
	 * @returns {Uint8Array} A byte array containing the string length as a 4-byte unsigned integer
	 *                       followed by the UTF-8 encoded representation of the string.
	 */
	writeString: (str) => rfc4253.writer(helper.toUtf8(str)),

	/**
	 * Converts the given input into a Uint8Array, calculates its length, and returns a new Uint8Array
	 * where the first 4 bytes represent the length of the input array and the remaining bytes
	 * contain the input data.
	 *
	 * @param {ArrayBuffer | Uint8Array} bytes - The input that will be converted to a Uint8Array.
	 *                                           If it is not already a Uint8Array, it will be wrapped in one.
	 * @returns {Uint8Array} A new Uint8Array where the first 4 bytes encode the length of the input data,
	 *                       followed by the data itself.
	 */
	writeStringBytes: (bytes) => {
		const b = (bytes instanceof Uint8Array) ? bytes : new Uint8Array(bytes);

		return rfc4253.writer(b);
	},

	/**
	 * Converts a byte array into an mpint (multiple precision integer) format.
	 * If the most significant bit of the first byte is set to 1, prepends a 0x00 byte to preserve the sign.
	 * Prepends the length of the byte array as a 4-byte unsigned integer in big-endian format to the output.
	 *
	 * @param {Uint8Array} bytes - The input byte array to be converted into mpint format.
	 * @returns {Uint8Array} A new Uint8Array in mpint format, containing the length prefix and the adjusted byte array.
	 */
	writeMpint: (bytes) => {
		// mpintは先頭bitが1なら 0x00 を前置して符号を守る
		let b = bytes;
		if(b.length > 0 && (b[0] & 0x80)){
			const tmp = new Uint8Array(b.length + 1);
			tmp.set(b, 1);
			b = tmp;
		}

		return rfc4253.writeStringBytes(b);
	},

	/**
	 * Concatenates multiple Uint8Array instances into a single Uint8Array.
	 *
	 * @param {...Uint8Array} arrays - The arrays to concatenate.
	 * @returns {Uint8Array} A new Uint8Array that contains the concatenated bytes of all input arrays.
	 */
	concatBytes: (...arrays) => {
		const arr = [...arrays];
		const len = arr.reduce((sum, a) => sum + a.length, 0);
		const out = new Uint8Array(len);
		let offset = 0;
		for(const a of arr){
			out.set(a, offset);
			offset += a.length;
		}

		return out;
	}
};

/**
 * An object containing utility functions for handling PuTTY Private Key (PPK) operations.
 *
 * @property {Function} computeMac - Computes a Message Authentication Code (MAC) to ensure integrity of provided inputs.
 * @property {Function} makeRsaPpkV3 - Generates an RSA PuTTY Private Key file in the format of PuTTY-User-Key-File-3 based on the given key pair and parameters.
 */
const forPPK = {
	/**
	 * Derives cryptographic keys from a given passphrase using the Argon2id key derivation function.
	 *
	 * @async
	 * @param {string} passphrase - The passphrase to be used for key derivation.
	 * @returns {Promise<Object>} An object containing the derived keys and used parameters:
	 *  - `salt` {Uint8Array}: The randomly generated salt used in the derivation.
	 *  - `mem` {number}: Memory size in KiB used in the derivation.
	 *  - `pass` {number}: Number of iterations used in the derivation.
	 *  - `parallel` {number}: Number of parallel threads used in the derivation.
	 *  - `cipher` {Uint8Array}: The derived cipher key for AES-256 encryption.
	 *  - `iv` {Uint8Array}: The derived initialization vector for AES-CBC.
	 *  - `mk` {Uint8Array}: The derived HMAC-SHA-256 key.
	 * @throws {Error} Throws an error if the `argon2-browser` library is not loaded or missing necessary functionality.
	 */
	deriveKeys: async (passphrase) => {
		if(!argon2 || typeof argon2.hash !== 'function'){
			throw new Error("argon2-browser is required for deriveKeys");
		}

		const passBytes = helper.toUtf8(passphrase);

		// PuTTYっぽいデフォルト値 (サンプルでもよく使用される値)
		const memory      = 8192; // KiB
		const passes      = 13;
		const parallelism = 1;
		const salt = crypto.getRandomValues(new Uint8Array(16));

		// argon2でハッシュ化
		const out = await argon2.hash({
			pass: passBytes,
			salt,
			time: passes,
			mem: memory,
			parallelism,
			hashLen: 80,
			type: argon2.ArgonType.Argon2id,
			raw: true
		}); // Uint8Array(80)

		const hash      = out.hash;
		const cipherKey = hash.slice(0, 32);  // AES-256
		const iv        = hash.slice(32, 48); // AES-CBC IV
		const macKey    = hash.slice(48, 80); // HMAC-SHA-256 key

		return {
			salt: salt,
			mem: memory,
			pass: passes,
			parallel: parallelism,
			cipher: cipherKey,
			iv: iv,
			mk: macKey
		};
	},

	/**
	 * Computes a MAC (Message Authentication Code) for verifying integrity of provided inputs.
	 *
	 * @async
	 * @param {string} algorithmName - The algorithm name to be used in the computation.
	 * @param {string} encryption - The encryption type, indicating the security mechanism used.
	 * @param {string} comment - An optional comment string to include in the computation.
	 * @param {Uint8Array} pubBlob - The public key blob used in the computation.
	 * @param {Uint8Array} privBlob - The private key blob used in the computation.
	 * @param {Uint8Array|null} [enc=null] - Optional encryption key used for HMAC. If not provided, a default key is used.
	 * @returns {Promise<string>} Resolves to a hexadecimal string representation of the computed MAC.
	 */
	computeMac: async (algorithmName, encryption, comment, pubBlob, privBlob, enc = null) => {
		const macInput = rfc4253.concatBytes(
			rfc4253.writeString(algorithmName),
			rfc4253.writeString(encryption),
			rfc4253.writeString(comment),
			rfc4253.writeStringBytes(pubBlob),
			rfc4253.writeStringBytes(privBlob)
		);

		// Encryption:none の場合は`enc = null`
		// PPKv3のMACは「鍵の秘密性」ではなく「改ざん検出」用途なので、PuTTY 側も HMAC の key="" と key="\x00" を区別していない。
		// ただし空の配列だとWebCryptoの規約違反なので0番目に\x00を入れて違反を回避。
		const keyData = (enc instanceof Uint8Array && enc.length > 0) ? enc : new Uint8Array([0]);
		const key = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		const sig = await crypto.subtle.sign("HMAC", key, macInput);
		const mac = new Uint8Array(sig);

		return helper.hexPad(mac);
	},

	/**
	 * Generates an RSA PPK (PuTTY Private Key) file in the format of PuTTY-User-Key-File-3.
	 *
	 * @async
	 * @param {string} algorithmName - The name of the encryption algorithm to be used (e.g., ssh-rsa).
	 * @param {CryptoKeyPair} keyPair - An object containing the RSA key pair. It must include the private key.
	 * @param {string} comment - A textual comment to include in the PPK file.
	 * @param {Uint8Array} pubBlob - RSA public key.
	 * @param {string} [encryption="none"] - Specifies the encryption type for the private key. Defaults to "none".
	 * @param {string} [passphrase=""] - Specifies the passphrase. Defaults to "".
	 * @returns {Promise<string>} A string representing the complete contents of the PPK file.
	 */
	makeRsaPpkV3: async (algorithmName, keyPair, comment, pubBlob, encryption = "none", passphrase = "") => {
		const pubB64 = helper.toBase64(pubBlob);

		// 平文の秘密鍵blob
		const privPlain = await makeRsaPrivateBlob(keyPair.privateKey);
		// ランダムパディング込みの秘密鍵
		const privPadded = addRandomPadding(privPlain, 16);

		// Base64用に暗号化or平文
		let privOut;
		// Key-Derivation系ヘッダ用
		let kdLines = "";
		// computeMacに渡すキー
		let macKey;

		// パスフレーズ指定無し
		if(encryption === "none" || !passphrase){
			// 平文のまま保存
			privOut = privPadded;
			// computeMac側で0x00鍵にフォールバックするために`null`を指定
			macKey = null;
		}
		// パスフレーズ指定あり (AES-256-CBC)
		else if(encryption === "aes256-cbc"){
			const d = await argon2KeyDerivation(passphrase, privPadded);
			privOut = d.privOut;
			macKey = d.macKey;
			kdLines = d.kdLines;
		}
		// その他
		else{
			throw new Error(`Unsupported encryption: ${encryption}`);
		}

		const privB64 = helper.toBase64(privOut);
		const pubLines  = helper.stringWrap(pubB64);
		const privLines = helper.stringWrap(privB64);
		const pubLineCount = pubLines.split("\n").length;
		const prvLineCount = privLines.split("\n").length;

		// MACは常に「平文＋パディング側」を入力にする！
		const macHex = await forPPK.computeMac(
			algorithmName,
			encryption,
			comment,
			pubBlob,
			privPadded,
			macKey
		);

		return [
			`PuTTY-User-Key-File-3: ${algorithmName}`,
			`Encryption: ${encryption}`,
			`Comment: ${comment}`,
			`Public-Lines: ${pubLineCount}`,
			`${pubLines}`,
			kdLines,
			`Private-Lines: ${prvLineCount}`,
			`${privLines}`,
			`Private-MAC: ${macHex}`
		].join("\n");
	},

	/**
	 * Generates an ECDSA PPK (PuTTY Private Key) file in the format of PuTTY-User-Key-File-3.
	 *
	 * @async
	 * @param {string} algorithmName - The name of the encryption algorithm to be used (e.g., ecdsa-sha2-nistp2256).
	 * @param {CryptoKeyPair} keyPair - An object containing the ECDSA key pair. It must include the private key.
	 * @param {string} comment - A textual comment to include in the PPK file.
	 * @param {Uint8Array} pubBlob - ECDSA public key.
	 * @param {string} [encryption="none"] - Specifies the encryption type for the private key. Defaults to "none".
	 * @param {string} [passphrase=""] - Specifies the passphrase. Defaults to "".
	 * @returns {Promise<string>} A string representing the complete contents of the PPK file.
	 */
	makeEcdsaPpkV3: async (algorithmName, keyPair, comment, pubBlob, encryption = "none", passphrase = "") => {
		const pubB64 = helper.toBase64(pubBlob);

		// 平文の秘密鍵blob
		const privPlain = await makeEcdsaPrivateBlob(keyPair.privateKey);
		// ランダムパディング込みの秘密鍵
		const privPadded = addRandomPadding(privPlain, 16);

		// Base64用に暗号化or平文
		let privOut;
		// Key-Derivation系ヘッダ用
		let kdLines = "";
		// computeMacに渡すキー
		let macKey;

		// パスフレーズ指定無し
		if(encryption === "none" || !passphrase){
			// 平文のまま保存
			privOut = privPadded;
			// computeMac側で0x00鍵にフォールバックするために`null`を指定
			macKey = null;
		}
		// パスフレーズ指定あり (AES-256-CBC)
		else if(encryption === "aes256-cbc"){
			const d = await argon2KeyDerivation(passphrase, privPadded);

			privOut = d.privOut
			macKey  = d.macKey;
			kdLines = d.kdLines;
		}
		// その他
		else{
			throw new Error(`Unsupported encryption: ${encryption}`);
		}

		const privB64 = helper.toBase64(privOut);
		const pubLines = helper.stringWrap(pubB64);
		const privLines = helper.stringWrap(privB64);
		const pubLineCount = pubLines.split("\n").length;
		const prvLineCount = privLines.split("\n").length;

		// MACは常に「平文＋パディング側」を入力にする！
		const macHex = await forPPK.computeMac(
			algorithmName,
			encryption,
			comment,
			pubBlob,
			privPadded,
			macKey
		);

		return [
			`PuTTY-User-Key-File-3: ${algorithmName}`,
			`Encryption: ${encryption}`,
			`Comment: ${comment}`,
			`Public-Lines: ${pubLineCount}`,
			`${pubLines}`,
			kdLines,
			`Private-Lines: ${prvLineCount}`,
			`${privLines}`,
			`Private-MAC: ${macHex}`
		].join("\n");
	}
};

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

	// Random-salt & IV
	const salt = crypto.getRandomValues(new Uint8Array(saltSize));
	const iv   = crypto.getRandomValues(new Uint8Array(16));

	// ---- PBKDF2でAES-256キーを導出 (PBKDF2-HMAC-SHA256)
	const baseKey = await crypto.subtle.importKey("raw", helper.toUtf8(passphrase), "PBKDF2", false, ["deriveKey"]);
	const aesKey = await crypto.subtle.deriveKey(
		{ name: "PBKDF2", salt, iterations, hash },
		baseKey,
		{ name: "AES-CBC", length: 256 },
		false,
		["encrypt"]
	);

	// ---- AES-256-CBC + PKCS#7 padding (WebCrypto Standard)
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, buffer));

	// ====== ここから ASN.1 組み立て ======

	// PRF AlgorithmIdentifier (hmacWithSHA256, NULL)
	const prfAlgId = pkcs8.derSequence(
		pkcs8.derConcat(
			pkcs8.derOid(OID.HMAC_SHA256),
			pkcs8.derNull()
		)
	);

	// PBKDF2-params ::= SEQUENCE {
	//   salt OCTET STRING,
	//   iterationCount INTEGER,
	//   keyLength INTEGER OPTIONAL,
	//   prf AlgorithmIdentifier DEFAULT ...
	// }
	const pbkdf2Params = pkcs8.derSequence(
		pkcs8.derConcat(
			pkcs8.derOctetString(salt),
			pkcs8.derInt(iterations),
			pkcs8.derInt(keyLength),
			prfAlgId
		)
	);

	// keyDerivationFunc AlgorithmIdentifier (PBKDF2)
	const kdfAlgId = pkcs8.derSequence(
		pkcs8.derConcat(
			pkcs8.derOid(OID.PBKDF2),
			pbkdf2Params
		)
	);

	// encryptionScheme AlgorithmIdentifier (AES-256-CBC, params = IV)
	const encSchemeAlgId = pkcs8.derSequence(
		pkcs8.derConcat(
			pkcs8.derOid(OID.AES256_CBC),
			pkcs8.derOctetString(iv)
		)
	);

	// PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
	const pbes2Params = pkcs8.derSequence(
		pkcs8.derConcat(
			kdfAlgId,
			encSchemeAlgId
		)
	);

	// encryptionAlgorithm AlgorithmIdentifier (PBES2 + params)
	const encryptionAlgorithm = pkcs8.derSequence(
		pkcs8.derConcat(
			pkcs8.derOid(OID.PBES2),
			pbes2Params
		)
	);

	// encryptedData OCTET STRING
	const encryptedData = pkcs8.derOctetString(ciphertext);

	// EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData }
	const encryptedPrivateKeyInfo = pkcs8.derSequence(
		pkcs8.derConcat(
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
 * Generates an OpenSSH private key block in Uint8Array format.
 *
 * @param {string} keyType - The type of the key (e.g., "ssh-rsa").
 * @param {Uint8Array} publicBlob - The public portion of the key in binary format.
 * @param {Uint8Array} privatePart - The private portion of the key in binary format, specific to the key type.
 * @param {string} [comment] - An optional comment to include in the key block.
 * @return {Uint8Array} A Uint8Array representing the OpenSSH private key block, padded to a multiple of the block size.
 */
function makeOpenSshPrivateBlock(keyType, publicBlob, privatePart, comment) {
	const check = crypto.getRandomValues(new Uint32Array(1))[0];

	const core = rfc4253.concatBytes(
		rfc4253.writeUint32(check),            // uint32 checkint1
		rfc4253.writeUint32(check),            // uint32 checkint2
		rfc4253.writeString(keyType),          // "ssh-rsa" など
		rfc4253.writeStringBytes(publicBlob),  // Uint8Array
		rfc4253.writeStringBytes(privatePart), // Uint8Array (鍵種別ごとの生フィールド)
		rfc4253.writeString(comment || "")
	);

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
 * @param {string} params.ciphername - The cipher name used for encryption, e.g., "chacha20-poly1305@openssh.com".
 * @param {string} params.kdfname - The key derivation function name, e.g., "bcrypt".
 * @param {Uint8Array} params.kdfoptions - The key derivation function options as a byte array.
 * @param {Uint8Array} params.publicBlob - The public key data as a byte array.
 * @param {Uint8Array} params.encryptedBlob - The encrypted private key data as a byte array.
 * @return {Uint8Array} The combined byte array representing the OpenSSH key in version 1 format.
 */
function buildOpenSSHKeyV1({ ciphername, kdfname, kdfoptions, publicBlob, encryptedBlob }){
	const magic = rfc4253.concatBytes(
		helper.toUtf8("openssh-key-v1"),
		new Uint8Array([0x00])
	);

	return rfc4253.concatBytes(
		magic,
		rfc4253.writeString(ciphername),        // "chacha20-poly1305@openssh.com"
		rfc4253.writeString(kdfname),           // "bcrypt"
		rfc4253.writeStringBytes(kdfoptions),   // string kdfoptions
		rfc4253.writeUint32(1),                 // 鍵の個数 N=1
		rfc4253.writeStringBytes(publicBlob),   // string publickey1
		rfc4253.writeStringBytes(encryptedBlob) // string encrypted_privates
	);
}

/**
 * Generates an OpenSSH private key in the v1 format.
 *
 * @async
 * @param {string} keyType - The type of key to generate, such as "ssh-rsa" or "ecdsa-sha2-<curve-name>".
 * @param {Object} keyInfo - The key information containing the public and private key components.
 * @param {string} [keyInfo.public] - The public key component.
 * @param {string} [keyInfo.private] - The private key component.
 * @param {string} [passphrase] - An optional passphrase to encrypt the private key. If not provided, the key will be unencrypted.
 * @param {string} [comment] - An optional comment to include in the private key.
 * @return {Promise<string>} A Promise that resolves to the OpenSSH private key in PEM (Base64-encoded) format.
 * @throws {Error} If an unsupported key type is provided.
 */
async function makeOpenSSHPrivateKeyV1(keyType, keyInfo, passphrase, comment) {
	// 1. 公開鍵blobと秘密フィールドblobを作る
	let pubBlob;
	let privBlob;

	if(keyType === "ssh-rsa"){
		const rsa = await makeRsaOpenSSHPubKey(keyInfo.public); // SPKI → OpenSSH blob
		pubBlob   = rsa.raw;
		privBlob  = await makeRsaPrivateBlob(keyInfo.private);
	} else if(keyType.startsWith("ecdsa-sha2-")){
		const ecdsa = await makeEcdsaOpenSSHPubKey(keyInfo.public);
		pubBlob     = ecdsa.raw;
		privBlob    = await makeEcdsaPrivateBlob(keyInfo.private);
	} else{
		throw new Error(`Unsupported key type for OpenSSH-key-v1: ${keyType}`);
	}

	// 2. 平文の秘密鍵ブロックを作成
	const plainBlock = makeOpenSshPrivateBlock(
		keyType,
		pubBlob,
		privBlob,
		comment || ""
	);

	// パスフレーズ無しなら暗号化せずにそのまま入れる
	if(!passphrase){
		const binary = buildOpenSSHKeyV1({
			ciphername:    "none",
			kdfname:       "none",
			kdfoptions:    new Uint8Array(0),
			publicBlob:    pubBlob,
			encryptedBlob: plainBlock
		});

		return helper.toOpenSSHPem(binary);
	}

	// 3. bcrypt-pbkdf で AEADキー導出
	const salt   = crypto.getRandomValues(new Uint8Array(16));
	const rounds = 16;
	const aeadKey = new Uint8Array(32); // chacha20poly1305 は 32byte鍵

	const passBytes = helper.toUtf8(passphrase);

	// bcrypt-pbkdf.pbkdf(pass, passlen, salt, saltlen, key, keylen, rounds)
	window.bcryptPbkdf.pbkdf(
		passBytes,
		passBytes.length,
		salt,
		salt.length,
		aeadKey,
		aeadKey.length,
		rounds
	);

	// 4. ChaCha20-Poly1305 で暗号化
	const nonce = crypto.getRandomValues(new Uint8Array(12)); // nonceLength=12
	const aead  = new window.chacha20poly1305(aeadKey);
	const aad   = new Uint8Array(0);

	const sealed = aead.seal(nonce, plainBlock, aad);
	// sealed = ciphertext || tag (末尾16バイトがタグ)
	const encryptedBlob = rfc4253.concatBytes(nonce, sealed);

	// 5. kdfoptions & コンテナ
	const kdfoptions = rfc4253.concatBytes(
		rfc4253.writeStringBytes(salt),  // string salt
		rfc4253.writeUint32(rounds)      // uint32 rounds
	);

	const binary = buildOpenSSHKeyV1({
		ciphername:   "chacha20-poly1305@openssh.com",
		kdfname:      "bcrypt",
		kdfoptions,
		publicBlob:   pubBlob,
		encryptedBlob
	});

	return helper.toOpenSSHPem(binary);
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
	return rfc4253.concatBytes(plain, pad);
};

/**
 * Encrypts the given plaintext using AES-CBC encryption with the provided key and initialization vector (IV).
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
 * Encrypts the given plaintext using AES-CBC with the provided key and initialization vector (IV) with no padding.
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
 * Performs key derivation using the Argon2id algorithm and encrypts the provided private key using AES-CBC without PKCS#7 padding.
 *
 * @async
 * @function argon2KeyDerivation
 * @param {string} passphrase - The passphrase used for deriving the encryption keys.
 * @param {Uint8Array} paddedPrivkey - The padded private key to be encrypted after key derivation.
 * @returns {Promise<Object>} Returns a promise that resolves to an object containing the encrypted private key (`privOut`),
 *                            the MAC key (`macKey`), and the generated key derivation metadata (`kdLines`).
 *
 * @throws {Error} Throws an error if the key derivation or encryption process fails.
 *
 * @description
 * This function derives a set of encryption keys and MAC keys from the provided passphrase using Argon2id. The provided padded
 * private key is then encrypted using AES-CBC with the derived cipher key and initialization vector. Due to padding conflicts
 * introduced by WebCrypto, this function uses a custom implementation of AES-CBC encryption without padding. Metadata
 * describing the Argon2id configuration is also generated and returned.
 */
const argon2KeyDerivation = async (passphrase, paddedPrivkey) => {
	// Argon2で鍵導出
	const ar2 = await forPPK.deriveKeys(passphrase);

	// AES-CBCで保存
	// FIXME: AES-CBCをWebCryptoでやると勝手にPKCS#7パディングを付けやがって永遠にMACと整合性がとれなくなるため、Crypto-JSを使ってパディング無しで生成させる。
	// 使わない: const privOut = aesCbcEncryptRaw(ar2.cipher, ar2.iv, paddedPrivkey);
	const privOut = aesCbcEncryptRawNoPadding(ar2.cipher, ar2.iv, paddedPrivkey);
	const macKey  = ar2.mk;

	// Key-Derivationヘッダの作成
	const kdLines = [
		`Key-Derivation: Argon2id`,
		`Argon2-Memory: ${ar2.mem}`,
		`Argon2-Passes: ${ar2.pass}`,
		`Argon2-Parallelism: ${ar2.parallel}`,
		`Argon2-Salt: ${helper.hexPad(ar2.salt)}`
	].join("\n");

	return { privOut, macKey, kdLines };
};

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
	let algo;
	let keyUsage;
	switch(name){
		case 'RSA':
			algo = {
				name: "RSA-PSS",
				modulusLength: opt.len,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256"
			};
			keyUsage = ["sign", "verify"];
			break;

		case 'ECDSA':
			algo = {
				name: name,
				namedCurve: opt.nist
			};
			keyUsage = ["sign", "verify"];
			break;
	}

	if(!algo){
		throw Error(`Invalid algorithm: ${name}`);
	}

	const comment = (opt.comment && opt.comment !== '') ? opt.comment : "";
	const passphrase = (opt.passphrase && opt.passphrase !== '') ? opt.passphrase : null;
	const encryption = (passphrase !== null) ? "aes256-cbc" : "none";

	let keyPair;
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

		const pairBuffer = await Promise.all(
			Array.from(
				{ length: count },
				() => wrapWithProgress(crypto.subtle.generateKey(algo, true, keyUsage))
			)
		);

		keyPair = pairBuffer[keygenReduceNum % count];
	} else{
		keyPair = await crypto.subtle.generateKey(algo, true, ["sign", "verify"])

		if(typeof onProgress === 'function'){
			onProgress(1, 1);
		}
	}

	// 公開DER
	const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
	// 秘密DER
	const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

	// 公開鍵・フィンガープリント・PuTTY-Private-Key
	let opensshPubkey;
	let opensshFingerprint;
	let ppk;
	switch(name){
		case "RSA":
			const rsaOpenssh = await makeRsaOpenSSHPubKey(spki);

			opensshPubkey = `${opt.prefix} ${rsaOpenssh.pubkey}` + ((comment !== undefined && comment !== '') ? ` ${comment}` : "");
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${rsaOpenssh.fingerprint}`;
			ppk = await forPPK.makeRsaPpkV3(opt.prefix, keyPair, comment, rsaOpenssh.raw, encryption, passphrase);
			break;

		case "ECDSA":
			const ecdsaOpenssh = await makeEcdsaOpenSSHPubKey(spki);

			opensshPubkey = `${opt.prefix} ${ecdsaOpenssh.pubkey}` + ((comment !== undefined && comment !== '') ? ` ${comment}` : "");
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${ecdsaOpenssh.fingerprint}`;
			ppk = await forPPK.makeEcdsaPpkV3(opt.prefix, keyPair, comment, ecdsaOpenssh.raw, encryption, passphrase);
			break;
	}

	return {
		raw: keyPair,
		public: spki,
		private: pkcs8,
		openssh: opensshPubkey,
		ppk: ppk,
		fingerprint: opensshFingerprint
	};
}
