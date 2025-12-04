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
	 * Parses an RSA SubjectPublicKeyInfo structure to extract the modulus and exponent components
	 * of an RSA public key.
	 *
	 * @return {Object} An object containing the RSA public key details:
	 *                  - `name`: The key algorithm name (always "ssh-rsa" for RSA keys).
	 *                  - `n`: The modulus as a byte array.
	 *                  - `e`: The exponent as a byte array.
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

			// subjectPublicKey BIT STRING
			this.#expect(0x03);
			const bitLen = this.#readLen();
			this.#offset++;               // unused bits = 0

			// RSAPublicKey (SEQUENCE)
			this.#expect(0x30);
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
	 * - `curveName`: The name of the curve in OpenSSH format (e.g., "nistp256").
	 * - `Q`: A Uint8Array representing the public key point (EC Point).
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

			const algOid = this.#readOidAsString();  // id-ecPublicKey のはず
			if(algOid !== "1.2.840.10045.2.1"){
				throw new Error(`Not an EC public key (unexpected algorithm OID: ${algOid})`);
			}

			const curveOid = this.#readOidAsString();  // 曲線OID

			// 残りはスキップ
			this.#offset = algEnd;

			// subjectPublicKey BIT STRING
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
		this.#bytes = new Uint8Array([]);
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

const PUBKEY_LABEL = "PUBLIC KEY";
const PRIVKEY_LABEL = "PRIVATE KEY";

let keygenReduceNum = -1;

/**
 * A set of utility functions for handling data formats and operations
 * specified in RFC 4253, focusing on SSH Binary Packet Protocol.
 */
const rfc4253 = {
	/**
	 * Encodes a given string into a Uint8Array format with a prepended 4-byte unsigned integer
	 * representing the length of the string in bytes.
	 *
	 * @param {string} str - The string to be encoded.
	 * @returns {Uint8Array} A byte array containing the string length as a 4-byte unsigned integer
	 *                       followed by the UTF-8 encoded representation of the string.
	 */
	writeString: (str) => {
		const enc = new TextEncoder();
		const s = enc.encode(str);

		const out = new Uint8Array(4 + s.length);
		const view = new DataView(out.buffer);
		view.setUint32(0, s.length);
		out.set(s, 4);

		return out;
	},

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

		const out = new Uint8Array(4 + b.length);
		const view = new DataView(out.buffer);
		view.setUint32(0, b.length);
		out.set(b, 4);

		return out;
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
		const out = new Uint8Array(4 + b.length);
		const view = new DataView(out.buffer);
		view.setUint32(0, b.length);
		out.set(b, 4);

		return out;
	},

	/**
	 * Concatenates multiple Uint8Array instances into a single Uint8Array.
	 *
	 * @param {Uint8Array[]} arrays - An array of Uint8Array instances to be concatenated.
	 * @returns {Uint8Array} A new Uint8Array containing the concatenated contents of the input arrays.
	 */
	concatBytes: (arrays) => {
		const len = arrays.reduce((sum, a) => sum + a.length, 0);
		const out = new Uint8Array(len);
		let offset = 0;
		for(const a of arrays){
			out.set(a, offset);
			offset += a.length;
		}

		return out;
	}
};

/**
 * Generates a SHA-256 fingerprint of the given data and converts it to a base64-encoded string without trailing equals signs.
 *
 * @param {ArrayBuffer} blob - The input data to generate the fingerprint for.
 * @return {Promise<string>} A promise that resolves to the base64-encoded SHA-256 fingerprint.
 */
async function makeFingerprint(blob) {
	const digest = await crypto.subtle.digest("SHA-256", blob);
	return toBase64(digest)
		// OpenSSH風に末尾の=を削る
		.replace(/=+$/, "");
}

/**
 * Generates an OpenSSH public key in RSA format from a given SPKI buffer.
 *
 * @param {Uint8Array} spkiBuf - A buffer containing the SPKI (Subject Public Key Info) data.
 * @return {Promise<{pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
 *    - `pubkey`: The Base64-encoded RSA public key in OpenSSH format.
 *    - `fingerprint`: The fingerprint of the RSA public key.
 */
async function makeRsaOpenSSHPubKey(spkiBuf) {
	const parser = new Parser(spkiBuf);
	const rsa = parser.rsaSpki();
	const blob = rfc4253.concatBytes([
		rfc4253.writeString(rsa.name),
		rfc4253.writeMpint(rsa.e),
		rfc4253.writeMpint(rsa.n)
	]);

	return {
		pubkey: toBase64(blob),
		fingerprint: await makeFingerprint(blob)
	};
}

/**
 * Generates an OpenSSH ECDSA public key from the provided SPKI (Subject Public Key Information) buffer.
 *
 * @param {Uint8Array} spkiBuf The buffer containing the SPKI data to parse the ECDSA public key from.
 * @return {Promise<{pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
 *    - `pubkey`: The Base64-encoded ECDSA public key in OpenSSH format.
 *    - `fingerprint`: The fingerprint of the ECDSA public key.
 */
async function makeEcdsaOpenSSHPubKey(spkiBuf) {
	const parser = new Parser(spkiBuf);
	const ecdsa = parser.ecdsaSpki();
	const blob = rfc4253.concatBytes([
		rfc4253.writeString(`ecdsa-sha2-${ecdsa.curveName}`),   //string  ex. "ecdsa-sha2-nistp256"
		rfc4253.writeString(ecdsa.curveName), // string "nistp256"
		rfc4253.writeStringBytes(ecdsa.Q),    // string Q (0x04 || X || Y)
	]);

	return {
		pubkey: toBase64(blob),
		fingerprint: await makeFingerprint(blob)
	};
}

/**
 * Converts an ArrayBuffer or TypedArray to a Base64-encoded string.
 *
 * @param {ArrayBuffer|TypedArray} buffer - The buffer or typed array that is to be converted to a Base64 string.
 * @returns {string} The Base64-encoded string representation of the input buffer.
 */
const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

/**
 * Decodes a Base64-encoded string into a Uint8Array.
 *
 * @param {string} b64 - The Base64-encoded string to decode. This string should not include
 * characters that are invalid in Base64 encoding, such as newline or whitespace.
 * @returns {Uint8Array|null} Returns a Uint8Array representing the decoded binary data, or null if the input is not a valid string.
 */
const fromBase64 = (b64) => {
	if(typeof b64 !== 'string'){
		return null;
	}

	const decoded = atob(b64.replace(/\-/g, '+').replace(/_/g, '/'));
	const buffer = new Uint8Array(decoded.length);
	for(let i = 0; i < b64.length; i++){
		buffer[i] = decoded.charCodeAt(i);
	}

	return buffer;
}

/**
 * Converts a given buffer into a PEM formatted string.
 *
 * @param {Buffer} buffer - The input buffer to be converted.
 * @param {string} label - The label to prepend and append to the PEM formatted string.
 * @returns {string} A PEM formatted string containing the base64 representation of the buffer, wrapped by the specified label.
 */
const toPEM = (buffer, label) => {
	const base64 = toBase64(buffer).replace(/(.{64})/g, "$1\n");

	return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}

/**
 * Generates a cryptographic key pair based on the specified algorithm and options.
 *
 * @param {string} name - The name of the algorithm to use for key generation (e.g., "RSA", "ECDSA").
 * @param {Object} opt - Options specific to the algorithm being used. For "RSA", this includes `len` (modulus length). For "ECDSA", this includes `nist` (named curve).
 * @param {function(number, number):void} [onProgress] - Optional callback function to track generation progress. It is called with the current progress step and the total steps.
 * @return {Promise<Object>} A promise that resolves to an object containing the keys and related data:
 * - `public` (ArrayBuffer): The public key in SPKI format.
 * - `private` (ArrayBuffer): The private key in PKCS8 format.
 * - `openssh` (string|undefined): The OpenSSH public key (only for RSA).
 * - `fingerprint` (string|undefined): The fingerprint of the OpenSSH public key (only for RSA).
 * @throws {Error} If an invalid algorithm name is provided or key generation fails.
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

	const comment = (opt.comment && opt.comment !== '') ? ` ${opt.comment}` : "";

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

	// OpenSSH公開鍵・フィンガープリント
	let opensshPubkey = undefined;
	let opensshFingerprint = undefined;
	switch(name){
		case "RSA":
			const rsaOpenssh = await makeRsaOpenSSHPubKey(spki);

			opensshPubkey = `${opt.prefix} ${rsaOpenssh.pubkey}${comment}`;
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${rsaOpenssh.fingerprint}`;
			break;

		case "ECDSA":
			const ecdsaOpenssh = await makeEcdsaOpenSSHPubKey(spki);

			opensshPubkey = `${opt.prefix} ${ecdsaOpenssh.pubkey}${comment}`;
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${ecdsaOpenssh.fingerprint}`;
			break;
	}

	return {
		public: spki,
		private: pkcs8,
		openssh: opensshPubkey,
		fingerprint: opensshFingerprint
	};
}
