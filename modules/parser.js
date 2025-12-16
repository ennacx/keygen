/**
 * Represents a parser for decoding RSA and ECDSA SubjectPublicKeyInfo structures.
 * This class provides methods to extract relevant public key components such as
 * modulus, exponent, curve name, and EC points from their respective binary formats.
 */
export class Parser {
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
			if(algOid !== App.Helper.OID.ECDSA_SPKI){
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
				case App.Helper.OID.NIST_P256: // secp256r1
					curveName = "nistp256";
					break;
				case App.Helper.OID.NIST_P384: // secp384r1
					curveName = "nistp384";
					break;
				case App.Helper.OID.NIST_P521: // secp521r1
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
