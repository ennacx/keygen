export class DerHelper {
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
	static concat(...arrays) {
		const arr = ((arrays.length === 1 && Array.isArray(arrays[0])) ? arrays[0] : [...arrays]).filter((a) => a instanceof Uint8Array);
		const len = arr.reduce((n, a) => n + a.length, 0);
		const out = new Uint8Array(len);

		let off = 0;
		for(const a of arr){
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
	static len(len) {
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
	 * Creates a TLV (Tag-Length-Value) structure by combining the provided tag, the length of the value, and the value itself.
	 *
	 * @param {number} tag - The tag identifier represented as a number.
	 * @param {number[] | Uint8Array} value - The value to be included in the TLV structure. Can be an array of numbers or a Uint8Array.
	 * @return {Uint8Array} A new Uint8Array representing the constructed TLV structure.
	 */
	static tlv(tag, value) {
		const v = (value instanceof Uint8Array) ? value : new Uint8Array(value);

		return this.concat(new Uint8Array([tag]), this.len(v.length), v);
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
	static seq(content) {
		return this.tlv(0x30, content);
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
	static oct(bytes) {
		return this.tlv(0x04, bytes);
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
	static int(num) {
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

		return this.tlv(0x02, bytes);
	}

	/**
	 * Creates and returns a new Uint8Array representing a DER Null object.
	 * The DER Null object is encoded as a two-byte sequence with an object identifier of 0x05 and a zero-length content of 0x00.
	 *
	 * @returns {Uint8Array} A Uint8Array containing the DER Null encoding.
	 */
	static nul() {
		return new Uint8Array([0x05, 0x00]);
	}

	/**
	 * Processes the input bytes by appending a specific byte and wrapping it within a TLV structure.
	 *
	 * @param {Uint8Array} bytes - An array of bytes to be processed and encoded.
	 * @return {Uint8Array} The resulting TLV-encoded byte array.
	 */
	static bit(bytes) {
		return this.tlv(0x03, this.concat(new Uint8Array([0x00]), bytes));
	}

	/**
	 * Creates an explicit context-specific TLV (Tag-Length-Value) by combining the specified context index and inner TLV data.
	 *
	 * @param {number} n - The context-specific tag index to be added to the base value (0xA0).
	 * @param {Uint8Array} innerTlv - The inner TLV data to be wrapped within the context-specific TLV.
	 * @return {Uint8Array} - The constructed context-specific TLV as a Buffer.
	 */
	static ctxExplicit(n, innerTlv) {
		return this.tlv(0xA0 + n, innerTlv);
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
	static oid(oidStr) {
		const parts = oidStr.split('.').map((x) => parseInt(x, 10));
		if(parts.length < 2){
			throw new Error('Invalid OID');
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

		return this.tlv(0x06, b);
	}

	/**
	 * Concatenates multiple input arrays and processes the resulting sequence.
	 *
	 * @param {...Uint8Array} arrays - The arrays to be concatenated and processed.
	 * @return {Uint8Array} The processed sequence derived from the concatenated input arrays.
	 */
	static concatSequence(...arrays) {
		return this.seq(this.concat(...arrays));
	}
}