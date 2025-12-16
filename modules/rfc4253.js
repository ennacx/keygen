/**
 * A set of utility functions for handling data formats and operations
 * specified in RFC 4253, focusing on SSH Binary Packet Protocol.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc4253
 */
export class RFC4253 {
	/**
	 * Encodes an array of bytes into a Uint8Array, prefixed with its length as a 32-bit unsigned integer.
	 *
	 * @param {Uint8Array} array - The input array of bytes to encode.
	 * @returns {Uint8Array} A new Uint8Array containing the 32-bit unsigned length followed by the input array's data.
	 */
	static writer(array) {
		const out = new Uint8Array(4 + array.length);
		const view = new DataView(out.buffer);

		view.setUint32(0, array.length);
		out.set(array, 4);

		return out;
	}

	/**
	 * Encodes a 32-bit unsigned integer into a 4-byte Uint8Array
	 * in big-endian byte order.
	 *
	 * @param {number} value - The 32-bit unsigned integer to encode.
	 * @returns {Uint8Array} A Uint8Array containing the big-endian representation of the input value.
	 */
	static writeUint32(value) {
		const buf = new Uint8Array(4);
		const view = new DataView(buf.buffer);

		view.setUint32(0, value >>> 0, false); // big endian

		return buf;
	}

	/**
	 * Encodes a given string into a Uint8Array format with a prepended 4-byte unsigned integer
	 * representing the length of the string in bytes.
	 *
	 * @param {string} str - The string to be encoded.
	 * @returns {Uint8Array} A byte array containing the string length as a 4-byte unsigned integer
	 *                       followed by the UTF-8 encoded representation of the string.
	 */
	static writeString(str) {
		return this.writer(App.Helper.toUtf8(str));
	}

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
	static writeStringBytes(bytes) {
		const b = (bytes instanceof Uint8Array) ? bytes : new Uint8Array(bytes);

		return this.writer(b);
	}

	/**
	 * Converts a byte array into an mpint (multiple precision integer) format.
	 * If the most significant bit of the first byte is set to 1, prepends a 0x00 byte to preserve the sign.
	 * Prepends the length of the byte array as a 4-byte unsigned integer in big-endian format to the output.
	 *
	 * @param {Uint8Array} bytes - The input byte array to be converted into mpint format.
	 * @returns {Uint8Array} A new Uint8Array in mpint format, containing the length prefix and the adjusted byte array.
	 */
	static writeMpint(bytes) {
		// mpintは先頭bitが1なら 0x00 を前置して符号を守る
		let b = bytes;
		if(b.length > 0 && (b[0] & 0x80)){
			const tmp = new Uint8Array(b.length + 1);
			tmp.set(b, 1);
			b = tmp;
		}

		return this.writeStringBytes(b);
	}
}