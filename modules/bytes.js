export class Bytes {
	/**
	 * Concatenates multiple Uint8Array instances into a single Uint8Array.
	 *
	 * @param {...Uint8Array} arrays - The arrays to concatenate.
	 * @returns {Uint8Array} A new Uint8Array that contains the concatenated bytes of all input arrays.
	 */
	static concat(...arrays) {
		const arr = ((arrays.length === 1 && Array.isArray(arrays[0])) ? arrays[0] : [...arrays]).filter((a) => a instanceof Uint8Array);
		const len = arr.reduce((sum, a) => sum + a.length, 0);
		const out = new Uint8Array(len);
		let offset = 0;
		for(const a of arr){
			out.set(a, offset);
			offset += a.length;
		}

		return out;
	}

	/**
	 * Converts an ArrayBuffer or TypedArray to a Base64-encoded string.
	 *
	 * @param {ArrayBuffer|TypedArray} buffer - The buffer or typed array that is to be converted to a Base64 string.
	 * @returns {string} The Base64-encoded string representation of the input buffer.
	 */
	static toBase64(buffer) {
		return btoa(String.fromCharCode(...new Uint8Array(buffer)));
	}

	/**
	 * Decodes a Base64-encoded string into a Uint8Array.
	 *
	 * @param {string} b64 - The Base64-encoded string to decode. This string should not include
	 *                       characters that are invalid in Base64 encoding, such as newline or whitespace.
	 * @returns {Uint8Array|null} Returns a Uint8Array representing the decoded binary data, or null if the input is not a valid string.
	 */
	static fromBase64(b64) {
		if(typeof b64 !== 'string'){
			return null;
		}

		let s = b64.replace(/\-/g, '+').replace(/_/g, '/');
		while(s.length % 4 > 0){
			s += '=';
		}

		const decoded = atob(s);
		const buffer = new Uint8Array(decoded.length);
		for(let i = 0; i < b64.length; i++){
			buffer[i] = decoded.charCodeAt(i);
		}

		return buffer;
	}

	/**
	 * Generates a hashed seed from the input buffer using the specified algorithm.
	 *
	 * @param {ArrayBuffer} buffer - The input buffer to hash.
	 * @param {string} [algo='SHA-256'] - The hashing algorithm to use. Defaults to 'SHA-256'.
	 * @return {Promise<Uint8Array>} A promise that resolves to a Uint8Array containing the hashed seed.
	 */
	static async generateSeed(buffer, algo = 'SHA-256') {
		const digest = await crypto.subtle.digest(algo, buffer);

		// 集めたプールをハッシュ化 (seedマテリアルとして扱える256bit(32byte))
		return new Uint8Array(digest);
	};
}