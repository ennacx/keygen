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
	 * Converts the given buffer into a Base64 URL-safe string.
	 * Replaces characters `+` with `-` and `/` with `_`, and trims
	 * trailing `=` characters.
	 *
	 * @param {Uint8Array|ArrayBuffer} buffer - The input buffer to be converted.
	 * @return {string} The Base64 URL-safe string representation of the buffer.
	 */
	static toBase64Url(buffer) {
		return this.toBase64(buffer)
			.replace(/\+/g, '-').replace(/\//g, '_')
			// OpenSSH風に末尾の=を削る
			.replace(/=+$/, '');
	}

	/**
	 * Decodes a Base64-encoded string into a Uint8Array.
	 *
	 * @param {string} b64 - The Base64-encoded string to decode. If the string is not properly formatted,
	 *                       it will attempt to correct padding and replace unsupported characters.
	 * @return {Uint8Array|null} The decoded data as a Uint8Array, or null if the input is not a string.
	 */
	static fromBase64(b64) {
		if(typeof b64 !== 'string'){
			return null;
		}

		let s = b64.replace(/\-/g, '+').replace(/_/g, '/');
		while(s.length % 4 > 0){
			s += '=';
		}

		const decoded    = atob(s);
		const decodedLen = decoded.length;
		const buffer     = new Uint8Array(decodedLen);
		for(let i = 0; i < decodedLen; i++){
			buffer[i] = decoded.charCodeAt(i);
		}

		return buffer;
	}

	/**
	 * Generates a random unsigned 8-bit integer (Uint8) using a cryptographically secure random number generator.
	 *
	 * @return {number} A cryptographically secure random unsigned 8-bit integer.
	 */
	static getRandomUint8() {
		return crypto.getRandomValues(new Uint8Array(1))[0];
	}

	/**
	 * Generates a random unsigned 32-bit integer (Uint32) using a cryptographically secure random number generator.
	 *
	 * @return {number} A cryptographically secure random unsigned 32-bit integer.
	 */
	static getRandomUint32() {
		return crypto.getRandomValues(new Uint32Array(1))[0];
	}

	/**
	 * Generates a cryptographically secure random salt.
	 *
	 * @param {number} [saltLen=16] - The desired length of the generated salt.
	 * @return {Uint8Array} A Uint8Array containing the randomly generated salt.
	 */
	static generateSalt(saltLen = 16) {
		return crypto.getRandomValues(new Uint8Array(saltLen));
	}

	/**
	 * Generates a hashed seed from the input buffer using the specified algorithm.
	 *
	 * @param {ArrayBuffer} buffer - The input buffer to hash.
	 * @param {string} [algo='SHA-256'] - The hashing algorithm to use. Defaults to 'SHA-256'.
	 * @return {Promise<Uint8Array>} A promise that resolves to a Uint8Array containing the hashed seed
	 */
	static async generateSeed(buffer, algo = 'SHA-256') {
		const digest = await crypto.subtle.digest(algo, buffer);

		// 集めたプールをハッシュ化 (seedマテリアルとして扱える256bit(32byte))
		return new Uint8Array(digest);
	};
}