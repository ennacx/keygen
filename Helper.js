/**
 * A utility class providing helper functions for data encoding, string manipulation, and formatting.
 */
export class Helper {
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
	static hexPad(arr){
		return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
	}

	/**
	 * Encodes a given string into its corresponding UTF-8 byte representation.
	 *
	 * @function
	 * @param {string} s - The input string to be encoded.
	 * @returns {Uint8Array} The UTF-8 encoded byte array of the input string.
	 */
	static toUtf8(s) {
		return new TextEncoder().encode(s);
	}

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
	static stringWrap(str, width = 64) {
		return str.replace(new RegExp(`(.{1,${width}})`, "g"), (match, grp1) => (grp1) ? `${grp1}\n` : "").trimEnd();
	}

	/**
	 * Calculates the number of lines in a given string.
	 *
	 * This function splits the input string by newline characters ("\n") and counts the number of resulting segments,
	 * effectively determining the number of lines in the input.
	 *
	 * @param {string} str - The input string to evaluate.
	 * @returns {number} The number of lines in the input string.
	 */
	static lineCount(str) {
		return str.split("\n").length;
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
			s += "=";
		}

		const decoded = atob(s);
		const buffer = new Uint8Array(decoded.length);
		for(let i = 0; i < b64.length; i++){
			buffer[i] = decoded.charCodeAt(i);
		}

		return buffer;
	}

	/**
	 * Converts a given buffer to a PEM formatted string.
	 *
	 * @param {Buffer} buffer - The binary data to be encoded in PEM format.
	 * @param {string} label - The label to include in the PEM header and footer (e.g., "PUBLIC KEY", "PRIVATE KEY").
	 * @param {number} [wrapWidth=64] - The width of line wrapping for the base64 content; defaults to 64.
	 * @param {string} [addLabel=""] - An optional additional prefix to the label,
	 *                                   appended before the main label in the header and footer (e.g., "ENCRYPTED", "OPENSSH").
	 * @returns {string} A PEM formatted string with the provided label and encoded data.
	 */
	static toPEM(buffer, label, wrapWidth = 64, addLabel = "") {
		const base64 = Helper.stringWrap(Helper.toBase64(buffer), wrapWidth);

		if(addLabel !== ""){
			label = `${addLabel} ${label}`;
		}

		return [
			`-----BEGIN ${label}-----`,
			base64,
			`-----END ${label}-----`
		].join("\n");
	}
}
