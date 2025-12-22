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
		return [...arr].map((b) => b.toString(16).padStart(2, '0')).join('');
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
	 * Combines an array of strings into a single string, with elements separated by a specified separator.
	 * Optionally filters out empty lines before combining.
	 *
	 * @param {string[]} array - The array of strings to be concatenated.
	 * @param {Object} [opt] - Optional settings for concatenation.
	 * @param {string} [opt.separator="\n"] - The string used to separate the array elements.
	 * @param {boolean} [opt.ignoreEmptyLines=true] - A flag indicating whether empty strings should be ignored.
	 * @return {string} - The concatenated string with specified separator and optional filtering applied.
	 */
	static implode(array, opt = {separator: "\n", ignoreEmptyLines: true}) {
		if(opt.ignoreEmptyLines){
			array = array.filter((e) => e !== "");
		}

		return array.filter((e) => typeof e === 'string' || e instanceof String).join(opt.separator ?? "\n");
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
		const base64 = this.stringWrap(App.Bytes.toBase64(buffer), wrapWidth);

		if(addLabel !== ""){
			label = `${addLabel} ${label}`;
		}

		return this.implode([
			`-----BEGIN ${label}-----`,
			base64,
			`-----END ${label}-----`
		]);
	}
}
