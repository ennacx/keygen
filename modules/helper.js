/**
 * A utility class providing helper functions for data encoding, string manipulation, and formatting.
 */
export class Helper {
	/**
	 * Object Identifier (OID) mapping for cryptographic algorithms and key types.
	 *
	 * This object provides a set of Object Identifiers (OIDs) representing
	 * various standard cryptographic algorithms and related parameters.
	 * These OIDs are used to identify specific cryptographic primitives
	 * in protocols and data formats.
	 *
	 * Properties:
	 * - `PBES2`: OID for Password-Based Encryption Scheme 2 (PBES2).
	 * - `PBKDF2`: OID for Password-Based Key Derivation Function 2 (PBKDF2).
	 * - `HMAC_SHA256`: OID for Hash-based Message Authentication Code (HMAC) using SHA-256.
	 * - `AES256_CBC`: OID for AES encryption using 256-bit key in Cipher Block Chaining (CBC) mode.
	 * - `ECDSA_SPKI`: OID for Elliptic Curve Digital Signature Algorithm (ECDSA) in Subject Public Key Info (SPKI) format.
	 * - `NIST_P256`: OID for the NIST P-256 elliptic curve (also known as secp256r1).
	 * - `NIST_P384`: OID for the NIST P-384 elliptic curve (also known as secp384r1).
	 * - `NIST_P521`: OID for the NIST P-521 elliptic curve (also known as secp521r1).
	 */
	static OID = {
		PBES2:       "1.2.840.113549.1.5.13",
		PBKDF2:      "1.2.840.113549.1.5.12",
		HMAC_SHA256: "1.2.840.113549.2.9",
		AES256_CBC:  "2.16.840.1.101.3.4.1.42",
		ECDSA_SPKI:  "1.2.840.10045.2.1",
		NIST_P256:   "1.2.840.10045.3.1.7",
		NIST_P384:   "1.3.132.0.34",
		NIST_P521:   "1.3.132.0.35"
	};

	/**
	 * An object representing PEM (Privacy Enhanced Mail) labels used for identifying
	 * different types of keys and formats in PEM encoded data.
	 *
	 * Properties:
	 * - `publicKey`: The label for a public key in PEM format.
	 * - `privateKey`: The label for a private key in PEM format.
	 * - `opensshAdd`: The label indicating an OpenSSH formatted key or data.
	 * - `encryptedAdd`: The label indicating that the data is encrypted.
	 */
	static PEM_LABEL = {
		publicKey:    "PUBLIC KEY",
		privateKey:   "PRIVATE KEY",
		opensshAdd:   "OPENSSH",
		encryptedAdd: "ENCRYPTED"
	};

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
	 * Joins the elements of an array into a single string, separated by a specified delimiter.
	 *
	 * @param {Array} arr - The array of elements to be joined.
	 * @param {string} [sep="\n"] - The delimiter to separate the array elements.
	 * @return {string} The resulting string formed by concatenating the array elements with the specified delimiter.
	 */
	static implode(arr, sep = "\n") {
		return arr.join(sep);
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
