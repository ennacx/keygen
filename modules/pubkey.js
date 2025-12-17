export class PubKey {
	/**
	 * Represents a parser instance that is responsible for analyzing and interpreting input data or structures,
	 * converting them into a usable format or extracting specific information as required.
	 *
	 * This variable typically facilitates operations such as lexical analysis, syntactic analysis, or data transformation.
	 *
	 * The exact behavior and scope of this parser instance may vary depending on the context and implementation.
	 */
	#parser;

	/**
	 * Constructs an instance of the class with a specified SPKI DER-encoded value.
	 *
	 * @param {ArrayBuffer} spkiDer - The SPKI (Subject Public Key Info) data encoded in DER format.
	 * @return {void} This constructor does not return a value.
	 */
	constructor(spkiDer) {
		this.#parser = new App.Parser(spkiDer);
	}

	/**
	 * Generates an OpenSSH public key in RSA format from a given SPKI buffer.
	 *
	 * @async
	 * @return {Promise<{raw: Uint8Array, pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
	 *  - `raw`: RSA public key in OpenSSH format.
	 *  - `pubkey`: The Base64-encoded RSA public key in OpenSSH format.
	 *  - `fingerprint`: The fingerprint of the RSA public key.
	 */
	async rsa() {
		const rsa = this.#parser.rsaSpki();
		const blob = App.Bytes.concat(
			App.RFC4253.writeString(rsa.name),
			App.RFC4253.writeMpint(rsa.e),
			App.RFC4253.writeMpint(rsa.n)
		);

		return {
			raw: blob,
			pubkey: App.Bytes.toBase64(blob),
			fingerprint: await makeFingerprint(blob)
		};
	}

	/**
	 * Generates an OpenSSH ECDSA public key from the provided SPKI (Subject Public Key Information) buffer.
	 *
	 * @async
	 * @return {Promise<{raw: Uint8Array, pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
	 *  - `raw`: ECDSA public key in OpenSSH format.
	 *  - `pubkey`: The Base64-encoded ECDSA public key in OpenSSH format.
	 *  - `fingerprint`: The fingerprint of the ECDSA public key.
	 */
	async ecdsa() {
		const ecdsa = this.#parser.ecdsaSpki();
		const blob = App.Bytes.concat(
			App.RFC4253.writeString(`ecdsa-sha2-${ecdsa.curveName}`), //string  ex. "ecdsa-sha2-nistp256"
			App.RFC4253.writeString(ecdsa.curveName), // string "nistp256"
			App.RFC4253.writeStringBytes(ecdsa.Q),    // string Q (0x04 || X || Y)
		);

		return {
			raw: blob,
			pubkey: App.Bytes.toBase64(blob),
			fingerprint: await makeFingerprint(blob)
		};
	}
}
