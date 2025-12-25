import { Bytes } from "./bytes.js";
import { Parser } from "./parser.js";
import { RFC4253 } from "./rfc4253.js";

/**
 * The `PubKey` class provides methods to parse SPKI (Subject Public Key Info) data
 * and generate public key representations in formats compatible with OpenSSH.
 * It supports different types of public key algorithms such as RSA, ECDSA, and EdDSA,
 * and provides utilities for generating and retrieving key fingerprints.
 */
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
		this.#parser = new Parser(spkiDer);
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
		const blob = Bytes.concat(
			RFC4253.writeString(rsa.name),
			RFC4253.writeMpint(rsa.e),
			RFC4253.writeMpint(rsa.n)
		);

		return await this.#ret(blob);
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
		const blob = Bytes.concat(
			RFC4253.writeString(`ecdsa-sha2-${ecdsa.curveName}`), //string  ex. "ecdsa-sha2-nistp256"
			RFC4253.writeString(ecdsa.curveName), // string "nistp256"
			RFC4253.writeStringBytes(ecdsa.Q),    // string Q (0x04 || X || Y)
		);

		return await this.#ret(blob);
	}

	/**
	 * Generates and returns an EdDSA public key blob.
	 *
	 * The method constructs an EdDSA key blob from the parsed key typeand public key data.
	 * It processes these components according to the RFC4253 format and returns the resulting blob.
	 *
	 * @async
	 * @return {Promise<Uint8Array>} A promise that resolves to a Uint8Array
	 * representing the EdDSA key blob.
	 */
	async eddsa() {
		const eddsa = this.#parser.eddsaSpki(); // eddsaSpki() = { keyType: "ssh-ed25519" or "ssh-ed448", pub: Uint8Array }
		const blob = Bytes.concat(
			RFC4253.writeString(eddsa.keyType),
			RFC4253.writeStringBytes(eddsa.pub)
		);

		return await this.#ret(blob);
	}

	/**
	 * Generates a fingerprint string by computing the hash of the provided data and converting it to a Base64 encoded format.
	 *
	 * @async
	 * @static
	 * @param {ArrayBuffer} blob - The data to be hashed.
	 * @param {string} [algo='SHA-256'] - The hashing algorithm to use, defaults to 'SHA-256'.
	 * @return {Promise<string>} A promise that resolves to the fingerprint string with trailing equals signs removed.
	 */
	async #makeFingerprint(blob, algo = 'SHA-256') {
		const digest = await crypto.subtle.digest(algo, blob);

		return Bytes.toBase64(digest)
			// OpenSSH風に末尾の=を削る
			.replace(/=+$/, '');
	}

	/**
	 * Processes the provided binary data (blob) and generates metadata including a base64-encoded public key
	 * and a fingerprint derived from the binary data.
	 *
	 * @async
	 * @param {Uint8Array} blob The binary data input to process.
	 * @return {Promise<Object>} A promise that resolves to an object containing the raw input as `raw`,
	 * the base64-encoded public key as `pubkey`, and the calculated fingerprint as `fingerprint`.
	 */
	async #ret(blob) {
		return {
			raw: blob,
			pubkey: Bytes.toBase64(blob),
			fingerprint: await this.#makeFingerprint(blob)
		};
	}
}
