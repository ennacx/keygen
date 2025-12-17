/**
 * Generates an OpenSSH public key in RSA format from a given SPKI buffer.
 *
 * @async
 * @param {Uint8Array} spkiBuf - A buffer containing the SPKI (Subject Public Key Info) data.
 * @return {Promise<{raw: Uint8Array, pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
 *  - `raw`: RSA public key in OpenSSH format.
 *  - `pubkey`: The Base64-encoded RSA public key in OpenSSH format.
 *  - `fingerprint`: The fingerprint of the RSA public key.
 */
export async function makeRsaOpenSSHPubKey(spkiBuf) {
	const parser = new Parser(spkiBuf);
	const rsa = parser.rsaSpki();
	const blob = App.Bytes.concat(
		rfc4253.writeString(rsa.name),
		rfc4253.writeMpint(rsa.e),
		rfc4253.writeMpint(rsa.n)
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
 * @param {Uint8Array} spkiBuf The buffer containing the SPKI data to parse the ECDSA public key from.
 * @return {Promise<{raw: Uint8Array, pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
 *  - `raw`: ECDSA public key in OpenSSH format.
 *  - `pubkey`: The Base64-encoded ECDSA public key in OpenSSH format.
 *  - `fingerprint`: The fingerprint of the ECDSA public key.
 */
export async function makeEcdsaOpenSSHPubKey(spkiBuf) {
	const parser = new Parser(spkiBuf);
	const ecdsa = parser.ecdsaSpki();
	const blob = App.Bytes.concat(
		rfc4253.writeString(`ecdsa-sha2-${ecdsa.curveName}`), //string  ex. "ecdsa-sha2-nistp256"
		rfc4253.writeString(ecdsa.curveName), // string "nistp256"
		rfc4253.writeStringBytes(ecdsa.Q),    // string Q (0x04 || X || Y)
	);

	return {
		raw: blob,
		pubkey: App.Bytes.toBase64(blob),
		fingerprint: await makeFingerprint(blob)
	};
}
