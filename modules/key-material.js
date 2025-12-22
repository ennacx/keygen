import { Bytes } from './bytes.js';
import { RFC4253 } from './rfc4253.js';
import { EdDSA } from "./eddsa.js";

/**
 * Class representing cryptographic key material used for secure operations
 * such as encryption, decryption, signing, and verification.
 */
export class KeyMaterial {
	/**
	 * Represents a Subject Public Key Information (SPKI) structure.
	 *
	 * SPKI is used in cryptographic operations to define the public key
	 * and the associated algorithm. It is commonly represented in DER
	 * (Distinguished Encoding Rules) or PEM (Privacy-Enhanced Mail) format.
	 * This variable may be used for encoding, decoding, or other operations
	 * involving public key infrastructure.
	 *
	 * Typically applicable in scenarios involving X.509 certificates,
	 * TLS/SSL connections, or verifying digital signatures.
	 */
	spki;

	/**
	 * Represents a PKCS#8 encoded private key.
	 *
	 * PKCS#8 is a standard syntax for storing private key information.
	 * It encapsulates the private key along with optional algorithm identifiers and attributes.
	 * This format is commonly used in cryptography and for working with secure systems.
	 *
	 * Typically, this variable contains the private key data in either binary or Base64-encoded string format.
	 * It can be used for cryptographic operations like signing, encryption, or key exchange.
	 *
	 * The content may vary depending on whether the key is encoded in DER (binary) or PEM (Base64 with header/footer) format.
	 */
	pkcs8;

	/**
	 * Represents a JSON Web Key (JWK) used in cryptographic operations.
	 * JWK is a JSON data structure that represents a cryptographic key and its associated metadata,
	 * including its type, intended usage, and cryptographic algorithm.
	 *
	 * This variable may include various key properties depending on the specific use case or key type (such as RSA, EC, or symmetric keys).
	 * It can be used for operations like signature verification, encryption, decryption, or key derivation
	 * in compliance with JSON Web Algorithms (JWA) and JSON Web Key Set (JWKS) specifications.
	 */
	jwk;

	/**
	 * Error message indicating that the JSON Web Key (JWK) has not been initialized.
	 * This constant is used to inform the developer that the `getInstance()` method
	 * must be called first to generate a key pair and export the JWK before accessing it.
	 *
	 * @constant {string} JWK_NO_INIT_ERR_MSG
	 */
	JWK_NO_INIT_ERR_MSG = 'JSON Web Key (JWK) not found. Call getInstance() first to generate a key pair and export the JWK.';

	constructor() {
		// NOP
	}

	/**
	 * Generates an instance of the object with a cryptographic key pair based on the specified algorithm.
	 *
	 * @param {string} name - The name of the algorithm to use (e.g., 'RSA', 'EdDSA', or 'ECDSA').
	 * @param {Object} opt - Configuration options for the key generation.
	 * @param {number} [opt.len] - Key length (required for RSA or EdDSA).
	 * @param {number} [opt.seedLen] - Seed length (applicable for EdDSA).
	 * @param {string} [opt.hash] - Hashing algorithm (used for EdDSA).
	 * @param {string} [opt.nist] - Named curve for elliptic curve algorithms (applicable for ECDSA).
	 * @return {Promise<Object>} A promise that resolves to an instance with the generated cryptographic keys.
	 * @throws {Error} If the specified algorithm is unsupported or key pair generation fails.
	 */
	static async getInstance(name, opt) {
		const myself = new this();

		let algo = {};
		switch(name){
			case 'RSA':
				algo = {
					name: 'RSA-PSS',
					modulusLength: opt.len,
					publicExponent: new Uint8Array([1, 0, 1]),
					hash: 'SHA-256'
				};
				break;
			case 'EdDSA':
				break;
			case 'ECDSA':
				algo = {
					name: name,
					namedCurve: opt.nist
				};
				break;
			default:
				throw new Error(`Unsupported algorithm: ${name}`);
		}

		if(name !== 'EdDSA'){
			const keyPair = await crypto.subtle.generateKey(algo, true, ['sign', 'verify']);

			if(!keyPair.publicKey || !keyPair.privateKey){
				throw new Error('Failed to generate key pair');
			}

			myself.spki  = await crypto.subtle.exportKey('spki', keyPair.publicKey);
			myself.pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
			myself.jwk   = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
		} else{
			const eddsa = new EdDSA(opt.name);
			const a = eddsa.generate();

			myself.spki  = a.spki;
			myself.pkcs8 = a.pkcs8;
			myself.jwk   = a.jwk;
		}

		return myself;
	}

	/**
	 * Generates and returns the concatenated RSA private key components in the specified order.
	 * Keys include modulus (`n`), public exponent (`e`), private exponent (`d`),
	 * CRT coefficient (`qi`), and prime factors (`p, q`).
	 *
	 * @throws {Error} If the JWK object is not initialized.
	 * @return {Uint8Array} A byte array containing the concatenated RSA private key components
	 *                      in the order: `n, e, d, qi, p, q`.
	 */
	rsaPrivatePart() {
		if(!this.jwk){
			throw new Error(this.JWK_NO_INIT_ERR_MSG);
		}

		const n  = Bytes.fromBase64(this.jwk.n);
		const e  = Bytes.fromBase64(this.jwk.e);
		const d  = Bytes.fromBase64(this.jwk.d);
		const qi = Bytes.fromBase64(this.jwk.qi); // qinv (q⁻¹ mod p)
		const p  = Bytes.fromBase64(this.jwk.p);
		const q  = Bytes.fromBase64(this.jwk.q);

		// FIXME: openssh-key-v1の平文での秘密鍵情報では n, e, d, qi, p, q の順序が必須
		return Bytes.concat(
			RFC4253.writeMpint(n),
			RFC4253.writeMpint(e),
			RFC4253.writeMpint(d),
			RFC4253.writeMpint(qi),
			RFC4253.writeMpint(p),
			RFC4253.writeMpint(q)
		);
	}

	/**
	 * Serializes the private components of an RSA key (`d, p, q, qinv`) into the PPKv3 (PuTTY-Private-Key v3) format,
	 * which follows the specific order required: `d, p, q, qinv`.
	 *
	 * @return {Uint8Array} A concatenated byte array representing the private key components in PPKv3 format.
	 * @throws {Error} Throws an error if the JWK object is not initialized.
	 */
	rsaPrivatePartPPKv3() {
		if(!this.jwk){
			throw new Error(this.JWK_NO_INIT_ERR_MSG);
		}

		const d  = Bytes.fromBase64(this.jwk.d);
		const p  = Bytes.fromBase64(this.jwk.p);
		const q  = Bytes.fromBase64(this.jwk.q);
		const qi = Bytes.fromBase64(this.jwk.qi); // qinv (q⁻¹ mod p)

		// FIXME: PPKv3のRSAでは d, p, q, qinv の順序が必須
		return Bytes.concat(
			RFC4253.writeMpint(d),
			RFC4253.writeMpint(p),
			RFC4253.writeMpint(q),
			RFC4253.writeMpint(qi),
		);
	}

	/**
	 * Retrieves the private part of an ECDSA key.
	 * The method extracts the private key component (`d`) from the JWK property
	 * and returns it as bytes. Throws an error if the JWK is not initialized.
	 *
	 * @return {Uint8Array} The private key component in byte format.
	 * @throws {Error} If the JWK property is not initialized.
	 */
	ecdsaPrivatePart() {
		if(!this.jwk){
			throw new Error(this.JWK_NO_INIT_ERR_MSG);
		}

		// ECDSAでの平文の秘密鍵情報は d だけ
		return Bytes.fromBase64(this.jwk.d);
	}

	/**
	 * Generates the Q point for an ECDSA key based on the X and Y coordinates in the JWK.
	 *
	 * The Q point is represented as: `0x04 || xBytes || yBytes`,
	 * where:
	 *   - 0x04 is a 1-byte prefix.
	 *   - xBytes represents the X coordinate.
	 *   - yBytes represents the Y coordinate.
	 *
	 * The length of the generated Q point varies based on the curve:
	 *   - P-256: 65 bytes (1 + 32 + 32).
	 *   - P-384: 97 bytes (1 + 48 + 48).
	 *   - P-521: 133 bytes (1 + 66 + 66).
	 *
	 * @throws {Error} If the `jwk` property is not initialized.
	 * @return {Uint8Array} The concatenated Q point.
	 * @see [SEC1 (Elliptic Curve Cryptography 1)](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)
	 */
	ecdsaQPoint() {
		if(!this.jwk){
			throw new Error(this.JWK_NO_INIT_ERR_MSG);
		}

		// Q点 (0x04 || xBytes || yBytes)
		// Q.length = P-256: 65bytes(1+32+32), P-384: 97bytes, P-521: 133bytes
		return Bytes.concat(
			Uint8Array.from([0x04]),
			Bytes.fromBase64(this.jwk.x),
			Bytes.fromBase64(this.jwk.y)
		);
	}
}