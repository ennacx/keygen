// CDN
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
// Local
import { OID, EdDSA_PRESET } from "./const.js";
import { Bytes } from "./bytes.js";
import { RFC4253 } from "./rfc4253.js";
import { DerHelper } from "./der-helper.js";

/**
 * Represents an Edwards-curve Digital Signature Algorithm (EdDSA) cryptographic key-pair generator and handler
 * supporting Ed25519 and Ed448 curves.
 *
 * Instances of this class manage both private and public keys,
 * as well as representation formats like SPKI, PKCS8, and JWK for interoperability in various systems.
 */
export class EdDSA {
	/**
	 * Represents the name of a specific curve. (e.g., "Ed25519", "Ed448")
	 *
	 * @type {string}
	 */
	curveName;

	/**
	 * Represents a predefined configuration or set of settings intended to be used as a template or default value.
	 *
	 * @type {Object}
	 */
	preset;

	/**
	 * Represents the seed value used for random number generation or other deterministic operations.
	 * The seed ensures reproducibility by providing a starting point for such processes.
	 *
	 * @type {Uint8Array}
	 */
	seed;

	/**
	 * Represents the type of the key used in a specific context. (e.g., "ssh-ed25519", "ssh-ed448")
	 *
	 * @type {string}
	 */
	keyType;

	/**
	 * Represents a public cryptographic key.
	 *
	 * @type {Uint8Array}
	 */
	publicKey;

	/**
	 * Represents the private key. (seed || publicKey)
	 *
	 * @type {Uint8Array}
	 */
	privateKey;

	/**
	 * Represents a publicly accessible data blob. (keyType || PublicKey)
	 *
	 * @type {Uint8Array}
	 */
	publicBlob;

	/**
	 * The `spki` variable represents a Subject Public Key Info (SPKI) structure,
	 * which is a standard data structure in cryptography used to describe public keys.
	 *
	 * @type {Uint8Array}
	 */
	spki;

	/**
	 * Represents a PKCS#8 encoded private key.
	 *
	 * @type {Uint8Array}
	 */
	pkcs8;

	/**
	 * Represents a JSON Web Key (JWK).
	 * A JSON Web Key is a JavaScript Object Notation (JSON) data structure
	 * that represents a cryptographic key. It is used for various cryptographic operations
	 * such as signing, encryption, and key exchange.
	 *
	 * @type {Object}
	 * @property {string} kty - The key type ("OKP" only).
	 * @property {string} crv - e.g., "Ed25519", "Ed448"
	 * @property {string} x - Base64 encoded public key.
	 * @property {string} d - (Optional) Base64 encoded seed.
	 */
	jwk;

	/**
	 * Constructs an instance of the class for the specified elliptic curve.
	 *
	 * @param {string} curveName - The name of the elliptic curve preset to use (e.g., 'Ed25519', 'Ed448').
	 * @throws {Error} Throws an error if the provided curve name is invalid or not supported.
	 * @return {Object} An object representing the initialized instance including public and private key materials,
	 *                  key formats, and additional information derived from the curve preset.
	 */
	constructor(curveName) {
		if(!EdDSA_PRESET[curveName]){
			throw new Error(`Invalid preset key: ${curveName}`);
		}

		this.curveName = curveName;
		this.preset    = EdDSA_PRESET[this.curveName];
		this.seed      = this.#generateSeed(this.preset.seedLen);
		this.keyType   = `ssh-${this.preset.name}`;

		switch(this.curveName){
			case 'Ed25519':
				this.publicKey = ed25519.getPublicKey(this.seed);
				break;
			case 'Ed448':
				this.publicKey = ed448.getPublicKey(this.seed);
				break;
			default:
				throw new Error(`Invalid curve: ${this.curveName}`);
		}

		this.publicBlob = Bytes.concat(
			RFC4253.writeString(this.keyType),
			RFC4253.writeStringBytes(this.publicKey)
		);

		// privateKey= seed || pub
		this.privateKey = Bytes.concat(this.seed, this.publicKey);

		this.spki  = this.#toSpkiDer();
		this.pkcs8 = this.#toPkcs8Der(false);
		this.jwk   = this.#toJwk();
	}

	/**
	 * Generates a cryptographically secure random seed as a Uint8Array.
	 *
	 * @param {number} length - The desired length of the generated seed.
	 * @return {Uint8Array} A Uint8Array containing randomly generated values.
	 */
	#generateSeed(length) {
		const seed = new Uint8Array(length);

		crypto.getRandomValues(seed);

		return seed;
	}

	/**
	 * Generates an AlgorithmIdentifier for the specified cryptographic curve.
	 *
	 * @param {string} crv - The curve identifier. Must be either "Ed25519" or "Ed448".
	 * @return {Uint8Array} The DER-encoded AlgorithmIdentifier sequence for the specified curve.
	 * @throws {Error} If the provided curve is invalid or unsupported.
	 */
	#algoIdFor(crv) {
		if(!OID[crv]){
			throw new Error(`Invalid curve: ${crv}. Must be Ed25519 or Ed448`);
		}

		const oid = OID[crv];

		// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ABSENT }
		return DerHelper.seq(DerHelper.oid(oid));
	}

	/**
	 * Converts the associated public key into the SPKI (Subject Public Key Info) DER format.
	 *
	 * @return {Uint8Array} The public key encoded in SPKI DER format as a Uint8Array.
	 */
	#toSpkiDer() {
		const alg = this.#algoIdFor(this.curveName);
		const spk = DerHelper.bit(this.publicKey); // BIT STRING of raw public key

		return DerHelper.concatSequence(alg, spk);
	}

	/**
	 * Converts the cryptographic key to a PKCS#8 DER-encoded format.
	 * This format is commonly used for representing private keys with optional inclusion of public keys.
	 *
	 * @param {boolean} [includePublic=false] - Indicates whether to include the public key in the DER-encoded output.
	 *                                          If true, the public key must be available, otherwise an error will be thrown.
	 * @return {Uint8Array} The PKCS#8 DER-encoded representation of the key.
	 *                      This will include the private key and, optionally, the public key.
	 * @throws {Error} If `includePublic` is true but the public key is not set.
	 */
	#toPkcs8Der(includePublic = false) {
		const algo       = this.#algoIdFor(this.curveName);
		const verNum     = (includePublic) ? 0x01 : 0x00; // v1 or v0
		const version    = DerHelper.tlv(0x02, new Uint8Array([verNum]));
		const insidePriv = DerHelper.oct(this.seed);       // RFC8410: privateKey OCTET STRING contains the seed (inside)
		const priv       = DerHelper.oct(insidePriv); // OCTET STRING contains the seed (outside)

		const items = [
			version,
			algo,
			priv
		];

		if(includePublic){
			if(!this.publicKey){
				throw new Error('includePublic=true requires pub');
			}

			const pubBit = DerHelper.bit(this.publicKey); // BIT STRING (0x00 || pub)

			// Add to items
			items.push(DerHelper.ctxExplicit(1, pubBit)); // [1] EXPLICIT BIT STRING
		}

		return DerHelper.concatSequence(...items);
	}

	/**
	 * Converts the current object to a JSON Web Key (JWK) format.
	 *
	 * @return {Object} A JWK representation of the object containing key type (kty),
	 * curve name (crv), public key (x), and optionally the private key (d) if available.
	 */
	#toJwk() {
		const jwk = {
			kty: 'OKP',
			crv: this.curveName,
			x: Bytes.toBase64Url(this.publicKey)
		};

		if(this.seed){
			jwk.d = Bytes.toBase64Url(this.seed);
		}

		return jwk;
	}
}