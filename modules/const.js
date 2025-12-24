/**
 * An object that maps commonly used cryptographic Object Identifiers (OIDs)
 * to their respective string representations. Each key represents a specific
 * cryptographic algorithm or parameter, and the value is its corresponding OID.
 *
 * Properties:
 * - PBES2: Represents the OID for Password-Based Encryption Scheme version 2 (`1.2.840.113549.1.5.13`).
 * - PBKDF2: Represents the OID for Password-Based Key Derivation Function 2 (`1.2.840.113549.1.5.12`).
 * - HMAC_SHA256: Represents the OID for HMAC with SHA-256 (`1.2.840.113549.2.9`).
 * - AES256_CBC: Represents the OID for AES encryption in CBC mode with a 256-bit key (`2.16.840.1.101.3.4.1.42`).
 * - ECDSA_SPKI: Represents the OID for ECDSA Subject Public Key Information (`1.2.840.10045.2.1`).
 * - NIST_P256: Represents the OID for the NIST P-256 elliptic curve (`1.2.840.10045.3.1.7`).
 * - NIST_P384: Represents the OID for the NIST P-384 elliptic curve (`1.3.132.0.34`).
 * - NIST_P521: Represents the OID for the NIST P-521 elliptic curve (`1.3.132.0.35`).
 * - Ed25519: Represents the OID for the Edwards-curve digital signature algorithm (EdDSA) using Curve25519 (`1.3.101.112`).
 * - Ed448: Represents the OID for the Edwards-curve digital signature algorithm (EdDSA) using Curve448 (`1.3.101.113`).
 */
export const OID = {
	PBES2:       '1.2.840.113549.1.5.13',
	PBKDF2:      '1.2.840.113549.1.5.12',
	HMAC_SHA256: '1.2.840.113549.2.9',
	AES256_CBC:  '2.16.840.1.101.3.4.1.42',
	ECDSA_SPKI:  '1.2.840.10045.2.1',
	NIST_P256:   '1.2.840.10045.3.1.7',
	NIST_P384:   '1.3.132.0.34',
	NIST_P521:   '1.3.132.0.35',
	Ed25519:     '1.3.101.112',
	Ed448:       '1.3.101.113'
};

/**
 * A preset configuration object for EdDSA (Edwards-curve Digital Signature Algorithm) key pair generation settings.
 *
 * @constant
 * @type {Object}
 * @property {Object} Ed25519 Configuration for the Ed25519 curve.
 * @property {string} Ed25519.name The name of the Ed25519 curve.
 * @property {number} Ed25519.len The bit length of the Ed25519 curve.
 * @property {number} Ed25519.seedLen The length of the seed (in bytes) required for key generation in Ed25519.
 * @property {string} Ed25519.hash The hashing algorithm used for Ed25519.
 * @property {Object} Ed448 Configuration for the Ed448 curve.
 * @property {string} Ed448.name The name of the Ed448 curve.
 * @property {number} Ed448.len The bit length of the Ed448 curve.
 * @property {number} Ed448.seedLen The length of the seed (in bytes) required for key generation in Ed448.
 * @property {string} Ed448.hash The hashing algorithm used for Ed448.
 */
export const EdDSA_PRESET = {
	Ed25519: {
		name: 'ed25519',
		len: 255,
		seedLen: 32,
		hash: 'SHA-512',
	},
	Ed448: {
		name: 'ed448',
		len: 448,
		seedLen: 57,
		hash: 'SHAKE-256',
	}
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
export const PEM_LABEL = {
	publicKey:    "PUBLIC KEY",
	privateKey:   "PRIVATE KEY",
	opensshAdd:   "OPENSSH",
	encryptedAdd: "ENCRYPTED"
};