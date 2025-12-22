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