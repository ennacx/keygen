/**
 * Represents a parser for decoding RSA and ECDSA SubjectPublicKeyInfo structures.
 * This class provides methods to extract relevant public key components such as
 * modulus, exponent, curve name, and EC points from their respective binary formats.
 */
class Parser {
	#bytes;
	#offset = 0;

	/**
	 * Constructs an instance with the specified SPKI (Subject Public Key Info) buffer.
	 *
	 * @param {Uint8Array|ArrayBuffer} spkiBuf - The Subject Public Key Info buffer used for initialization. Can be either a Uint8Array or an ArrayBuffer.
	 * @return {void} This constructor does not return a value.
	 */
	constructor(spkiBuf){
		this.#bytes = (spkiBuf instanceof Uint8Array) ? spkiBuf : new Uint8Array(spkiBuf);
		this.#offset = 0;
	}

	/**
	 * Parses an RSA SubjectPublicKeyInfo structure to extract the modulus and exponent components of an RSA public key.
	 *
	 * @return {Object} An object containing the RSA public key details:
	 *  - `name`: The key algorithm name (always "ssh-rsa" for RSA keys).
	 *  - `n`: The modulus as a byte array.
	 *  - `e`: The exponent as a byte array.
	 */
	rsaSpki() {
		try {
			// SubjectPublicKeyInfo
			this.#expect(0x30);           // SEQUENCE
			this.#readLen();              // 全体長

			// AlgorithmIdentifier
			this.#expect(0x30);           // SEQUENCE
			const algLen = this.#readLen();
			this.#offset += algLen;       // ざっくりスキップ（rsaEncryption前提）

			// subjectPublicKey BIT STRING
			this.#expect(0x03);
			const bitLen = this.#readLen();
			this.#offset++;               // unused bits = 0

			// RSAPublicKey (SEQUENCE)
			this.#expect(0x30);
			this.#readLen();

			// modulus (INTEGER)
			this.#expect(0x02);
			let nLen = this.#readLen();
			let nStart = this.#offset;
			this.#offset += nLen;

			// exponent (INTEGER)
			this.#expect(0x02);
			let eLen = this.#readLen();
			let eStart = this.#offset;
			this.#offset += eLen;

			// 先頭 0x00 は符号ビット用の場合があるので取り除く
			while(nLen > 0 && this.#bytes[nStart] === 0x00){
				nStart++;
				nLen--;
			}
			while(eLen > 0 && this.#bytes[eStart] === 0x00){
				eStart++;
				eLen--;
			}

			// 元のバイト列からmodulus, exponentを切り出す
			const n = this.#bytes.slice(nStart, nStart + nLen);
			const e = this.#bytes.slice(eStart, eStart + eLen);

			return {
				name: "ssh-rsa",
				n: n,
				e: e
			};
		} finally {
			this.#reset();
		}
	}

	/**
	 * Parses an ECDSA key in the SubjectPublicKeyInfo format, extracting the curve name
	 * and public key point (Q) as used in the ECDSA algorithm.
	 *
	 * @return {Object} An object containing the parsed information:
	 *  - `curveName`: The name of the curve in OpenSSH format (e.g., "nistp256").
	 *  - `Q`: A Uint8Array representing the public key point (EC Point).
	 * @throws {Error} If the input is not an EC public key, contains unexpected OIDs,
	 *                 or unsupported EC curves are encountered.
	 */
	ecdsaSpki() {
		try {
			// SubjectPublicKeyInfo
			this.#expect(0x30);              // SEQUENCE
			this.#readLen();                 // 全体長は使わない

			// AlgorithmIdentifier
			this.#expect(0x30);              // SEQUENCE
			const algLen = this.#readLen();
			const algEnd = this.#offset + algLen;

			const algOid = this.#readOidAsString();  // id-ecPublicKey のはず
			if(algOid !== "1.2.840.10045.2.1"){
				throw new Error(`Not an EC public key (unexpected algorithm OID: ${algOid})`);
			}

			const curveOid = this.#readOidAsString();  // 曲線OID

			// 残りはスキップ
			this.#offset = algEnd;

			// subjectPublicKey BIT STRING
			this.#expect(0x03);
			const bitStrLen = this.#readLen();
			const unusedBits = this.#bytes[this.#offset++];  // たいてい 0
			if(unusedBits !== 0){
				throw new Error("Unexpected unused bits in EC public key");
			}

			// 残り全部が Q（EC Point）
			const q = this.#bytes.slice(this.#offset, this.#offset + (bitStrLen - 1));

			// OID → OpenSSHのcurve名にマップ
			let curveName;
			switch(curveOid){
				case "1.2.840.10045.3.1.7":   // secp256r1
					curveName = "nistp256";
					break;
				case "1.3.132.0.34":          // secp384r1
					curveName = "nistp384";
					break;
				case "1.3.132.0.35":          // secp521r1
					curveName = "nistp521";
					break;
				default:
					throw new Error(`Unsupported EC curve OID: ${curveOid}`);
			}

			return {
				curveName: curveName,
				Q: q
			};
		} finally {
			this.#reset();
		}
	}

	/**
	 * Reads a length value from a byte array, interpreting the value based on the first byte.
	 *
	 * If the most significant bit (MSB) of the first byte is not set, the value of the first byte
	 * directly represents the length. If the MSB is set, the remaining 7 bits of the first byte
	 * indicate the number of subsequent bytes that represent the length in a big-endian manner.
	 *
	 * The function advances the offset position with each byte processed.
	 *
	 * @function
	 * @returns {number} The decoded length value derived from the bytes at the current offset.
	 */
	#readLen() {
		let len = this.#bytes[this.#offset++];
		if(len & 0x80){
			const nBytes = len & 0x7F;

			len = 0;
			for(let i = 0; i < nBytes; i++){
				len = (len << 8) | this.#bytes[this.#offset++];
			}
		}

		return len;
	};

	/**
	 * Validates that the current byte from the input buffer matches the expected ASN.1 tag.
	 * Increments the offset after reading the byte.
	 *
	 * @param {number} tag - The expected ASN.1 tag value to match.
	 * @throws {Error} If the current byte does not match the expected tag value, an error is thrown with a message including the expected tag.
	 */
	#expect(tag) {
		if(this.#bytes[this.#offset++] !== tag){
			throw new Error(`Unexpected ASN.1 tag, expected 0x${tag.toString(16).padStart(2, '0')}`);
		}
	};

	/**
	 * Resets the internal state of the object by clearing the byte array and resetting the offset to zero.
	 *
	 * @return {void} Does not return a value.
	 */
	#reset() {
		this.#bytes = new Uint8Array(0);
		this.#offset = 0;
	}

	/**
	 * Reads an Object Identifier (OID) from the byte stream and decodes it into its standard dot-separated string representation.
	 *
	 * The method processes the bytes from the stream, calculates the OID components (including using the special logic for the first two components),
	 * and concatenates the values into a string format commonly used for OIDs.
	 *
	 * @return {string} The decoded OID as a dot-separated string.（1.2.840... の形式）
	 */
	#readOidAsString() {
		this.#expect(0x06);
		const len = this.#readLen();
		const end = this.#offset + len;
		const out = [];

		// 先頭1byteは (first * 40 + second)
		const first = this.#bytes[this.#offset++];
		out.push(Math.floor(first / 40));
		out.push(first % 40);

		let value = 0;
		while(this.#offset < end){
			const b = this.#bytes[this.#offset++];
			value = (value << 7) | (b & 0x7F);
			if((b & 0x80) === 0){
				out.push(value);
				value = 0;
			}
		}

		return out.join(".");
	}
}

const PUBKEY_LABEL = "PUBLIC KEY";
const PRIVKEY_LABEL = "PRIVATE KEY";

let keygenReduceNum = -1;

/**
 * Generates a SHA-256 fingerprint of the given data and converts it to a base64-encoded string without trailing equals signs.
 *
 * @param {ArrayBuffer} blob - The input data to generate the fingerprint for.
 * @return {Promise<string>} A promise that resolves to the base64-encoded SHA-256 fingerprint.
 */
async function makeFingerprint(blob) {
	const digest = await crypto.subtle.digest("SHA-256", blob);
	return toBase64(digest)
		// OpenSSH風に末尾の=を削る
		.replace(/=+$/, "");
}

/**
 * Generates an OpenSSH public key in RSA format from a given SPKI buffer.
 *
 * @param {Uint8Array} spkiBuf - A buffer containing the SPKI (Subject Public Key Info) data.
 * @return {Promise<{raw: Uint8Array, pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
 *  - `raw`: RSA public key in OpenSSH format.
 *  - `pubkey`: The Base64-encoded RSA public key in OpenSSH format.
 *  - `fingerprint`: The fingerprint of the RSA public key.
 */
async function makeRsaOpenSSHPubKey(spkiBuf) {
	const parser = new Parser(spkiBuf);
	const rsa = parser.rsaSpki();
	const blob = rfc4253.concatBytes([
		rfc4253.writeString(rsa.name),
		rfc4253.writeMpint(rsa.e),
		rfc4253.writeMpint(rsa.n)
	]);

	return {
		raw: blob,
		pubkey: toBase64(blob),
		fingerprint: await makeFingerprint(blob)
	};
}

/**
 * Generates an OpenSSH ECDSA public key from the provided SPKI (Subject Public Key Information) buffer.
 *
 * @param {Uint8Array} spkiBuf The buffer containing the SPKI data to parse the ECDSA public key from.
 * @return {Promise<{raw: Uint8Array, pubkey: string, fingerprint: string}>} A promise that resolves to an object with the following properties:
 *  - `raw`: ECDSA public key in OpenSSH format.
 *  - `pubkey`: The Base64-encoded ECDSA public key in OpenSSH format.
 *  - `fingerprint`: The fingerprint of the ECDSA public key.
 */
async function makeEcdsaOpenSSHPubKey(spkiBuf) {
	const parser = new Parser(spkiBuf);
	const ecdsa = parser.ecdsaSpki();
	const blob = rfc4253.concatBytes([
		rfc4253.writeString(`ecdsa-sha2-${ecdsa.curveName}`), //string  ex. "ecdsa-sha2-nistp256"
		rfc4253.writeString(ecdsa.curveName), // string "nistp256"
		rfc4253.writeStringBytes(ecdsa.Q),    // string Q (0x04 || X || Y)
	]);

	return {
		raw: blob,
		pubkey: toBase64(blob),
		fingerprint: await makeFingerprint(blob)
	};
}

/**
 * Generates an RSA private key blob in the appropriate format.
 *
 * This method exports the provided private key to JWK format, extracts the components
 * required for the blob (d, p, q, and qi), and concatenates them into a byte array
 * according to the RFC 4253 specification.
 *
 * @param {CryptoKey} privateKey - The RSA private key to be converted into a private key blob.
 * @return {Promise<Uint8Array>} A promise that resolves to the RSA private key blob represented as a byte array.
 */
async function makeRsaPrivateBlob(privateKey) {
	const jwk = await crypto.subtle.exportKey("jwk", privateKey);

	// RSAでは d, p, q, qinv
	const d  = fromBase64(jwk.d);
	const p  = fromBase64(jwk.p);
	const q  = fromBase64(jwk.q);
	const qi = fromBase64(jwk.qi); // qinv (q⁻¹ mod p)

	return rfc4253.concatBytes([
		rfc4253.writeMpint(d),
		rfc4253.writeMpint(p),
		rfc4253.writeMpint(q),
		rfc4253.writeMpint(qi),
	]);
}

/**
 * Generates an ECDSA private key blob in the appropriate format.
 *
 * @param {CryptoKey} privateKey - The ECDSA private key to be exported and processed.
 * @return {Promise<Uint8Array>} A promise that resolves to the ECDSA private key blob represented as a byte array.
 */
async function makeEcdsaPrivateBlob(privateKey) {
	const jwk = await crypto.subtle.exportKey("jwk", privateKey);

	// ECDSAでは d だけ
	const d = fromBase64(jwk.d);

	// PPKv3の`C.3.3: NIST EC keys`は`mpint(d)`だけ
	return rfc4253.writeMpint(d);
}

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
const hexPad = (arr) => [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");

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
const stringWrap = (str, width = 64) => str.replace(new RegExp(`(.{1,${width}})`, "g"), (match, grp1) => (grp1) ? `${grp1}\n` : "").trimEnd();

/**
 * Converts an ArrayBuffer or TypedArray to a Base64-encoded string.
 *
 * @param {ArrayBuffer|TypedArray} buffer - The buffer or typed array that is to be converted to a Base64 string.
 * @returns {string} The Base64-encoded string representation of the input buffer.
 */
const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

/**
 * Decodes a Base64-encoded string into a Uint8Array.
 *
 * @param {string} b64 - The Base64-encoded string to decode. This string should not include
 *                       characters that are invalid in Base64 encoding, such as newline or whitespace.
 * @returns {Uint8Array|null} Returns a Uint8Array representing the decoded binary data, or null if the input is not a valid string.
 */
const fromBase64 = (b64) => {
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
 * Converts a given buffer into a PEM formatted string.
 *
 * @param {Buffer} buffer - The input buffer to be converted.
 * @param {string} label - The label to prepend and append to the PEM formatted string.
 * @returns {string} A PEM formatted string containing the base64 representation of the buffer, wrapped by the specified label.
 */
const toPEM = (buffer, label) => {
	const base64 = stringWrap(toBase64(buffer), 64);

	return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}

/**
 * A set of utility functions for handling data formats and operations
 * specified in RFC 4253, focusing on SSH Binary Packet Protocol.
 */
const rfc4253 = {
	/**
	 * Encodes an array of bytes into a Uint8Array, prefixed with its length as a 32-bit unsigned integer.
	 *
	 * @param {Uint8Array} array - The input array of bytes to encode.
	 * @returns {Uint8Array} A new Uint8Array containing the 32-bit unsigned length followed by the input array's data.
	 */
	writer: (array) => {
		const out = new Uint8Array(4 + array.length);
		const view = new DataView(out.buffer);
		view.setUint32(0, array.length);
		out.set(array, 4);

		return out;
	},

	/**
	 * Encodes a given string into a Uint8Array format with a prepended 4-byte unsigned integer
	 * representing the length of the string in bytes.
	 *
	 * @param {string} str - The string to be encoded.
	 * @returns {Uint8Array} A byte array containing the string length as a 4-byte unsigned integer
	 *                       followed by the UTF-8 encoded representation of the string.
	 */
	writeString: (str) => {
		const enc = new TextEncoder();
		const s = enc.encode(str);

		return rfc4253.writer(s);
	},

	/**
	 * Converts the given input into a Uint8Array, calculates its length, and returns a new Uint8Array
	 * where the first 4 bytes represent the length of the input array and the remaining bytes
	 * contain the input data.
	 *
	 * @param {ArrayBuffer | Uint8Array} bytes - The input that will be converted to a Uint8Array.
	 *                                           If it is not already a Uint8Array, it will be wrapped in one.
	 * @returns {Uint8Array} A new Uint8Array where the first 4 bytes encode the length of the input data,
	 *                       followed by the data itself.
	 */
	writeStringBytes: (bytes) => {
		const b = (bytes instanceof Uint8Array) ? bytes : new Uint8Array(bytes);

		return rfc4253.writer(b);
	},

	/**
	 * Converts a byte array into an mpint (multiple precision integer) format.
	 * If the most significant bit of the first byte is set to 1, prepends a 0x00 byte to preserve the sign.
	 * Prepends the length of the byte array as a 4-byte unsigned integer in big-endian format to the output.
	 *
	 * @param {Uint8Array} bytes - The input byte array to be converted into mpint format.
	 * @returns {Uint8Array} A new Uint8Array in mpint format, containing the length prefix and the adjusted byte array.
	 */
	writeMpint: (bytes) => {
		// mpintは先頭bitが1なら 0x00 を前置して符号を守る
		let b = bytes;
		if(b.length > 0 && (b[0] & 0x80)){
			const tmp = new Uint8Array(b.length + 1);
			tmp.set(b, 1);
			b = tmp;
		}

		return rfc4253.writeStringBytes(b);
	},

	/**
	 * Concatenates multiple Uint8Array instances into a single Uint8Array.
	 *
	 * @param {Uint8Array[]} arrays - An array of Uint8Array instances to be concatenated.
	 * @returns {Uint8Array} A new Uint8Array containing the concatenated contents of the input arrays.
	 */
	concatBytes: (arrays) => {
		const len = arrays.reduce((sum, a) => sum + a.length, 0);
		const out = new Uint8Array(len);
		let offset = 0;
		for(const a of arrays){
			out.set(a, offset);
			offset += a.length;
		}

		return out;
	}
};

/**
 * An object containing utility functions for handling PuTTY Private Key (PPK) operations.
 *
 * @property {Function} computeMac - Computes a Message Authentication Code (MAC) to ensure integrity of provided inputs.
 * @property {Function} makeRsaPpkV3 - Generates an RSA PuTTY Private Key file in the format of PuTTY-User-Key-File-3 based on the given key pair and parameters.
 */
const forPPK = {
	/**
	 * Derives cryptographic keys from a given passphrase using the Argon2id key derivation function.
	 *
	 * @param {string} passphrase - The passphrase to be used for key derivation.
	 * @returns {Promise<Object>} An object containing the derived keys and used parameters:
	 *  - `salt` {Uint8Array}: The randomly generated salt used in the derivation.
	 *  - `mem` {number}: Memory size in KiB used in the derivation.
	 *  - `pass` {number}: Number of iterations used in the derivation.
	 *  - `parallel` {number}: Number of parallel threads used in the derivation.
	 *  - `cipher` {Uint8Array}: The derived cipher key for AES-256 encryption.
	 *  - `iv` {Uint8Array}: The derived initialization vector for AES-CBC.
	 *  - `mk` {Uint8Array}: The derived HMAC-SHA-256 key.
	 * @throws {Error} Throws an error if the `argon2-browser` library is not loaded or missing necessary functionality.
	 */
	deriveKeys: async (passphrase) => {
		if(!argon2 || typeof argon2.hash !== 'function'){
			throw new Error("argon2-browser is required for deriveKeys");
		}

		const enc = new TextEncoder();
		const passBytes = enc.encode(passphrase);

		// PuTTYっぽいデフォルト値 (サンプルでもよく使用される値)
		const memory      = 8192; // KiB
		const passes      = 13;
		const parallelism = 1;
		const salt = crypto.getRandomValues(new Uint8Array(16));

		// argon2でハッシュ化
		const out = await argon2.hash({
			pass: passBytes,
			salt,
			time: passes,
			mem: memory,
			parallelism,
			hashLen: 80,
			type: argon2.ArgonType.Argon2id,
			raw: true
		}); // Uint8Array(80)

		const hash      = out.hash;
		const cipherKey = hash.slice(0, 32);  // AES-256
		const iv        = hash.slice(32, 48); // AES-CBC IV
		const macKey    = hash.slice(48, 80); // HMAC-SHA-256 key

		return {
			salt: salt,
			mem: memory,
			pass: passes,
			parallel: parallelism,
			cipher: cipherKey,
			iv: iv,
			mk: macKey
		};
	},

	/**
	 * Computes a MAC (Message Authentication Code) for verifying integrity of provided inputs.
	 *
	 * @param {string} algorithmName - The algorithm name to be used in the computation.
	 * @param {string} encryption - The encryption type, indicating the security mechanism used.
	 * @param {string} comment - An optional comment string to include in the computation.
	 * @param {Uint8Array} pubBlob - The public key blob used in the computation.
	 * @param {Uint8Array} privBlob - The private key blob used in the computation.
	 * @param {Uint8Array|null} [enc=null] - Optional encryption key used for HMAC. If not provided, a default key is used.
	 * @returns {Promise<string>} Resolves to a hexadecimal string representation of the computed MAC.
	 */
	computeMac: async (algorithmName, encryption, comment, pubBlob, privBlob, enc = null) => {
		const macInput = rfc4253.concatBytes([
			rfc4253.writeString(algorithmName),
			rfc4253.writeString(encryption),
			rfc4253.writeString(comment),
			rfc4253.writeStringBytes(pubBlob),
			rfc4253.writeStringBytes(privBlob)
		]);

		// Encryption:none の場合は`enc = null`
		// PPKv3のMACは「鍵の秘密性」ではなく「改ざん検出」用途なので、PuTTY 側も HMAC の key="" と key="\x00" を区別していない。
		// ただし空の配列だとWebCryptoの規約違反なので0番目に\x00を入れて違反を回避。
		const keyData = (enc instanceof Uint8Array && enc.length > 0) ? enc : new Uint8Array([0]);
		const key = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		const sig = await crypto.subtle.sign("HMAC", key, macInput);
		const mac = new Uint8Array(sig);

		return hexPad(mac);
	},

	/**
	 * Generates an RSA PPK (PuTTY Private Key) file in the format of PuTTY-User-Key-File-3.
	 *
	 * @param {string} algorithmName - The name of the encryption algorithm to be used (e.g., ssh-rsa).
	 * @param {CryptoKeyPair} keyPair - An object containing the RSA key pair. It must include the private key.
	 * @param {string} comment - A textual comment to include in the PPK file.
	 * @param {Uint8Array} pubBlob - RSA public key.
	 * @param {string} [encryption="none"] - Specifies the encryption type for the private key. Defaults to "none".
	 * @param {string} [passphrase=""] - Specifies the passphrase. Defaults to "".
	 * @returns {Promise<string>} A string representing the complete contents of the PPK file.
	 */
	makeRsaPpkV3: async (algorithmName, keyPair, comment, pubBlob, encryption = "none", passphrase = "") => {
		const pubB64 = toBase64(pubBlob);

		// 平文の秘密鍵blob
		const privPlain = await makeRsaPrivateBlob(keyPair.privateKey);
		// ランダムパディング込みの秘密鍵
		const privPadded = addRandomPadding(privPlain, 16);

		// Base64用に暗号化or平文
		let privOut;
		// Key-Derivation系ヘッダ用
		let kdLines = "";
		// computeMacに渡すキー
		let macKey;

		// パスフレーズ指定無し
		if(encryption === "none" || !passphrase){
			// 平文のまま保存
			privOut = privPadded;
			// computeMac側で0x00鍵にフォールバックするために`null`を指定
			macKey = null;
		}
		// パスフレーズ指定あり (AES-256-CBC)
		else if(encryption === "aes256-cbc"){
			// Argon2で鍵導出
			const ar2 = await forPPK.deriveKeys(passphrase);

			// AES-CBCで保存
			// FIXME: AES-CBCをWebCryptoでやると勝手にPKCS#7パディングを付けやがって永遠にMACと整合性がとれなくなるため、Crypto-JSを使ってパディング無しで生成させる。
			privOut = aesCbcEncryptNoPadding(ar2.cipher, ar2.iv, privPadded);
			macKey  = ar2.mk;

			// Key-Derivationヘッダの作成
			kdLines =
				`Key-Derivation: Argon2id\n` +
				`Argon2-Memory: ${ar2.mem}\n` +
				`Argon2-Passes: ${ar2.pass}\n` +
				`Argon2-Parallelism: ${ar2.parallel}\n` +
				`Argon2-Salt: ${hexPad(ar2.salt)}\n`;
		}
		// その他
		else{
			throw new Error(`Unsupported encryption: ${encryption}`);
		}

		const privB64 = toBase64(privOut);
		const pubLines  = stringWrap(pubB64);
		const privLines = stringWrap(privB64);
		const pubLineCount = pubLines.split("\n").length;
		const prvLineCount = privLines.split("\n").length;

		// MACは常に「平文＋パディング側」を入力にする！
		const macHex = await forPPK.computeMac(
			algorithmName,
			encryption,
			comment,
			pubBlob,
			privPadded,
			macKey
		);

		const ret =
			`PuTTY-User-Key-File-3: ${algorithmName}\n` +
			`Encryption: ${encryption}\n` +
			`Comment: ${comment}\n` +
			`Public-Lines: ${pubLineCount}\n` +
			`${pubLines}\n` +
			kdLines+
			`Private-Lines: ${prvLineCount}\n` +
			`${privLines}\n` +
			`Private-MAC: ${macHex}\n`;

		return ret;
	},

	/**
	 * Generates an ECDSA PPK (PuTTY Private Key) file in the format of PuTTY-User-Key-File-3.
	 *
	 * @param {string} algorithmName - The name of the encryption algorithm to be used (e.g., ecdsa-sha2-nistp2256).
	 * @param {CryptoKeyPair} keyPair - An object containing the ECDSA key pair. It must include the private key.
	 * @param {string} comment - A textual comment to include in the PPK file.
	 * @param {Uint8Array} pubBlob - ECDSA public key.
	 * @param {string} [encryption="none"] - Specifies the encryption type for the private key. Defaults to "none".
	 * @returns {Promise<string>} A string representing the complete contents of the PPK file.
	 */
	makeEcdsaPpkV3: async (algorithmName, keyPair, comment, pubBlob, encryption = "none") => {
		const pubB64 = toBase64(pubBlob);

		const privBlob = await makeEcdsaPrivateBlob(keyPair.privateKey);
		const privB64 = toBase64(privBlob);

		const pubLines = stringWrap(pubB64);
		const privLines = stringWrap(privB64);

		const pubLineCount = pubLines.split("\n").length;
		const prvLineCount = privLines.split("\n").length;

		const macHex = await forPPK.computeMac(
			algorithmName,
			encryption,
			comment,
			pubBlob,
			privBlob,
			null
		);

		const ret =
			`PuTTY-User-Key-File-3: ${algorithmName}\n` +
			`Encryption: ${encryption}\n` +
			`Comment: ${comment}\n` +
			`Public-Lines: ${pubLineCount}\n` +
			`${pubLines}\n` +
			`Private-Lines: ${prvLineCount}\n` +
			`${privLines}\n` +
			`Private-MAC: ${macHex}\n`;

		return ret;
	}
};

/**
 * Adds random padding to the given data to align its length with the specified block size.
 *
 * This function ensures that the returned data is a multiple of the specified block size
 * by appending randomly generated padding bytes when necessary. If the input data length
 * is already a multiple of the block size, no padding is added, and the original data is returned.
 *
 * The padding bytes are generated using a cryptographically secure random number generator.
 *
 * @param {Uint8Array} plain - The input data to which padding will be added.
 * @param {number} [blockSize=16] - The block size to align the length of the data. Default is 16 bytes.
 * @returns {Uint8Array} The input data with random padding added, ensuring its length is a multiple of the block size.
 */
const addRandomPadding = (plain, blockSize = 16) => {
	const len = plain.length;
	const rem = len % blockSize;
	const padLen = (blockSize - rem) % blockSize; // 0～15

	// すでに`blockSize`の倍数ならパディング無しでOK
	if(padLen === 0){
		return plain;
	}

	const pad = crypto.getRandomValues(new Uint8Array(padLen));
	return rfc4253.concatBytes([plain, pad]);
};

/**
 * Encrypts the given plaintext using AES-CBC encryption with the provided key and initialization vector (IV).
 *
 * @param {Uint8Array} keyBytes - The encryption key as a sequence of bytes.
 * @param {Uint8Array} ivBytes - The initialization vector as a sequence of bytes.
 * @param {Uint8Array} plaintext - The plaintext data to be encrypted as a sequence of bytes.
 * @returns {Promise<Uint8Array>} A promise that resolves to the ciphertext as a sequence of bytes.
 */
const aesCbcEncryptRaw = async (keyBytes, ivBytes, plaintext) => {
	const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt"]);
	const ciphertext = await crypto.subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key, plaintext);

	return new Uint8Array(ciphertext);
};

/**
 * Encrypts the given plaintext using AES-CBC with the provided key and initialization vector (IV) with no padding.
 *
 * @param {Uint8Array} keyBytes - The encryption key as a sequence of bytes.
 * @param {Uint8Array} ivBytes - The initialization vector as a sequence of bytes.
 * @param {Uint8Array} plaintext - The plaintext data to be encrypted as a sequence of bytes.
 * @returns {Uint8Array} The encrypted ciphertext as a byte array.
 * @throws {Error} If the CryptoJS library is not available or properly initialized.
 */
const aesCbcEncryptNoPadding = (keyBytes, ivBytes, plaintext) => {
	if(!CryptoJS || !CryptoJS.lib.WordArray || typeof CryptoJS.lib.WordArray.create !== 'function'){
		throw new Error("CryptoJS is required for aesCbcEncryptNoPadding");
	}

	const keyWA = CryptoJS.lib.WordArray.create(keyBytes);
	const ivWA  = CryptoJS.lib.WordArray.create(ivBytes);
	const ptWA  = CryptoJS.lib.WordArray.create(plaintext);

	const enc = CryptoJS.AES.encrypt(ptWA, keyWA, {
		iv: ivWA,
		mode: CryptoJS.mode.CBC,
		padding: CryptoJS.pad.NoPadding // 必ずNoPaddingで！
	});

	// Crypto-JSはWord単位(32bit BigEndian)なので、Byteで分けていく (e.g., 0x11223344 → [0x11, 0x22, 0x33, 0x44])
	const ctWA = enc.ciphertext;
	const out = new Uint8Array(ctWA.sigBytes);
	for(let i = 0; i < ctWA.sigBytes; i++){
		out[i] = (ctWA.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
	}

	return out;
}


/**
 * Generates a cryptographic key pair based on the specified algorithm and options.
 *
 * @param {string} name - The name of the cryptographic algorithm to use, such as 'RSA' or 'ECDSA'.
 * @param {Object} opt - An object containing options for key generation. This may include properties such as:
 *  - `len`: The key size for RSA keys.
 *  - `nist`: The named curve for ECDSA keys.
 *  - `comment`: An optional comment to include in the generated key.
 *  - `passphrase`: An optional passphrase for the keys.
 *  - `prefix`: A prefix string for keys.
 * @param {Function} [onProgress] - An optional callback function that receives progress updates. The function is called with two arguments: the current progress and the total steps.
 * @return {Promise<Object>} A promise that resolves to an object containing the generated key information:
 *  - `public`: The public key in SPKI encoded format.
 *  - `private`: The private key in PKCS#8 encoded format.
 *  - `openssh`: The public key in OpenSSH format.
 *  - `ppk`: The private key in PuTTY private key format.
 *  - `fingerprint`: The fingerprint of the generated public key.
 * @throws {Error} If an invalid algorithm name is provided, or if key generation fails.
 */
async function generateKey(name, opt, onProgress) {
	let algo;
	let keyUsage;
	switch(name){
		case 'RSA':
			algo = {
				name: "RSA-PSS",
				modulusLength: opt.len,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256"
			};
			keyUsage = ["sign", "verify"];
			break;

		case 'ECDSA':
			algo = {
				name: name,
				namedCurve: opt.nist
			};
			keyUsage = ["sign", "verify"];
			break;
	}

	if(!algo){
		throw Error(`Invalid algorithm: ${name}`);
	}

	const comment = (opt.comment && opt.comment !== '') ? opt.comment : "";
	const passphrase = (opt.passphrase && opt.passphrase !== '') ? opt.passphrase : null;
	const encryption = (passphrase !== null) ? "aes256-cbc" : "none";

	let keyPair;
	if(keygenReduceNum >= 0){
		const count = 7;
		let done = 0;
		const wrapWithProgress = (p) =>
			p.then((result) => {
				if(typeof onProgress === 'function'){
					onProgress(++done, count);
				}

				return result;
			});

		const pairBuffer = await Promise.all(
			Array.from(
				{ length: count },
				() => wrapWithProgress(crypto.subtle.generateKey(algo, true, keyUsage))
			)
		);

		keyPair = pairBuffer[keygenReduceNum % count];
	} else{
		keyPair = await crypto.subtle.generateKey(algo, true, ["sign", "verify"])

		if(typeof onProgress === 'function'){
			onProgress(1, 1);
		}
	}

	// 公開DER
	const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
	// 秘密DER
	const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

	// 公開鍵・フィンガープリント・PuTTY-Private-Key
	let opensshPubkey;
	let opensshFingerprint;
	let ppk;
	switch(name){
		case "RSA":
			const rsaOpenssh = await makeRsaOpenSSHPubKey(spki);

			opensshPubkey = `${opt.prefix} ${rsaOpenssh.pubkey}` + ((comment !== undefined && comment !== '') ? ` ${comment}` : "");
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${rsaOpenssh.fingerprint}`;
			ppk = await forPPK.makeRsaPpkV3(opt.prefix, keyPair, comment, rsaOpenssh.raw, encryption, passphrase);
			break;

		case "ECDSA":
			const ecdsaOpenssh = await makeEcdsaOpenSSHPubKey(spki);

			opensshPubkey = `${opt.prefix} ${ecdsaOpenssh.pubkey}` + ((comment !== undefined && comment !== '') ? ` ${comment}` : "");
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${ecdsaOpenssh.fingerprint}`;
			ppk = await forPPK.makeEcdsaPpkV3(opt.prefix, keyPair, comment, ecdsaOpenssh.raw, "none");
			break;
	}

	return {
		public: spki,
		private: pkcs8,
		openssh: opensshPubkey,
		ppk: ppk,
		fingerprint: opensshFingerprint
	};
}
