const PUBKEY_LABEL = "PUBLIC KEY";
const PRIVKEY_LABEL = "PRIVATE KEY";

let keygenReduceNum = -1;

/**
 * Parses an SPKI (Subject Public Key Info) buffer specifically for RSA public keys, extracting the modulus and exponent.
 *
 * @param {ArrayBuffer|Uint8Array} spkiBuf - The SPKI data buffer (in DER format) from which the RSA public key will be extracted. Can be provided as an `ArrayBuffer` or `Uint8Array`.
 * @return {Object} An object containing the RSA public key components:
 * - `n` {Uint8Array}: The modulus of the RSA key.
 * - `e` {Uint8Array}: The public exponent of the RSA key.
 * @throws {Error} If the SPKI data is malformed or does not match the expected format.
 */
function parseRsaSpki(spkiBuf) {
	const bytes = (spkiBuf instanceof Uint8Array) ? spkiBuf : new Uint8Array(spkiBuf);
	let offset = 0;

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
	const readLen = () => {
		let len = bytes[offset++];
		if(len & 0x80){
			const nBytes = len & 0x7F;

			len = 0;
			for(let i = 0; i < nBytes; i++){
				len = (len << 8) | bytes[offset++];
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
	const expect = (tag) => {
		if(bytes[offset++] !== tag){
			throw new Error(`Unexpected ASN.1 tag, expected 0x${tag.toString(16).padStart(2, '0')}`);
		}
	};

	// SubjectPublicKeyInfo
	expect(0x30);           // SEQUENCE
	readLen();              // 全体長

	// AlgorithmIdentifier
	expect(0x30);           // SEQUENCE
	const algLen = readLen();
	offset += algLen;       // ざっくりスキップ（rsaEncryption前提）

	// subjectPublicKey BIT STRING
	expect(0x03);
	const bitLen = readLen();
	offset++;               // unused bits = 0

	// RSAPublicKey (SEQUENCE)
	expect(0x30);
	readLen();

	// modulus (INTEGER)
	expect(0x02);
	let nLen = readLen();
	let nStart = offset;
	offset += nLen;

	// exponent (INTEGER)
	expect(0x02);
	let eLen = readLen();
	let eStart = offset;
	offset += eLen;

	// 先頭 0x00 は符号ビット用の場合があるので取り除く
	while(nLen > 0 && bytes[nStart] === 0x00){
		nStart++;
		nLen--;
	}
	while(eLen > 0 && bytes[eStart] === 0x00){
		eStart++;
		eLen--;
	}

	// 元のバイト列からmodulus, exponentを切り出す
	const n = bytes.slice(nStart, nStart + nLen);
	const e = bytes.slice(eStart, eStart + eLen);

	return { n, e };
}

/**
 * A set of utility functions for handling data formats and operations
 * specified in RFC 4253, focusing on SSH Binary Packet Protocol.
 */
const rfc4253 = {
	/**
	 * Encodes a given string into a Uint8Array format with a prepended 4-byte unsigned integer
	 * representing the length of the string in bytes.
	 *
	 * @param {string} str - The string to be encoded.
	 * @returns {Uint8Array} A byte array containing the string length as a 4-byte unsigned integer
	 * followed by the UTF-8 encoded representation of the string.
	 */
	writeString: (str) => {
		const enc = new TextEncoder();
		const s = enc.encode(str);
		const out = new Uint8Array(4 + s.length);
		const view = new DataView(out.buffer);
		view.setUint32(0, s.length);
		out.set(s, 4);

		return out;
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
		const out = new Uint8Array(4 + b.length);
		const view = new DataView(out.buffer);
		view.setUint32(0, b.length);
		out.set(b, 4);

		return out;
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
 * Generates an OpenSSH public key and its fingerprint based on a given RSA SPKI buffer.
 *
 * @param {ArrayBuffer} spkiBuf - The SPKI buffer containing the RSA public key.
 * @return {Promise<{pubkey: string, fingerprint: string}>} A promise resolving to an object containing the OpenSSH public key as `pubkey` and its SHA-256 fingerprint as `fingerprint`.
 */
async function makeOpenSSHPubKey(spkiBuf) {
	const { n, e } = parseRsaSpki(spkiBuf);
	const blob = rfc4253.concatBytes([
		rfc4253.writeString("ssh-rsa"),
		rfc4253.writeMpint(e),
		rfc4253.writeMpint(n)
	]);

	const pubkey = toBase64(blob);
	const digest = await crypto.subtle.digest("SHA-256", blob);
	const fingerprint = toBase64(digest)
		// OpenSSH風に末尾の=を削る
		.replace(/=+$/, "");

	return {
		pubkey: pubkey,
		fingerprint: fingerprint
	};
}

/**
 * Converts an ArrayBuffer or TypedArray to a Base64-encoded string.
 *
 * @param {ArrayBuffer|TypedArray} buffer - The buffer or typed array that is to be converted to a Base64 string.
 * @returns {string} The Base64-encoded string representation of the input buffer.
 */
const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

/**
 * Converts a given buffer into a PEM formatted string.
 *
 * @param {Buffer} buffer - The input buffer to be converted.
 * @param {string} label - The label to prepend and append to the PEM formatted string.
 * @returns {string} A PEM formatted string containing the base64 representation of the buffer, wrapped by the specified label.
 */
const toPEM = (buffer, label) => {
	const base64 = toBase64(buffer).replace(/(.{64})/g, "$1\n");

	return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}

/**
 * Generates a cryptographic key pair based on the specified algorithm and options.
 *
 * @param {string} name - The name of the algorithm to use for key generation (e.g., "RSA", "ECDSA").
 * @param {Object} opt - Options specific to the algorithm being used. For "RSA", this includes `len` (modulus length). For "ECDSA", this includes `nist` (named curve).
 * @param {function(number, number):void} [onProgress] - Optional callback function to track generation progress. It is called with the current progress step and the total steps.
 * @return {Promise<Object>} A promise that resolves to an object containing the keys and related data:
 * - `public` (ArrayBuffer): The public key in SPKI format.
 * - `private` (ArrayBuffer): The private key in PKCS8 format.
 * - `openssh` (string|undefined): The OpenSSH public key (only for RSA).
 * - `fingerprint` (string|undefined): The fingerprint of the OpenSSH public key (only for RSA).
 * @throws {Error} If an invalid algorithm name is provided or key generation fails.
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

	// OpenSSH公開鍵・フィンガープリント
	let opensshPubkey = undefined;
	let opensshFingerprint = undefined;
	if(name === 'RSA'){
		const openssh = await makeOpenSSHPubKey(spki);
		const comment = opt.comment ? ` ${opt.comment}` : "";

		opensshPubkey = `ssh-rsa ${openssh.pubkey}${comment}`;
		opensshFingerprint = `ssh-rsa ${opt.len} SHA256:${openssh.fingerprint}`;
	}

	return {
		public: spki,
		private: pkcs8,
		openssh: opensshPubkey,
		fingerprint: opensshFingerprint
	};
}
