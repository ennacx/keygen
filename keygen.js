/**
 * Helper variable serves as the reference to the `App.Helper` module or object,
 * providing access to various utility functions, constants, and methods that
 * support the application in performing helper operations.
 *
 * This variable is initialized from the `App.Helper` and is globally available
 * where the `Helper` is imported or defined.
 *
 * It is commonly used to group auxiliary or shared functionalities that
 * assist in the main business logic of the application, enhancing code
 * readability and maintainability.
 */
const Helper = App.Helper;

/**
 * Represents an implementation or reference to the RFC 4253 specification,
 * which defines the SSH Transport Layer Protocol.
 *
 * The RFC 4253 outlines the structure and behavior of the transport layer in the SSH protocol,
 * including algorithms for key exchange, server authentication, encryption, and message integrity.
 *
 * This variable may encapsulate methods, constants, or configurations that adhere to the
 * rules and mechanisms specified in RFC 4253.
 */
const rfc4253 = App.RFC4253;

let keygenReduceNum = -1;

/**
 * Encrypts the given plaintext using AES-CBC encryption
 * with the provided key and initialization vector (IV) within PKCS#7 padding.
 *
 * @async
 * @param {Uint8Array} keyBytes - The encryption key as a sequence of bytes.
 * @param {Uint8Array} ivBytes - The initialization vector as a sequence of bytes.
 * @param {Uint8Array} plaintext - The plaintext data to be encrypted as a sequence of bytes.
 * @returns {Promise<Uint8Array>} A promise that resolves to the ciphertext as a sequence of bytes.
 */
const aesCbcEncryptRaw = async (keyBytes, ivBytes, plaintext) => {
	const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
	const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, key, plaintext);

	return new Uint8Array(ciphertext);
};

/**
 * Encrypts the given plaintext using AES-CBC
 * with the provided key and initialization vector (IV) without padding.
 *
 * @param {Uint8Array} keyBytes - The encryption key as a sequence of bytes.
 * @param {Uint8Array} ivBytes - The initialization vector as a sequence of bytes.
 * @param {Uint8Array} plaintext - The plaintext data to be encrypted as a sequence of bytes.
 * @returns {Uint8Array} The encrypted ciphertext as a byte array.
 * @throws {Error} If the CryptoJS library is not available or properly initialized.
 */
const aesCbcEncryptRawNoPadding = (keyBytes, ivBytes, plaintext) => {
	if(!CdnApp.CryptoJS || !CdnApp.CryptoJS.lib.WordArray || typeof CdnApp.CryptoJS.lib.WordArray.create !== 'function'){
		throw new Error('CryptoJS is required for aesCbcEncryptNoPadding');
	}

	const keyWA = CdnApp.CryptoJS.lib.WordArray.create(keyBytes);
	const ivWA  = CdnApp.CryptoJS.lib.WordArray.create(ivBytes);
	const ptWA  = CdnApp.CryptoJS.lib.WordArray.create(plaintext);

	const enc = CdnApp.CryptoJS.AES.encrypt(ptWA, keyWA, {
		iv: ivWA,
		mode: CdnApp.CryptoJS.mode.CBC,
		padding: CdnApp.CryptoJS.pad.NoPadding // 必ずNoPaddingで！
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
 * Generates a cryptographic key and associated metadata based on the provided parameters.
 *
 * This function supports generating RSA and ECDSA keys. Additionally, it creates necessary
 * representations of the key, including OpenSSH formatted public keys, fingerprints, and PuTTY
 * private key (PPK) files.
 *
 * @async
 * @function generateKey
 * @param {string} name - The type of key to generate ("RSA" or "ECDSA").
 * @param {Object} opt - An options object containing key generation settings.
 * @param {number} opt.len - The key length for RSA keys or an equivalent parameter for other key types.
 * @param {string} opt.nist - The elliptic curve name for ECDSA keys.
 * @param {string} [opt.comment] - An optional comment to associate with the generated key.
 * @param {string} [opt.passphrase] - A passphrase used to encrypt the private key.
 * @param {string} [opt.prefix] - The prefix indicating the public key type (e.g., "ssh-rsa").
 * @param {function} [onProgress] - An optional callback function invoked to report the progress of key generation.
 *                                    The function is called with two arguments: the number of completed tasks
 *                                    and the total number of tasks.
 * @return {Promise<Object>}
 * A promise that resolves to an object containing the generated key material and related information:
 *  - `material` (KeyMaterial): The generated key material.
 *  - `openssh` (string): The OpenSSH formatted public key string.
 *  - `ppk` (Object): The PuTTY private key (PPK) object.
 *  - `fingerprint` (string): The fingerprint of the generated key.
 */
async function generateKey(name, opt, onProgress) {
	const comment    = (opt.comment && opt.comment !== '') ? opt.comment : '';
	const passphrase = (opt.passphrase && opt.passphrase !== '') ? opt.passphrase : null;
	const encryption = (passphrase !== null) ? 'aes256-cbc' : 'none';

	/**
	 * Represents an asynchronous callback function that retrieves an instance of KeyMaterial.
	 *
	 * This function uses the `KeyMaterial.getInstance` method to obtain a key material instance.
	 * The instance is created using the provided `name` and options `opt` that specify the desired
	 * length `opt.len` and elliptic curve `opt.nist`.
	 *
	 * @async
	 * @function
	 * @returns {Promise<KeyMaterial>} A promise that resolves to an instance of KeyMaterial.
	 */
	const kmCallback = async () => KeyMaterial.getInstance(name, { len: opt.len, curve: opt.nist });

	/**
	 * Represents the cryptographic material or data used as a key in encryption or decryption processes.
	 * This variable typically holds the key data in raw, binary, or encoded format,
	 * which is utilized for cryptographic operations like symmetric or asymmetric encryption.
	 */
	let keyMaterial;

	if(keygenReduceNum >= 0){
		const count = 7;
		let done = 0;

		/**
		 * A function that wraps a given Promise to track its resolution progress.
		 * Updates the progress by invoking a specified `onProgress` callback function,
		 * if defined, whenever the wrapped Promise resolves.
		 *
		 * @param {Promise} p - The Promise to be wrapped and tracked for progress.
		 * @returns {Promise} A new Promise that resolves with the result of the input Promise.
		 *                    The progress is updated when the Promise resolves.
		 */
		const wrapWithProgress = (p) =>
			p.then((result) => {
				if(typeof onProgress === 'function'){
					onProgress(++done, count);
				}

				return result;
			});

		const kmBuffer = await Promise.all(
			Array.from(
				{ length: count },
				() => wrapWithProgress(kmCallback())
			)
		);

		keyMaterial = kmBuffer[keygenReduceNum % count];
	} else{
		keyMaterial = await kmCallback();

		if(typeof onProgress === 'function'){
			onProgress(1, 1);
		}
	}

	const pubkey = new App.PubKey(keyMaterial.spki);

	/**
	 * Constructs an OpenSSH formatted public key string.
	 *
	 * @function
	 * @param {Object} opt - Options object containing the prefix for the key type.
	 * @param {string} opt.prefix - The prefix indicating the public key type, e.g., "ssh-rsa".
	 * @param {string} pubkey - The base64-encoded public key string.
	 * @param {string} [comment] - An optional comment to include in the key string.
	 * @returns {string} The formatted OpenSSH public key string.
	 */
	const makeOpenSshPubKey = (opt, pubkey, comment) =>
		`${opt.prefix} ${pubkey}` + ((comment !== undefined && comment !== '') ? ` ${comment}` : '');

	// 公開鍵・フィンガープリント・PuTTY-Private-Key
	let pubBlob;
	let opensshPubkey;
	let opensshFingerprint;
	let privatePlain;

	switch(name){
		case 'RSA':
			const rsaOpenssh = await pubkey.rsa();

			pubBlob = rsaOpenssh.raw;
			opensshPubkey      = makeOpenSshPubKey(opt, rsaOpenssh.pubkey, comment);
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${rsaOpenssh.fingerprint}`;
			privatePlain       = keyMaterial.rsaPrivatePartPPKv3();

			break;

		case 'ECDSA':
			const ecdsaOpenssh = await pubkey.ecdsa();

			pubBlob = ecdsaOpenssh.raw;
			opensshPubkey      = makeOpenSshPubKey(opt, ecdsaOpenssh.pubkey, comment);
			opensshFingerprint = `${opt.prefix} ${opt.len} SHA256:${ecdsaOpenssh.fingerprint}`;
			privatePlain       = keyMaterial.ecdsaPrivatePart();

			break;
	}

	// PPKの生成
	const ppk = await App.PPKv3.generate(opt.prefix, privatePlain, comment, pubBlob, encryption, passphrase);

	return {
		material: keyMaterial,
		openssh: opensshPubkey,
		ppk: ppk,
		fingerprint: opensshFingerprint
	};
}
