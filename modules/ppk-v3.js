/**
 * Represents the PPKv3 class, which provides functionality to generate RSA and ECDSA
 * PuTTY private key (PPK) files in the PuTTY-User-Key-File-3 format, with optional encryption
 * and passphrase-based key derivation.
 */
export class PPKv3 {
	/**
	 * Generates an RSA PPK (PuTTY Private Key) file in the format of PuTTY-User-Key-File-3.
	 *
	 * @async
	 * @static
	 * @param {string} algorithmName - The name of the encryption algorithm to be used (e.g., ssh-rsa).
	 * @param {KeyMaterial} keyMaterial - An object containing the RSA key pair. It must include the private key.
	 * @param {string} comment - A textual comment to include in the PPK file.
	 * @param {Uint8Array} pubBlob - RSA public key.
	 * @param {string} [encryption="none"] - Specifies the encryption type for the private key. Defaults to "none".
	 * @param {string} [passphrase=""] - Specifies the passphrase. Defaults to "".
	 * @returns {Promise<string>} A string representing the complete contents of the PPK file.
	 */
	static async makeRsaPpkV3(algorithmName, keyMaterial, comment, pubBlob, encryption = "none", passphrase = "") {
		const pubB64 = App.Bytes.toBase64(pubBlob);

		// 平文の秘密鍵blob
		const privPlain = keyMaterial.rsaPrivatePartPPKv3();

		// ランダムパディング込みの秘密鍵
		const privPadded = this.#addRandomPadding(privPlain, 16);

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
			const d = await this.#argon2KeyDerivation(passphrase, privPadded);
			privOut = d.privOut;
			macKey = d.macKey;
			kdLines = d.kdLines;
		}
		// その他
		else{
			throw new Error(`Unsupported encryption: ${encryption}`);
		}

		const privB64      = App.Bytes.toBase64(privOut);
		const pubLines     = App.Helper.stringWrap(pubB64);
		const privLines    = App.Helper.stringWrap(privB64);
		const pubLineCount = App.Helper.lineCount(pubLines);
		const prvLineCount = App.Helper.lineCount(privLines);

		// MACは常に「平文＋パディング側」を入力にする！
		const macHex = await this.#computeMac(
			algorithmName,
			encryption,
			comment,
			pubBlob,
			privPadded,
			macKey
		);

		// FIXME: 順番重要
		return App.Helper.implode([
			`PuTTY-User-Key-File-3: ${algorithmName}`,
			`Encryption: ${encryption}`,
			`Comment: ${comment}`,
			`Public-Lines: ${pubLineCount}`,
			`${pubLines}`,
			kdLines,
			`Private-Lines: ${prvLineCount}`,
			`${privLines}`,
			`Private-MAC: ${macHex}`
		]);
	}

	/**
	 * Generates an ECDSA PPK (PuTTY Private Key) file in the format of PuTTY-User-Key-File-3.
	 *
	 * @async
	 * @static
	 * @param {string} algorithmName - The name of the encryption algorithm to be used (e.g., ecdsa-sha2-nistp2256).
	 * @param {KeyMaterial} keyMaterial - An object containing the ECDSA key pair. It must include the private key.
	 * @param {string} comment - A textual comment to include in the PPK file.
	 * @param {Uint8Array} pubBlob - ECDSA public key.
	 * @param {string} [encryption="none"] - Specifies the encryption type for the private key. Defaults to "none".
	 * @param {string} [passphrase=""] - Specifies the passphrase. Defaults to "".
	 * @returns {Promise<string>} A string representing the complete contents of the PPK file.
	 */
	static async makeEcdsaPpkV3(algorithmName, keyMaterial, comment, pubBlob, encryption = "none", passphrase = "") {
		const pubB64 = App.Bytes.toBase64(pubBlob);

		// 平文の秘密鍵blob
		const privPlain = keyMaterial.ecdsaPrivatePart();
		// ランダムパディング込みの秘密鍵
		const privPadded = this.#addRandomPadding(privPlain, 16);

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
			const d = await this.#argon2KeyDerivation(passphrase, privPadded);

			privOut = d.privOut
			macKey  = d.macKey;
			kdLines = d.kdLines;
		}
		// その他
		else{
			throw new Error(`Unsupported encryption: ${encryption}`);
		}

		const privB64      = App.Bytes.toBase64(privOut);
		const pubLines     = Helper.stringWrap(pubB64);
		const privLines    = Helper.stringWrap(privB64);
		const pubLineCount = Helper.lineCount(pubLines);
		const prvLineCount = Helper.lineCount(privLines);

		// MACは常に「平文＋パディング側」を入力にする！
		const macHex = await this.#computeMac(
			algorithmName,
			encryption,
			comment,
			pubBlob,
			privPadded,
			macKey
		);

		// FIXME: 順番重要
		return App.Helper.implode([
			`PuTTY-User-Key-File-3: ${algorithmName}`,
			`Encryption: ${encryption}`,
			`Comment: ${comment}`,
			`Public-Lines: ${pubLineCount}`,
			`${pubLines}`,
			kdLines,
			`Private-Lines: ${prvLineCount}`,
			`${privLines}`,
			`Private-MAC: ${macHex}`
		]);
	}

	/**
	 * Derives cryptographic keys from a given passphrase using the Argon2id key derivation function.
	 *
	 * @async
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
	static async #deriveKeys(passphrase) {
		if(!argon2 || typeof argon2.hash !== 'function'){
			throw new Error("argon2-browser is required for deriveKeys");
		}

		const passBytes = Helper.toUtf8(passphrase);

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
	}

	/**
	 * Performs key derivation using the Argon2id algorithm and encrypts the provided private key using AES-CBC without PKCS#7 padding.
	 *
	 * @async
	 * @param {string} passphrase - The passphrase used for deriving the encryption keys.
	 * @param {Uint8Array} paddedPrivkey - The padded private key to be encrypted after key derivation.
	 * @returns {Promise<Object>} Returns a promise that resolves to an object containing the encrypted private key (`privOut`),
	 *                            the MAC key (`macKey`), and the generated key derivation metadata (`kdLines`).
	 *
	 * @throws {Error} Throws an error if the key derivation or encryption process fails.
	 *
	 * @description
	 * This function derives a set of encryption keys and MAC keys from the provided passphrase using Argon2id. The provided padded
	 * private key is then encrypted using AES-CBC with the derived cipher key and initialization vector. Due to padding conflicts
	 * introduced by WebCrypto, this function uses a custom implementation of AES-CBC encryption without padding. Metadata
	 * describing the Argon2id configuration is also generated and returned.
	 */
	static async #argon2KeyDerivation(passphrase, paddedPrivkey) {
		// Argon2で鍵導出
		const ar2 = await this.#deriveKeys(passphrase);

		// AES-CBCで保存
		// FIXME: AES-CBCをWebCryptoでやると勝手にPKCS#7パディングを付けやがって永遠にMACと整合性がとれなくなるため、Crypto-JSを使ってパディング無しで生成させる。
		// 使わない: const privOut = aesCbcEncryptRaw(ar2.cipher, ar2.iv, paddedPrivkey);
		const privOut = aesCbcEncryptRawNoPadding(ar2.cipher, ar2.iv, paddedPrivkey);
		const macKey  = ar2.mk;

		// Key-Derivationヘッダの作成
		const kdLines = App.Helper.implode([
			`Key-Derivation: Argon2id`,
			`Argon2-Memory: ${ar2.mem}`,
			`Argon2-Passes: ${ar2.pass}`,
			`Argon2-Parallelism: ${ar2.parallel}`,
			`Argon2-Salt: ${Helper.hexPad(ar2.salt)}`
		]);

		return { privOut, macKey, kdLines };
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
	static #addRandomPadding(plain, blockSize = 16) {
		const len = plain.length;
		const rem = len % blockSize;
		const padLen = (blockSize - rem) % blockSize; // 0～15

		// すでに`blockSize`の倍数ならパディング無しでOK
		if(padLen === 0){
			return plain;
		}

		const pad = crypto.getRandomValues(new Uint8Array(padLen));
		return App.Bytes.concat(plain, pad);
	};

	/**
	 * Computes a MAC (Message Authentication Code) for verifying integrity of provided inputs.
	 *
	 * @async
	 * @param {string} algorithmName - The algorithm name to be used in the computation.
	 * @param {string} encryption - The encryption type, indicating the security mechanism used.
	 * @param {string} comment - An optional comment string to include in the computation.
	 * @param {Uint8Array} pubBlob - The public key blob used in the computation.
	 * @param {Uint8Array} privBlob - The private key blob used in the computation.
	 * @param {Uint8Array|null} [enc=null] - Optional encryption key used for HMAC. If not provided, a default key is used.
	 * @returns {Promise<string>} Resolves to a hexadecimal string representation of the computed MAC.
	 */
	static async #computeMac(algorithmName, encryption, comment, pubBlob, privBlob, enc = null) {
		const macInput = App.Bytes.concat(
			rfc4253.writeString(algorithmName),
			rfc4253.writeString(encryption),
			rfc4253.writeString(comment),
			rfc4253.writeStringBytes(pubBlob),
			rfc4253.writeStringBytes(privBlob)
		);

		// Encryption:none の場合は`enc = null`
		/*
		 * FIXME:
		 *  PPKv3のMACは「鍵の秘密性」ではなく「改ざん検出」用途なので、PuTTY側もHMACのkey=""とkey="\x00"を区別していない。
		 *  ただし空の配列だとWebCryptoの規約違反なので0番目に\x00を入れて違反を回避。
		 */
		const keyData = (enc instanceof Uint8Array && enc.length > 0) ? enc : new Uint8Array([0]);
		const key = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		const sig = await crypto.subtle.sign("HMAC", key, macInput);
		const mac = new Uint8Array(sig);

		return Helper.hexPad(mac);
	}
}
