export class PPKv3 {
	/**
	 * Generates an RSA PPK (PuTTY Private Key) file in the format of PuTTY-User-Key-File-3.
	 *
	 * @async
	 * @static
	 * @param {string} algorithmName - The name of the encryption algorithm to be used (e.g., ssh-rsa).
	 * @param {CryptoKeyPair} keyPair - An object containing the RSA key pair. It must include the private key.
	 * @param {string} comment - A textual comment to include in the PPK file.
	 * @param {Uint8Array} pubBlob - RSA public key.
	 * @param {string} [encryption="none"] - Specifies the encryption type for the private key. Defaults to "none".
	 * @param {string} [passphrase=""] - Specifies the passphrase. Defaults to "".
	 * @returns {Promise<string>} A string representing the complete contents of the PPK file.
	 */
	static async makeRsaPpkV3(algorithmName, keyPair, comment, pubBlob, encryption = "none", passphrase = "") {
		const pubB64 = App.Bytes.toBase64(pubBlob);

		const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

		// PPKv3のRSAでは d, p, q, qinv
		const d  = App.Bytes.fromBase64(jwk.d);
		const p  = App.Bytes.fromBase64(jwk.p);
		const q  = App.Bytes.fromBase64(jwk.q);
		const qi = App.Bytes.fromBase64(jwk.qi); // qinv (q⁻¹ mod p)

		// 平文の秘密鍵blob
		const privPlain = App.Bytes.concat(
			rfc4253.writeMpint(d),
			rfc4253.writeMpint(p),
			rfc4253.writeMpint(q),
			rfc4253.writeMpint(qi),
		);

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
		return [
			`PuTTY-User-Key-File-3: ${algorithmName}`,
			`Encryption: ${encryption}`,
			`Comment: ${comment}`,
			`Public-Lines: ${pubLineCount}`,
			`${pubLines}`,
			kdLines,
			`Private-Lines: ${prvLineCount}`,
			`${privLines}`,
			`Private-MAC: ${macHex}`
		].join("\n");
	}

	/**
	 * Generates an ECDSA PPK (PuTTY Private Key) file in the format of PuTTY-User-Key-File-3.
	 *
	 * @async
	 * @static
	 * @param {string} algorithmName - The name of the encryption algorithm to be used (e.g., ecdsa-sha2-nistp2256).
	 * @param {CryptoKeyPair} keyPair - An object containing the ECDSA key pair. It must include the private key.
	 * @param {string} comment - A textual comment to include in the PPK file.
	 * @param {Uint8Array} pubBlob - ECDSA public key.
	 * @param {string} [encryption="none"] - Specifies the encryption type for the private key. Defaults to "none".
	 * @param {string} [passphrase=""] - Specifies the passphrase. Defaults to "".
	 * @returns {Promise<string>} A string representing the complete contents of the PPK file.
	 */
	static async makeEcdsaPpkV3(algorithmName, keyPair, comment, pubBlob, encryption = "none", passphrase = "") {
		const pubB64 = App.Bytes.toBase64(pubBlob);

		// 平文の秘密鍵blob
		const priv = await makeEcdsaPrivateBlob(keyPair.privateKey);
		const privPlain = priv.d;
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
		return [
			`PuTTY-User-Key-File-3: ${algorithmName}`,
			`Encryption: ${encryption}`,
			`Comment: ${comment}`,
			`Public-Lines: ${pubLineCount}`,
			`${pubLines}`,
			kdLines,
			`Private-Lines: ${prvLineCount}`,
			`${privLines}`,
			`Private-MAC: ${macHex}`
		].join("\n");
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
		const kdLines = [
			`Key-Derivation: Argon2id`,
			`Argon2-Memory: ${ar2.mem}`,
			`Argon2-Passes: ${ar2.pass}`,
			`Argon2-Parallelism: ${ar2.parallel}`,
			`Argon2-Salt: ${Helper.hexPad(ar2.salt)}`
		].join("\n");

		return { privOut, macKey, kdLines };
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
