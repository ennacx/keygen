export class KeyMaterial {

	keyPair;
	spki;
	pkcs8;
	jwk;

	JWK_NO_INIT_ERR_MSG = "JSON Web Key (JWK) not found. Call getInstance() first to generate a key pair and export the JWK.";

	constructor() {
		// NOP
	}

	static async getInstance(name, { len, curve }) {
		const myself = new this();

		let algo = {};
		switch(name){
			case "RSA":
				algo = {
					name: "RSA-PSS",
					modulusLength: len,
					publicExponent: new Uint8Array([1, 0, 1]),
					hash: "SHA-256"
				};
				break;
			case "ECDSA":
				algo = {
					name: name,
					namedCurve: curve
				};
				break;
			default:
				throw new Error(`Unsupported algorithm: ${name}`);
		}

		myself.keyPair = await crypto.subtle.generateKey(algo, true, ["sign", "verify"]);

		if(!myself.keyPair.publicKey || !myself.keyPair.privateKey){
			throw new Error("Failed to generate key pair");
		}

		myself.spki  = await crypto.subtle.exportKey("spki", myself.keyPair.publicKey);
		myself.pkcs8 = await crypto.subtle.exportKey("pkcs8", myself.keyPair.privateKey);
		myself.jwk   = await crypto.subtle.exportKey("jwk", myself.keyPair.privateKey);

		return myself;
	}

	rsaPrivatePart() {
		if(!this.jwk){
			throw new Error(this.JWK_NO_INIT_ERR_MSG);
		}

		const n  = App.Bytes.fromBase64(this.jwk.n);
		const e  = App.Bytes.fromBase64(this.jwk.e);
		const d  = App.Bytes.fromBase64(this.jwk.d);
		const qi = App.Bytes.fromBase64(this.jwk.qi); // qinv (q⁻¹ mod p)
		const p  = App.Bytes.fromBase64(this.jwk.p);
		const q  = App.Bytes.fromBase64(this.jwk.q);

		// FIXME: openssh-key-v1の平文での秘密鍵情報では n, e, d, qi, p, q の順序が必須
		return App.Bytes.concat(
			App.RFC4253.writeMpint(n),
			App.RFC4253.writeMpint(e),
			App.RFC4253.writeMpint(d),
			App.RFC4253.writeMpint(qi),
			App.RFC4253.writeMpint(p),
			App.RFC4253.writeMpint(q)
		);
	}

	rsaPrivatePartPPKv3() {
		if(!this.jwk){
			throw new Error(this.JWK_NO_INIT_ERR_MSG);
		}

		const d  = App.Bytes.fromBase64(this.jwk.d);
		const p  = App.Bytes.fromBase64(this.jwk.p);
		const q  = App.Bytes.fromBase64(this.jwk.q);
		const qi = App.Bytes.fromBase64(this.jwk.qi); // qinv (q⁻¹ mod p)

		// FIXME: PPKv3のRSAでは d, p, q, qinv の順序が必須
		return App.Bytes.concat(
			App.RFC4253.writeMpint(d),
			App.RFC4253.writeMpint(p),
			App.RFC4253.writeMpint(q),
			App.RFC4253.writeMpint(qi),
		);
	}

	ecdsaPrivatePart() {
		if(!this.jwk){
			throw new Error(this.JWK_NO_INIT_ERR_MSG);
		}

		// ECDSAでの平文の秘密鍵情報は d だけ
		return App.Bytes.fromBase64(this.jwk.d);
	}

	ecdsaQPoint() {
		if(!this.jwk){
			throw new Error(this.JWK_NO_INIT_ERR_MSG);
		}

		// Q点 (0x04 || xBytes || yBytes)
		// Q.length = P-256: 65bytes(1+32+32), P-384: 97bytes, P-521: 133bytes
		return App.Bytes.concat(
			Uint8Array.from([0x04]),
			App.Bytes.fromBase64(this.jwk.x),
			App.Bytes.fromBase64(this.jwk.y)
		);
	}
}