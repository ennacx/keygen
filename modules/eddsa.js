// CDN
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
// Local
import { OID, EdDSA_PRESET } from "./const.js";
import { Bytes } from "./bytes.js";
import { RFC4253 } from "./rfc4253.js";
import { DerHelper } from "./der-helper.js";

export class EdDSA {
	#curveName;

	constructor(curveName) {
		if(!EdDSA_PRESET[curveName]){
			throw new Error(`Invalid preset key: ${curveName}`);
		}

		this.#curveName = curveName;
	}
	generate() {
		const preset = EdDSA_PRESET[this.#curveName];
		const seed = this.#getSeed(preset.seedLen);

		let pub;
		switch(this.#curveName){
			case 'Ed25519':
				pub = ed25519.getPublicKey(seed);
				break;
			case 'Ed448':
				pub = ed448.getPublicKey(seed);
				break;
		}

		const keyType = `ssh-${preset.name}`;

		const spki  = this.#toSpkiDer({ crv: this.#curveName, pub });
		const pkcs8 = this.#toPkcs8Der({ crv: this.#curveName, seed, pub, includePublic: true });
		const jwk   = this.#toJwk({ crv: this.#curveName, pub, seed });

		return {
			keyType,
			seed,
			pub,
			len: preset.len,
			publicBlob: this.#makeEdPublicBlob(keyType, pub),
			privateFields: this.#makeEdPrivateFields(pub, seed),
			spki,
			pkcs8,
			jwk
		};
	}

	#getSeed(length) {
		const seed = new Uint8Array(length);

		crypto.getRandomValues(seed);

		return seed;
	}

	#makeEdPublicBlob(keyType, pub) {
		return Bytes.concat(
			RFC4253.writeString(keyType),
			RFC4253.writeStringBytes(pub)
		);
	}

	#makeEdPrivateFields(pub, seed) {
		const priv = App.Bytes.concat(seed, pub); // seed || pub

		return Bytes.concat(
			RFC4253.writeStringBytes(pub),
			RFC4253.writeStringBytes(priv)
		);
	}

	#algoIdFor(crv) {
		if(!OID[crv]){
			throw new Error(`Invalid curve: ${crv}. Must be Ed25519 or Ed448`);
		}

		const oid = OID[crv];

		// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ABSENT }
		return DerHelper.seq(DerHelper.oid(oid));
	}

	#toSpkiDer({ crv, pub }) {
		const alg = this.#algoIdFor(crv);
		const spk = DerHelper.bit(pub); // BIT STRING of raw public key

		return DerHelper.concatSequence(alg, spk);
	}

	#toPkcs8Der({ crv, seed, pub = null, includePublic = true }) {
		const alg = this.#algoIdFor(crv);
		const version = (includePublic) ? DerHelper.tlv(0x02, Uint8Array.of(0x01)) : DerHelper.int(0); // INTEGER 1 if publicKey present, else 0
		const priv = DerHelper.oct(seed); // RFC8410: privateKey OCTET STRING contains the seed
		const items = [version, alg, priv];

		if(includePublic){
			if(!pub){
				throw new Error('includePublic=true requires pub');
			}

			const pubBit = DerHelper.bit(pub);
			items.push(DerHelper.ctxExplicit(1, pubBit)); // [1] EXPLICIT BIT STRING
		}

		return DerHelper.concatSequence(...items);
	}

	#toJwk({ crv, pub, seed = null }) {
		const jwk = {
			kty: 'OKP',
			crv,
			x: Bytes.toBase64(pub),
			d: null
		};

		if(seed){
			jwk.d = Bytes.toBase64(seed);
		}

		return jwk;
	}
}