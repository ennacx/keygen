// CDN
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
// Local
import { OID, EdDSA_PRESET } from "./const.js";
import { Bytes } from "./bytes.js";
import { RFC4253 } from "./rfc4253.js";
import { DerHelper } from "./der-helper.js";

export class EdDSA {
	curveName;

	preset;

	seed;

	keyType;

	publicKey;

	privateKey;

	publicBlob;

	privateFields;

	spki;

	pkcs8;

	jwk;

	constructor(curveName) {
		if(!EdDSA_PRESET[curveName]){
			throw new Error(`Invalid preset key: ${curveName}`);
		}

		this.curveName = curveName;
		this.preset    = EdDSA_PRESET[this.curveName];
		this.seed      = this.#getSeed(this.preset.seedLen);
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

	#getSeed(length) {
		const seed = new Uint8Array(length);

		crypto.getRandomValues(seed);

		return seed;
	}

	#algoIdFor(crv) {
		if(!OID[crv]){
			throw new Error(`Invalid curve: ${crv}. Must be Ed25519 or Ed448`);
		}

		const oid = OID[crv];

		// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ABSENT }
		return DerHelper.seq(DerHelper.oid(oid));
	}

	#toSpkiDer() {
		const alg = this.#algoIdFor(this.curveName);
		const spk = DerHelper.bit(this.publicKey); // BIT STRING of raw public key

		return DerHelper.concatSequence(alg, spk);
	}

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