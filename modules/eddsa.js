// CDN
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
// Local
import { Bytes } from "./bytes.js";
import { RFC4253 } from "./rfc4253.js";

export class EdDSA {
	static preset = {
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

	static generate(presetKey) {
		if(!this.preset[presetKey]){
			throw new Error(`Invalid preset key: ${presetKey}`);
		}

		const preset = this.preset[presetKey];
		const seed = this.#getSeed(preset.seedLen);

		let pub;
		switch(presetKey){
			case 'Ed25519':
				pub = ed25519.getPublicKey(seed);
				break;
			case 'Ed448':
				pub = ed448.getPublicKey(seed);
				break;
		}

		const keyType = `ssh-${preset.name}`;

		return {
			keyType,
			seed,
			pub,
			len: preset.len,
			publicBlob: this.#makeEdPublicBlob(keyType, pub),
			privateFields: this.#makeEdPrivateFields(pub, seed),
		};
	}

	static #getSeed(length) {
		const seed = new Uint8Array(length);

		crypto.getRandomValues(seed);

		return seed;
	}

	static #makeEdPublicBlob(keyType, pub) {
		return Bytes.concat(
			RFC4253.writeString(keyType),
			RFC4253.writeStringBytes(pub)
		);
	}

	static #makeEdPrivateFields(pub, seed) {
		const priv = App.Bytes.concat(seed, pub); // seed || pub

		return Bytes.concat(
			RFC4253.writeStringBytes(pub),
			RFC4253.writeStringBytes(priv)
		);
	}
}