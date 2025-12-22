// CDN
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
// Local
import { EdDSA_PRESET } from "./const.js";
import { Bytes } from "./bytes.js";
import { RFC4253 } from "./rfc4253.js";

export class EdDSA {
	static generate(presetKey) {
		if(!EdDSA_PRESET[presetKey]){
			throw new Error(`Invalid preset key: ${presetKey}`);
		}

		const preset = EdDSA_PRESET[presetKey];
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