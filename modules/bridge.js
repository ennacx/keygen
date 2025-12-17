import bcryptPbkdf from 'https://cdn.jsdelivr.net/npm/bcrypt-pbkdf@1.0.2/+esm';
import * as chacha20poly1305 from 'https://cdn.jsdelivr.net/npm/@stablelib/chacha20poly1305@2.0.1/+esm';

import { Helper } from './helper.js';
import { Bytes } from './bytes.js';
import { Parser } from './parser.js';
import { RFC4253 } from './rfc4253.js';
import { PubKey } from "./pubkey.js";
import { KeyMaterial } from "./key-material.js";
import { PKCS8withPBES2 } from './pkcs8-with-pbes2.js';
import { PPKv3 } from './ppk-v3.js';

window.CdnApp = Object.freeze({
	bcryptPbkdf,
	Chacha20poly1305: chacha20poly1305.ChaCha20Poly1305,
});
window.App = Object.freeze({
	Helper,
	Bytes,
	Parser,
	RFC4253,
	PubKey,
	PKCS8withPBES2,
	PPKv3,
});

window.KeyMaterial = KeyMaterial;
