import bcryptPbkdf from 'bcrypt-pbkdf';
import argon2 from "argon2-browser/dist/argon2-bundled.min.js";
import CryptoJS from 'crypto-js';
import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305';

import { Helper } from './helper.js';
import { Bytes } from './bytes.js';
import { Parser } from './parser.js';
import { RFC4253 } from './rfc4253.js';
import { OpenSSH } from './openssh.js';
import { PubKey } from "./pubkey.js";
import { KeyMaterial } from "./key-material.js";
import { PKCS8withPBES2 } from './pkcs8-with-pbes2.js';
import { PPKv3 } from './ppk-v3.js';

window.CdnApp = Object.freeze({
	PBKDF: bcryptPbkdf,
	Argon2: argon2,
	CryptoJS,
	ChaCha20Poly1305,
});
window.App = Object.freeze({
	Helper,
	Bytes,
	Parser,
	RFC4253,
	OpenSSH,
	PubKey,
	PKCS8withPBES2,
	PPKv3,
});

window.KeyMaterial = KeyMaterial;
