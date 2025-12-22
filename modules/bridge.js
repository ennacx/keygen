import CryptoJS from 'crypto-js';

import { OID, PEM_LABEL } from './const.js';

import { Helper } from './helper.js';
import { DerHelper } from './der-helper.js';
import { Bytes } from './bytes.js';
import { Parser } from './parser.js';
import { RFC4253 } from './rfc4253.js';
import { OpenSSH } from './openssh.js';
import { PubKey } from "./pubkey.js";
import { KeyMaterial } from "./key-material.js";
import { EdDSA } from './eddsa.js';
import { PKCS8withPBES2 } from './pkcs8-with-pbes2.js';
import { PPKv3 } from './ppk-v3.js';

window.KeyMaterial = KeyMaterial;

window.CdnApp = Object.freeze({
	CryptoJS,
});
window.App = Object.freeze({
	PEM_LABEL,
	Helper,
	DerHelper,
	Bytes,
	Parser,
	RFC4253,
	OpenSSH,
	PubKey,
	EdDSA,
	PKCS8withPBES2,
	PPKv3,
});
