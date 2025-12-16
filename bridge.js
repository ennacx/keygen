import bcryptPbkdf from 'https://cdn.jsdelivr.net/npm/bcrypt-pbkdf@1.0.2/+esm';
import * as chacha20poly1305 from 'https://cdn.jsdelivr.net/npm/@stablelib/chacha20poly1305@2.0.1/+esm';

import { Parser } from './Parser.js';
import { Helper } from './Helper.js';

window.CdnApp = Object.freeze({
	bcryptPbkdf,
	Chacha20poly1305: chacha20poly1305.ChaCha20Poly1305,
});
window.App = Object.freeze({
	Parser,
	Helper,
});
