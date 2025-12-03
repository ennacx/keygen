const PUBKEY_LABEL = "PUBLIC KEY";
const PRIVKEY_LABEL = "PRIVATE KEY";

let keygenReduceNum = -1;

function parseRsaSpki(spkiBuf) {
	const bytes = (spkiBuf instanceof Uint8Array) ? spkiBuf : new Uint8Array(spkiBuf);
	let offset = 0;

	const readLen = () => {
		let len = bytes[offset++];
		if(len & 0x80){
			const nBytes = len & 0x7F;

			len = 0;
			for(let i = 0; i < nBytes; i++){
				len = (len << 8) | bytes[offset++];
			}
		}

		return len;
	};

	const expect = (tag) => {
		if(bytes[offset++] !== tag){
			throw new Error(`Unexpected ASN.1 tag, expected 0x${tag.toString(16).padStart(2, '0')}`);
		}
	};

	// SubjectPublicKeyInfo
	expect(0x30);           // SEQUENCE
	readLen();              // 全体長

	// AlgorithmIdentifier
	expect(0x30);           // SEQUENCE
	const algLen = readLen();
	offset += algLen;       // ざっくりスキップ（rsaEncryption前提）

	// subjectPublicKey BIT STRING
	expect(0x03);
	const bitLen = readLen();
	offset++;               // unused bits = 0

	// RSAPublicKey (SEQUENCE)
	expect(0x30);
	readLen();

	// modulus (INTEGER)
	expect(0x02);
	let nLen = readLen();
	let nStart = offset;
	offset += nLen;

	// exponent (INTEGER)
	expect(0x02);
	let eLen = readLen();
	let eStart = offset;
	offset += eLen;

	// 先頭 0x00 は符号ビット用の場合があるので取り除く
	while(nLen > 0 && bytes[nStart] === 0x00){
		nStart++;
		nLen--;
	}
	while(eLen > 0 && bytes[eStart] === 0x00){
		eStart++;
		eLen--;
	}

	// 元のバイト列からmodulus, exponentを切り出す
	const n = bytes.slice(nStart, nStart + nLen);
	const e = bytes.slice(eStart, eStart + eLen);

	return { n, e };
}

const rfc4253 = {
	writeString: (str) => {
		const enc = new TextEncoder();
		const s = enc.encode(str);
		const out = new Uint8Array(4 + s.length);
		const view = new DataView(out.buffer);
		view.setUint32(0, s.length);
		out.set(s, 4);

		return out;
	},

	writeMpint: (bytes) => {
		// mpintは先頭bitが1なら 0x00 を前置して符号を守る
		let b = bytes;
		if(b.length > 0 && (b[0] & 0x80)){
			const tmp = new Uint8Array(b.length + 1);
			tmp.set(b, 1);
			b = tmp;
		}
		const out = new Uint8Array(4 + b.length);
		const view = new DataView(out.buffer);
		view.setUint32(0, b.length);
		out.set(b, 4);

		return out;
	},

	// 複数Uint8Arrayを連結
	concatBytes: (arrays) => {
		const len = arrays.reduce((sum, a) => sum + a.length, 0);
		const out = new Uint8Array(len);
		let offset = 0;
		for(const a of arrays){
			out.set(a, offset);
			offset += a.length;
		}

		return out;
	}
};

const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

const toPEM = (buffer, label) => {
	const base64 = toBase64(buffer).replace(/(.{64})/g, "$1\n");

	return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}

function download(id, content, filename) {
	const btn = document.getElementById(id);
	btn.disabled = false;
	btn.onclick = () => {
		const blob = new Blob([content], { type: "application/x-pem-file" });
		const a = document.createElement("a");
		a.href = URL.createObjectURL(blob);
		a.download = filename;
		a.click();
		URL.revokeObjectURL(a.href);
	};
}

async function generateKey(name, opt, onProgress) {
	let algo;
	let keyUsage;
	switch(name){
		case 'RSA':
			algo = {
				name: "RSA-PSS",
				modulusLength: opt.len,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256"
			};
			keyUsage = ["sign", "verify"];
			break;

		case 'ECDSA':
			algo = {
				name: name,
				namedCurve: opt.nist
			};
			keyUsage = ["sign", "verify"];
			break;
	}

	if(!algo){
		throw Error(`Invalid algorithm: ${name}`);
	}

	let keyPair;
	if(keygenReduceNum >= 0){
		const count = 7;
		let done = 0;
		const wrapWithProgress = (p) =>
			p.then((result) => {
				if(typeof onProgress === 'function'){
					onProgress(++done, count);
				}

				return result;
			});

		const pairBuffer = await Promise.all(
			Array.from(
				{ length: count },
				() => wrapWithProgress(crypto.subtle.generateKey(algo, true, keyUsage))
			)
		);

		keyPair = pairBuffer[keygenReduceNum & count];
	} else{
		keyPair = await crypto.subtle.generateKey(algo, true, ["sign", "verify"])

		if(typeof onProgress === 'function'){
			onProgress(1, 1);
		}
	}

	// 公開DER
	const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
	// 秘密DER
	const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

	let openssh;
	if(name === 'RSA'){
		const { n, e } = parseRsaSpki(spki);
		const b64 = toBase64(rfc4253.concatBytes([
			rfc4253.writeString("ssh-rsa"),
			rfc4253.writeMpint(e),
			rfc4253.writeMpint(n)
		]));

		openssh = `ssh-rsa ${b64}`;

		if(opt.comment.length > 0){
			openssh += ` ${opt.comment}`;
		}
	} else{
		openssh = undefined;
	}

	return {
		public: spki,
		private: pkcs8,
		openssh: openssh
	};
}
