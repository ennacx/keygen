import fs from 'fs';

const pem = fs.readFileSync(process.argv[2] || 'id_rsa.pem', 'utf8');

const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

const bufToBigInt = (buf) => {
	// mpintの先頭 0x00（符号保護）があれば除外してOK
	if(buf.length && buf[0] === 0x00){
		buf = buf.slice(1);
	}

	return BigInt(`0x${buf.toString('hex')}`);
};

const modMul = (a, b, m) => (a * b) % m;

const logger = (msgArray, e = null) => {
	let msg;

	if(Array.isArray(msgArray)){
		msg = msgArray.join('\n');
	} else if(typeof msgArray === 'string'){
		msg = msgArray;
	}

	if(msg){
		if(e === null){
			console.log(msg);
		} else{
			console.error(msg, e);
		}
	}
};

// 1. ヘッダ/フッタを削って base64 デコード
const b64 = pem
	.split('\n')
	.filter((line) => !line.startsWith('-----') && line.trim() !== '')
	.join('');

const buf = Buffer.from(b64, 'base64');

let offset = 0;
const readU32 = () => {
	const v = buf.readUInt32BE(offset);

	offset += 4;

	return v;
};
const readString = () => {
	const len = readU32();
	const s = buf.slice(offset, offset + len);

	offset += len;

	return s;
};

// 2. magic チェック
const magicLen = 'openssh-key-v1'.length + 1; // 末尾の0x00分
const magic = buf.slice(0, magicLen);
logger(`magic: ${magic.toString('utf8')}`); // "openssh-key-v1\0"

offset = magicLen;

// 3. cipherName / kdfName / kdfOptions
const cipherName = readString().toString('utf8');
const kdfName    = readString().toString('utf8');
const kdfOptions = readString();
logger([
	`cipherName: ${cipherName}`,
	`kdfName: ${kdfName}`,
	`kdfOptions(hex): ${kdfOptions.toString('hex')}`
]);

if(kdfName === 'bcrypt'){
	// ここで初めて salt / rounds を中身から読む
	let koOffset = 0;
	const readKdfU32 = () => {
		const v = kdfOptions.readUInt32BE(koOffset);

		koOffset += 4;

		return v;
	};
	const readKdfString = () => {
		const len = readKdfU32();
		const s = kdfOptions.slice(koOffset, koOffset + len);

		koOffset += len;

		return s;
	};

	const salt   = readKdfString();
	const rounds = readKdfU32();
	logger([
		`salt(hex): ${salt.toString('hex')}`,
		`rounds: ${rounds}`
	]);
} else{
	// kdfName = none の場合は kdfOptions は長さ0
	logger('no KDF options (cipherName/kdfName = none)');
}

// 5. nKeys と publicKey1, encrypted/plain list を読む
const nKeys = readU32();
logger(`nKeys: ${nKeys}`);

// 公開鍵は1個だけを想定
const publicKey1 = readString();
logger([
	`publicKey1 length: ${publicKey1.length} bytes`,
	`publicKey1(hex head): ${publicKey1.toString('hex').slice(0, 64)}...`,
	`offset after publicKey1: ${offset} bytes.`,
	`next 4 bytes (privList len): ${buf.slice(offset, offset + 4).toString('hex')}`
]);

const readPubU32 = (buf, st) => {
	const v = buf.readUInt32BE(st.off);

	st.off += 4;

	return v;
};
const readPubString = (buf, st) => {
	const len = readPubU32(buf, st);
	const s = buf.slice(st.off, st.off+len);

	st.off += len;
	return s;
};
const mpintToBigInt = (b) => {
	if(b[0] === 0x00){
		b = b.slice(1);
	}

	return BigInt(`0x${b.toString('hex')}`);
}

// 公開鍵のmpint
const st = { off: 0 };
const kt = readPubString(publicKey1, st).toString('utf8'); // "ssh-rsa"
if(kt === 'ssh-rsa'){
	const a  = readPubString(publicKey1, st);                  // mpint #1
	const b  = readPubString(publicKey1, st);                  // mpint #2
	const A  = mpintToBigInt(a);
	const B  = mpintToBigInt(b);
	logger([
		`pub keytype: ${kt}`,
		`mpint#1 len: ${a.length}`,
		`mpint#2 len: ${b.length}`,
		`mpint#1: ${A.toString(16)}`,
		`mpint#2 head: ${b.slice(0, 8).toString('hex')}`
	]);
} else if(kt.startsWith('ecdsa-sha2-')){
	const curve = readPubString(publicKey1, st).toString('utf8');
	const Q = readPubString(publicKey1, st); // 0x04||X||Y
	logger([
		`pub keytype: ${kt}`,
		`curve: ${curve}`,
		`QLen: ${Q.length}`
	]);
} else if(kt.startsWith('ssh-ed')){
	const pub = readPubString(publicKey1, st); // 32 or 57 bytes
	logger([
		`pub keytype: ${kt}`,
		`pubLen: ${pub.length}`,
		`pub(hex head): ${pub.slice(0, 8).toString('hex')}`
	]);
} else{
	logger(`unsupported public key type: ${kt}`);
}

// 最後の string が encrypted または plain な private list
const privList = readString();
logger([
	`privList length: ${privList.length} bytes`
]);

// 6. cipherName=none の場合は privList をそのままパースして中身を確認
if(cipherName === 'none'){
	logger('---- parsing plain private block ----');

	let privOffset = 0;

	const readPrivU32 = () => {
		const v = privList.readUInt32BE(privOffset);

		privOffset += 4;

		return v;
	};
	const readPrivString = () => {
		const len = readPrivU32();
		const s = privList.slice(privOffset, privOffset + len);

		privOffset += len;

		return s;
	};

	try {
		// checkInt
		const check1 = readPrivU32();
		const check2 = readPrivU32();
		logger([
			`checkInt1: ${check1}`,
			`checkInt2: ${check2}`
		]);

		// key type
		const keyType = readPrivString().toString('utf8');
		logger(`inner keyType: ${keyType}`);

		if(keyType === 'ssh-rsa'){
			// inner public blob
			const innerPublicBlob = readPrivString();
			logger([
				`inner public blob: ${toBase64(innerPublicBlob)}`,
				`inner public blob length: ${innerPublicBlob.length}`,
				// ついでに外側 publicKey1 と一致チェック
				`(inner public blob == publicKey1): ${(innerPublicBlob.equals(publicKey1)) ? 'true' : 'false'}`,
			]);

			// mpint
			const n    = readPrivString();  // mpint n
			const e    = readPrivString();  // mpint e
			const d    = readPrivString();  // mpint d
			const iqmp = readPrivString();  // mpint iqmp
			const p    = readPrivString();  // mpint p
			const q    = readPrivString();  // mpint q
			const N    = bufToBigInt(n);    // bigint n
			const E    = bufToBigInt(e);    // bigint e
			const D    = bufToBigInt(d);    // bigint d
			const IQMP = bufToBigInt(iqmp); // bigint iqmp
			const P    = bufToBigInt(p);    // bigint p
			const Q    = bufToBigInt(q);    // bigint q
			logger([
				'----- Mpint values -----',
				`n: ${toBase64(n)}`,
				`nLen: ${n.length}`, // 256〜257バイト
				`e: ${toBase64(e)}`,
				`eLen: ${e.length}`, // 3バイト (0x010001)
				`d: ${toBase64(d)}`,
				`dLen: ${d.length}`,
				`iqmp: ${toBase64(iqmp)}`,
				`iqmpLen: ${iqmp.length}`,
				`p: ${toBase64(p)}`,
				`pLen: ${p.length}`,
				`q: ${toBase64(q)}`,
				`qLen: ${q.length}`,
				'-------------------------------',
				`n == p * q ?: ${(N === P * Q) ? 'true' : 'false'}`,
				`(q * iqmp) % p == 1 ?: ${(modMul(Q, IQMP, P) === 1n) ? 'true' : 'false'}`,
				'-------------------------------'
			]);
		} else if (keyType === 'ssh-ed25519' || keyType === 'ssh-ed448') {
			const pub  = readPrivString(); // 32 or 57 bytes
			const priv = readPrivString(); // 64 or 114 bytes (seed||pub)

			logger([
				`pub(hex): ${pub.toString('hex')}`,
				`priv(hex): ${priv.toString('hex')}`
			]);
		} else if (keyType.startsWith('ecdsa-sha2-')){
			const curve = readPrivString().toString('utf8');
			const Q     = readPrivString(); // bytes, Q[0] should be 0x04
			const d     = readPrivString(); // mpint, same as string encoding

			logger([
				`curve: ${curve}`,
				`Q: ${toBase64(Q)}`,
				`QLen: ${Q.length}`,
				`d: ${toBase64(d)}`,
				`dLen: ${d.length}`,
			]);
		}

		// comment
		const comment = readPrivString().toString('utf8');
		logger(`comment: ${JSON.stringify(comment)}`);

		// remaining, offset
		const remaining = privList.length - privOffset;
		logger(`remaining bytes (should be padding): ${remaining}`);
		if(remaining > 0){
			logger(`padding(hex): ${privList.slice(privOffset).toString('hex')}`);
		}
	} catch(e){
		logger('error while parsing plain private block:', e);
	}
} else{
	logger("cipherName != none → privList は暗号化済みブロック (中身はここではパースしない)");
}
