import fs from "fs";

const pem = fs.readFileSync(process.argv[2] || "id_rsa.pem", "utf8");

const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

const bufToBigInt = (buf) => {
	// mpintの先頭 0x00（符号保護）があれば除外してOK
	if(buf.length && buf[0] === 0x00){
		buf = buf.slice(1);
	}

	return BigInt(`0x${buf.toString("hex")}`);
};

const modMul = (a, b, m) => (a * b) % m;

// 1. ヘッダ/フッタを削って base64 デコード
const b64 = pem
	.split("\n")
	.filter((line) => !line.startsWith("-----") && line.trim() !== "")
	.join("");

const buf = Buffer.from(b64, "base64");

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
const magicLen = "openssh-key-v1".length + 1; // 末尾の0x00分
const magic = buf.slice(0, magicLen);
console.log(`magic: ${magic.toString("utf8")}`); // "openssh-key-v1\0"

offset = magicLen;

// 3. cipherName / kdfName / kdfOptions
const cipherName = readString().toString("utf8");
const kdfName    = readString().toString("utf8");
const kdfOptions = readString();
console.log([
	`cipherName: ${cipherName}`,
	`kdfName: ${kdfName}`,
	`kdfOptions(hex): ${kdfOptions.toString("hex")}`
].join("\n"));

if(kdfName === "bcrypt"){
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
	console.log([
		`salt(hex): ${salt.toString("hex")}`,
		`rounds: ${rounds}`
	].join("\n"));
} else{
	// kdfName = none の場合は kdfOptions は長さ0
	console.log("no KDF options (cipherName/kdfName = none)");
}

// 5. nKeys と publicKey1, encrypted/plain list を読む
const nKeys = readU32();
console.log(`nKeys: ${nKeys}`);

// 公開鍵は1個だけを想定
const publicKey1 = readString();
console.log([
	`publicKey1 length: ${publicKey1.length} bytes`,
	`publicKey1(hex head): ${publicKey1.toString("hex").slice(0, 64)}...`
].join("\n"));

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
const a  = readPubString(publicKey1, st);                  // mpint #1
const b  = readPubString(publicKey1, st);                  // mpint #2
const A  = mpintToBigInt(a);
const B  = mpintToBigInt(b);
console.log([
	`pub keytype: ${kt}`,
	`mpint#1 len: ${a.length}`,
	`mpint#2 len: ${b.length}`,
	`mpint#1: ${A.toString(16)}`,
	`mpint#2 head: ${b.slice(0, 8).toString('hex')}`
].join("\n"));

// 最後の string が encrypted または plain な private list
const privList = readString();
console.log(`privList length: ${privList.length} bytes`);

// 6. cipherName=none の場合は privList をそのままパースして中身を確認
if(cipherName === "none"){
	console.log("---- parsing plain private block ----");
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
		console.log([
			`checkInt1: ${check1}`,
			`checkInt2: ${check2}`
		].join("\n"));

		// key type
		const keyType = readPrivString().toString("utf8");
		console.log(`inner keyType: ${keyType}`);

		// inner public blob
		const innerPublicBlob = readPrivString(); // ← これを追加
		console.log([
			`inner public blob: ${toBase64(innerPublicBlob)}`,
			`inner public blob length: ${innerPublicBlob.length}`,
			// ついでに外側 publicKey1 と一致チェック
			`(inner public blob == publicKey1): ${(innerPublicBlob.equals(publicKey1)) ? "true" : "false"}`,
		].join("\n"));

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
		console.log([
			"----- Mpint values -----",
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
			"-------------------------------",
			`n == p * q ?: ${(N === P * Q) ? "true" : "false"}`,
			`(q * iqmp) % p == 1 ?: ${(modMul(Q, IQMP, P) === 1n) ? "true" : "false"}`,
			"-------------------------------"
		].join("\n"));

		// comment
		const comment = readPrivString().toString("utf8");
		console.log(`comment: ${JSON.stringify(comment)}`);

		// remaining, offset
		const remaining = privList.length - privOffset;
		console.log(`remaining bytes (should be padding): ${remaining}`);
		if(remaining > 0){
			console.log(`padding(hex): ${privList.slice(privOffset).toString("hex")}`);
		}
	} catch(e){
		console.error("error while parsing plain private block:", e);
	}
} else{
	console.log("cipherName != none → privList は暗号化済みブロック（中身はここではパースしない）");
}
