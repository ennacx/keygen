import fs from "fs";

const pem = fs.readFileSync(process.argv[2] || "id_rsa.pem", "utf8");

const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

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

// 3. ciphername / kdfname / kdfoptions
const ciphername = readString().toString("utf8");
const kdfname    = readString().toString("utf8");
const kdfoptions = readString();
console.log([
	`ciphername: ${ciphername}`,
	`kdfname: ${kdfname}`,
	`kdfoptions(hex): ${kdfoptions.toString("hex")}`
].join("\n"));

if(kdfname === "bcrypt"){
	// ここで初めて salt / rounds を中身から読む
	let koOffset = 0;
	const readKdfU32 = () => {
		const v = kdfoptions.readUInt32BE(koOffset);

		koOffset += 4;

		return v;
	};
	const readKdfString = () => {
		const len = readKdfU32();
		const s = kdfoptions.slice(koOffset, koOffset + len);

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
	// kdfname = none の場合は kdfoptions は長さ0
	console.log("no KDF options (ciphername/kdfname = none)");
}

// 5. nkeys と publickey1, encrypted/plain list を読む
const nkeys = readU32();
console.log(`nkeys: ${nkeys}`);

// 公開鍵は1個だけを想定
const publicKey1 = readString();
console.log([
	`publicKey1 length: ${publicKey1.length} bytes`,
	`publicKey1(hex head): ${publicKey1.toString("hex").slice(0, 64)}...`
].join("\n"));

// 最後の string が encrypted または plain な private list
const privList = readString();
console.log(`privList length: ${privList.length} bytes`);

// 6. ciphername=none の場合は privList をそのままパースして中身を確認
if(ciphername === "none"){
	console.log("---- parsing plain private block ----");
	let poff = 0;
	const readPrivU32 = () => {
		const v = privList.readUInt32BE(poff);

		poff += 4;

		return v;
	};
	const readPrivString = () => {
		const len = readPrivU32();
		const s = privList.slice(poff, poff + len);

		poff += len;

		return s;
	};

	try {
		// checkint
		const check1 = readPrivU32();
		const check2 = readPrivU32();
		console.log([
			`checkint1: ${check1}`,
			`checkint2: ${check2}`
		].join("\n"));

		// key type
		const keytype = readPrivString().toString("utf8");
		console.log(`inner keytype: ${keytype}`);

		// mpint
		const n    = readPrivString(); // mpint n
		const e    = readPrivString(); // mpint e
		const d    = readPrivString(); // mpint d
		const iqmp = readPrivString(); // mpint iqmp
		const p    = readPrivString(); // mpint p
		const q    = readPrivString(); // mpint q
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
			"-------------------------------"
		].join("\n"));

		// comment
		const comment = readPrivString().toString("utf8");
		console.log(`comment: ${JSON.stringify(comment)}`);

		// remaining, offset
		const remaining = privList.length - poff;
		console.log(`remaining bytes (should be padding): ${remaining}`);
		if(remaining > 0){
			console.log(`padding(hex): ${privList.slice(poff).toString("hex")}`);
		}
	} catch(e){
		console.error("error while parsing plain private block:", e);
	}
} else{
	console.log("ciphername != none → privList は暗号化済みブロック（中身はここではパースしない）");
}
