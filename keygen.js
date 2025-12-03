const PUBKEY_LABEL = "PUBLIC KEY";
const PRIVKEY_LABEL = "PRIVATE KEY";

let keygenReduceNum = -1;

function toPEM(buffer, label) {
	const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)))
		.replace(/(.{64})/g, "$1\n");
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

async function generateRSA(name, opt, onProgress) {
	let algo;
	switch(name){
		case 'RSA':
			algo = {
				name: "RSA-PSS",
				modulusLength: opt.len,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256"
			};
			break;

		case 'ECDSA':
			algo = {
				name: "ECDSA",
				namedCurve: `P-${opt.nist}`
			};
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
				() => wrapWithProgress(crypto.subtle.generateKey(algo, true, ["sign", "verify"]))
			)
		);

		keyPair = pairBuffer[keygenReduceNum & count];
	} else{
		keyPair = await crypto.subtle.generateKey(algo, true, ["sign", "verify"])

		if(typeof onProgress === 'function'){
			onProgress(1, 1);
		}
	}

	return {
		// 公開DER
		public: await crypto.subtle.exportKey("spki", keyPair.publicKey),
		// 秘密DER
		private: await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)
	};
}
