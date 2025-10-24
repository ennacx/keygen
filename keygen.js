const PUBKEY_LABEL = "PUBLIC KEY";
const PRIVKEY_LABEL = "PRIVATE KEY";

async function generateRSA(name, nist) {
	let algo;
	switch(name){
		case 'RSA':
			algo = {
				name: "RSA-PSS",
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256"
			};
			break;

		case 'ECDSA':
			algo = {
				name: "ECDSA",
				namedCurve: `P-${nist}`
			}
	}

	if(!algo){
		throw Error("Invalid algorithm:");
	}

	const keyPair = await crypto.subtle.generateKey(algo, true, ["sign", "verify"]);

	const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
	const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);

	const publicPEM  = toPEM(spki, PUBKEY_LABEL);
	const privatePEM = toPEM(pkcs8, PRIVKEY_LABEL);

	document.getElementById("pub").textContent  = publicPEM;
	document.getElementById("priv").textContent = privatePEM;

	download("dlPub", publicPEM, "id_rsa.pub.pem");
	download("dlPriv", privatePEM, "id_rsa.pem");
}

function toPEM(buffer, label) {
	const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)))
		.replace(/(.{64})/g, "$1\n");
	return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}
