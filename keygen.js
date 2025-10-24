const PUBKEY_LABEL = "PUBLIC KEY";
const PRIVKEY_LABEL = "PRIVATE KEY";

async function generateRSA() {
	const keyPair = await crypto.subtle.generateKey(
		{
			name: "RSA-PSS",
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: "SHA-256"
		},
		true,
		["sign", "verify"]
	);

	const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
	const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);

	const privatePEM = toPEM(pkcs8, PUBKEY_LABEL);
	const publicPEM  = toPEM(spki, PRIVKEY_LABEL);

	document.getElementById("priv").textContent = privatePEM;
	document.getElementById("pub").textContent  = publicPEM;

	enableDownload("dlPriv", privatePEM, "id_rsa.pem");
	enableDownload("dlPub", publicPEM, "id_rsa.pub.pem");
}

function toPEM(buffer, label) {
	const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)))
		.replace(/(.{64})/g, "$1\n");
	return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}

function enableDownload(id, content, filename) {
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

document.getElementById("gen").addEventListener("click", generateRSA);
