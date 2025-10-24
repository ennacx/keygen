// Crypt実装チェック
if(!window.crypto || typeof window.crypto.getRandomValues !== 'function' || typeof window.crypto.randomUUID !== 'function'){
	// ボタン無効化
	$('button').each(function(idx, elem){
		$(elem).prop('disabled', true);
	});

	window.alert("お使いのブラウザでは本機能を使用することが出来ません😢");
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

$('button[name="gen"]').click(async function(){
	const al = $('select[name="algo"] option:selected').val();
	const nist = $('input[name="nist"]:checked').val();

	await generateRSA(al, nist);
});
