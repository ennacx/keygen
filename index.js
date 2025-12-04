// Crypt実装チェック
if(!window.crypto || !window.crypto.subtle || typeof window.crypto.getRandomValues !== 'function'){
	// 全ボタン無効化
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

$(() => {
	const $rsaLengthRadio = $('#rsa-length-radio');
	const $ecdsaNistRadio = $('#ecdsa-nist-radio');
	const $guri2Check = $('input[name="guri2view"]');
	const $generateButton = $('button[name="gen"]');
	const $resetButton = $('button[name="gen-reset"]');

	const algoRadioToggle = () => {
		const al = $('select[name="algo"] option:selected').val();
		switch(al){
			case 'RSA':
				$rsaLengthRadio.addClass('d-flex').removeClass('d-none');
				$ecdsaNistRadio.addClass('d-none').removeClass('d-flex');
				break;
			case 'ECDSA':
				$rsaLengthRadio.addClass('d-none').removeClass('d-flex');
				$ecdsaNistRadio.addClass('d-flex').removeClass('d-none');
				break;
		}
	};

	algoRadioToggle();
	$('select[name="algo"]').change(algoRadioToggle);

	const guri2zoneToggle = (checked) => {
		if(checked){
			$('#guri2-zone').show(200);

			keygenReduceNum = 0;

			$generateButton.prop('disabled', true);
		} else{
			$('#guri2-zone').hide(200);

			keygenReduceNum = -1;

			$generateButton.prop('disabled', false);
		}

		$('button#gen-reset').click();
	};

	guri2zoneToggle($guri2Check.prop('checked'));
	$guri2Check.change(function(){
		guri2zoneToggle($(this).prop('checked'));
	});

	$resetButton.click(() => {
		$('pre#pub-fp').text("（未生成）");
		$('pre#pub-openssh').text("（未生成）");
		$('pre#pub').text("（未生成）");
		$('pre#priv').text("（未生成）");
		$('#dlPub').prop('disabled', true);
		$('#dlPubOpenSSH').prop('disabled', true);
		$('#dlPriv').prop('disabled', true);

		$('#generate-fill').width('0%');
	});

	$generateButton.click(async () => {
		const al = $('select[name="algo"] option:selected').val();
		const opt = {
			comment: ''
		};

		const $progress = $('#generate-fill');
		const progress = (done, total) => {
			$progress.width(`${Math.round((done / total) * 100)}%`);
		};

		$resetButton.click();
		$progress.width('0%');

		switch(al){
			case 'RSA':
				const val = $('input[name="rsalen"]:checked').val();

				opt.prefix = 'ssh-rsa';
				opt.len = parseInt(val);
				break;
			case 'ECDSA':
				const nistVal = $('input[name="nist"]:checked').val();

				opt.nist = `P-${nistVal}`;
				opt.len = parseInt(nistVal);
				opt.prefix = 'ecdsa-sha2-nist' + opt.nist.replace(/\-/g, '').toLowerCase();
				break;
		}

		const result = await generateKey(al, opt, progress);

		// 公開PEM
		const publicPEM  = toPEM(result.public, PUBKEY_LABEL);
		// 秘密PEM
		const privatePEM = toPEM(result.private, PRIVKEY_LABEL);

		// 表示用
		$('#pub-fp').text(result.fingerprint);
		$('#pub-openssh').text(result.openssh);
		$('#pub').text(publicPEM);
		$('#priv').text(privatePEM);

		// DL用
		download("dlPub", publicPEM, `id_${al.toLowerCase()}.pub.pem`);
		download("dlPriv", privatePEM, `id_${al.toLowerCase()}.pem`);
		if(result.openssh !== undefined){
			download("dlPubOpenSSH", result.openssh, `authorized_keys`);
		}
	});
})
