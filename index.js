let runnable = true;

// Crypt実装チェック
if(!window.crypto || !window.crypto.subtle || typeof window.crypto.getRandomValues !== 'function'){
	runnable = false;

	// 全ボタン無効化
	$('button, input, select').each(function(idx, elem){
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
	const $generateButton = $('button[name="generate-button"]');
	const $resetButton = $('button[name="gen-reset-button"]');
	const $errorAlert = $('#error-alert');

	const genUiReset = () => {
		$('pre#pub-fp').text("(Ungenerated)");
		$('pre#pub-openssh').text("(Ungenerated)");
		$('pre#pub').text("(Ungenerated)");
		$('pre#priv').text("(Ungenerated)");

		$errorAlert.hide();
		$errorAlert.empty();

		$('#dlPub').prop('disabled', true);
		$('#dlPubOpenSSH').prop('disabled', true);
		$('#dlPriv').prop('disabled', true);
		$('#dlPrivPpk').prop('disabled', true);

		$('#generate-fill').width('0%');
	};

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
		if(!runnable){
			return;
		}

		$resetButton.click();

		if(checked){
			$('#guri2-field').show(200);

			keygenReduceNum = 0;

			$generateButton.prop('disabled', true);
		} else{
			$('#guri2-field').hide(200);

			keygenReduceNum = -1;

			$generateButton.prop('disabled', false);
		}

		$('button#gen-reset').click();
	};

	guri2zoneToggle($guri2Check.prop('checked'));
	$guri2Check.change(function(){
		guri2zoneToggle($(this).prop('checked'));
	});

	/*
	 * リセットボタン押下
	 */
	$resetButton.click(() => {
		if(!runnable){
			return;
		}

		genUiReset();
	});

	/*
	 * 生成ボタン押下
	 */
	$generateButton.click(async () => {
		if(!runnable){
			return;
		}

		const al = $('select[name="algo"] option:selected').val();
		const opt = {
			comment: $('input[name="comment"]').val().replace(/[^0-9a-z\-_]/g, '')
		};

		const $progress = $('#generate-fill');
		const progress = (done, total) => {
			$progress.width(`${Math.round((done / total) * 100)}%`);
		};

		progress(0, 1);

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

		try {
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
			download("dlPubOpenSSH", result.openssh, `authorized_keys`);
			download("dlPriv", privatePEM, `id_${al.toLowerCase()}.pem`);
			if(result.ppk !== undefined){
				download("dlPrivPpk", result.ppk, `id_${al.toLowerCase()}.ppk`);
			} else{
				$('#dlPrivPpk').prop('disabled', true);
			}
		} catch(e) {
			$errorAlert.text(e.message).show();
		}
	});
})
