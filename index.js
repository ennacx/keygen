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
		const blob = new Blob([content], { type: 'application/x-pem-file' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = filename;
		a.click();
		URL.revokeObjectURL(a.href);
	};
}

$(() => {
	const $rsaLengthRadio = $('#rsa-length-radio');
	const $ecdsaNistRadio = $('#ecdsa-nist-radio');
	const $passphraseCheck = $('input[name="use-passphrase"]');
	const $guri2Check = $('input[name="guri2view"]');
	const $generateButton = $('button[name="generate-button"]');
	const $resetButton = $('button[name="gen-reset-button"]');
	const $errorAlert = $('#error-alert');

	const genUiReset = () => {
		$('pre#pub-fp').text('(Ungenerated)');
		$('pre#pub-openssh').text('(Ungenerated)');
		$('pre#pub').text('(Ungenerated)');
		$('pre#priv').text('(Ungenerated)');

		$errorAlert.hide();
		$errorAlert.empty();

		$passphraseCheck.prop('checked', false).change();
		$('input[name="passphrase"]').val('');
		$('input[name="passphrase_c"]').val('');

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

	const passphraseCheckToggle = (checked) => {
		if(!runnable){
			return;
		}

		if(checked){
			$('#passphrase-field').show(200);
		} else{
			$('#passphrase-field').hide(200);
		}
	};

	passphraseCheckToggle($passphraseCheck.prop('checked'));
	$passphraseCheck.change(function(){
		passphraseCheckToggle($(this).prop('checked'));
	});

	/*
	 * マウスぐりぐりゾーン表示切替
	 */
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
	 * パスフレーズ入力
	 */
	$(document).on('keyup, blur', 'input.passphrase-input', function(){
		const $this = $(this);
		const type = $this.prop('type');
		if(type === 'password'){
			return false;
		}

		// 半角英数字と記号以外は省く
		$this.val($this.val().replace(/[^ -~]/g, ''));
	});

	/*
	 * パスフレーズ表示切替
	 */
	$('button.show-toggle-passphrase').click(function(){
		const $input = $(this).parent().find('input');
		const $i = $(this).find('i');
		const type = $input.prop('type');

		const prop = {
			password: {
				next: 'text',
				remove: 'bi-eye',
				add: 'bi-eye-slash'
			},
			text: {
				next: 'password',
				remove: 'bi-eye-slash',
				add: 'bi-eye'
			}
		};

		const state = prop[type];
		if(!state){
			throw new Error(`State Error: ${type} is not defined.`)
		}

		$input.prop('type', state.next);
		if($i.hasClass(state.remove)){
			$i.removeClass(state.remove);
		}
		$i.addClass(state.add);
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

		$errorAlert.hide();
		$errorAlert.empty();

		const al = $('select[name="algo"] option:selected').val();
		const opt = {
			comment: $('input[name="comment"]').val()
				.trim()                 // 両サイドトリム
				.replace(/ +/g, '-')    // 文字間スペースをハイフンに
				.replace(/[^ -~]/g, '') // 半角英数字と記号以外は省く
		};

		const $progress = $('#generate-fill');
		const progressFunc = (done, total) => {
			$progress.width(`${Math.round((done / total) * 100)}%`);
		};

		// プログレスバーの初期化
		progressFunc(0, 1);

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

		const encType = $('input[name="enc-type"]:checked').val();

		if($passphraseCheck.prop('checked')){
			const passphrase = $('input[name="passphrase"]').val();
			const passphrase_c = $('input[name="passphrase_c"]').val();

			if(encType === 'pkcs8' && passphrase === ''){
				$errorAlert.text('Passphrase is required').show();
				return;
			} else if(passphrase !== passphrase_c){
				$errorAlert.text('Passphrase does not match').show();
				return;
			}

			opt.passphrase = passphrase;
		}

		// try {
			const result = await generateKey(al, opt, progressFunc);

			// 公開PEM
			const publicPEM  = App.Helper.toPEM(result.material.spki, App.Helper.PEM_LABEL.publicKey, 64);

			// 秘密PEM
			let privatePEM;
			if($passphraseCheck.prop('checked')){
				switch(encType){
					case 'pkcs8':
						if(opt.passphrase && opt.passphrase !== ''){
							const pkcs8pbes2 = new App.PKCS8withPBES2(opt.passphrase);
							const { encrypted } = await pkcs8pbes2.encrypt(result.material.pkcs8);
							privatePEM = App.Helper.toPEM(encrypted, App.Helper.PEM_LABEL.privateKey, 64, App.Helper.PEM_LABEL.encryptedAdd);
						} else{
							throw new Error('Passphrase is required for PKCS#8 encryption.');
						}

						break;
					case 'sshv1-cc20p1305':
					case 'sshv1-aes256ctr':
						const cipher = encType.replace(/^sshv1-/, '');

						privatePEM = await App.OpenSSH.makeOpenSSHPrivateKeyV1(
							cipher,
							opt.prefix,
							result.material,
							opt.passphrase || '',
							opt.comment
						);

						break;
					default:
						throw new Error(`Invalid encryption type ${encType}`);
				}
			} else{
				privatePEM = App.Helper.toPEM(result.material.pkcs8, App.Helper.PEM_LABEL.privateKey, 64);
			}

			// 表示用
			$('#pub-fp').text(result.fingerprint);
			$('#pub-openssh').text(result.openssh);
			$('#pub').text(publicPEM);
			$('#priv').text(privatePEM);

			// DL用
			download('dlPub', publicPEM, `id_${al.toLowerCase()}.pub.pem`);
			download('dlPubOpenSSH', result.openssh, `authorized_keys`);
			download('dlPriv', privatePEM, `id_${al.toLowerCase()}.pem`);
			if(result.ppk !== undefined){
				download('dlPrivPpk', result.ppk, `id_${al.toLowerCase()}.ppk`);
			} else{
				$('#dlPrivPpk').prop('disabled', true);
			}
		// } catch(e){
		// 	$errorAlert.text(e.message).show();
		// }
	});
})
