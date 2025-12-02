// Crypt実装チェック
if(!window.crypto || typeof window.crypto.getRandomValues !== 'function' || typeof window.crypto.randomUUID !== 'function'){
	// 全ボタン無効化
	$('button').each(function(idx, elem){
		$(elem).prop('disabled', true);
	});

	window.alert("お使いのブラウザでは本機能を使用することが出来ません😢");
}

$(() => {
	const $rsaLengthRadio = $('#rsa-length-radio');
	const $ecdsaNistRadio = $('#ecdsa-nist-radio');
	const $guri2Check = $('input[name="guri2view"]');
	const $guri2ResetButton = $('button[name="guri2gen-reset"]');
	const $generateButton = $('button[name="gen"]');

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

			$('button#guri2gen-reset').click();

			$generateButton.prop('disabled', false);
		}
	};

	guri2zoneToggle($guri2Check.prop('checked'));
	$guri2Check.change(function(){
		guri2zoneToggle($(this).prop('checked'));
	});

	$guri2ResetButton.click(() => {
		$('pre#pub').text("（未生成）");
		$('pre#priv').text("（未生成）");
	});

	$generateButton.click(async function(){
		const al = $('select[name="algo"] option:selected').val();
		const opt = {};

		switch(al){
			case 'RSA':
				opt.len = parseInt($('input[name="rsalen"]:checked').val());
				break;
			case 'ECDSA':
				opt.nist = $('input[name="nist"]:checked').val();
				break;
		}

		await generateRSA(al, opt);
	});
})
