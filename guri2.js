(() => {
	// 目標ビット数 (2bits/ev見積 ⇒ 128サンプル ≒ 256bits)
	const TARGET_BITS = 256;
	const BITS_PER_EVENT = 2;

	// リングバッファ的に生バッファを溜める
	const POOL_BYTES = 1024;
	const POOL = new Uint8Array(POOL_BYTES);

	const PASSIVE_TRUE = { passive: true };

	let writeIdx = 0;
	let collectedBits = 0;
	let done = false;

	const zone = document.getElementById('zone');
	const fill = document.getElementById('fill');
	const status = document.getElementById('status');
	const out = document.getElementById('out');
	const btnReset = document.getElementById('guri2gen-reset');

	const getProcessingStatusText = () => `収集中: ${collectedBits} / ${TARGET_BITS} bits`;

	const getSeed = async () => {
		const digest = await crypto.subtle.digest('SHA-256', POOL);

		// 集めたプールをハッシュ化 (seedマテリアルとして扱える256bit(32byte))
		return new Uint8Array(digest);
	};

	const toHex = (u8arr) => [...u8arr].map((b) => b.toString(16).padStart(2, '0')).join('');

	const addEntropy = (x, y) => {
		// 時刻の微細な揺らぎ (小数) も混ぜる
		const t = performance.now();
		// OS乱数も少量ミックスして乱数の偏り対策
		const r = crypto.getRandomValues(new Uint8Array(1))[0];

		// 低ビットの方が揺らぎが大きいことが多いので折りたたむ
		const v1 = (x ^ (x >>> 3) ^ (y << 1) ^ (y >>> 2)) & 0xFF;
		const tt = ((t * 1000) | 0) & 0xFFFFFFFF; // μs相当の下位を使う
		const v2 = (tt ^ (tt >>> 11) ^ (r << 5)) & 0xFF;

		POOL[writeIdx++ % POOL_BYTES] ^= v1;
		POOL[writeIdx++ % POOL_BYTES] ^= v2;

		collectedBits = Math.min(TARGET_BITS, collectedBits + BITS_PER_EVENT);
		const pct = Math.round((collectedBits / TARGET_BITS) * 100);
		fill.style.width = `${pct}%`;

		if(collectedBits >= TARGET_BITS){
			if(!done){
				done = true;
				status.textContent = `${TARGET_BITS}bit分のエントロピーを収集しました。`;

				document.getElementById('generate-button').disabled = false;

				getSeed().then((d) => {
					keygenReduceNum = d.reduce((a, b) => a ^ b, 0);

					out.textContent = `Seed (SHA-256):\n${toHex(d)}`;

					document.getElementById('generate-button').click();
				});
			}
		} else{
			status.textContent = getProcessingStatusText();
		}
	};

	const onMouse = (e) => {
		addEntropy(e.clientX|0, e.clientY|0);
	};
	const onTouch = (e) => {
		for(const t of e.touches){
			addEntropy(t.clientX|0, t.clientY|0);
		}
	};
	const onClick = (e) => {
		addEntropy((e.clientX ^ e.button)|0, (e.clientY ^ Date.now())|0);
	};

	zone.addEventListener('mousemove', onMouse);
	zone.addEventListener('mousedown', onClick);
	zone.addEventListener('touchmove', onTouch, PASSIVE_TRUE);
	zone.addEventListener('touchstart', onTouch, PASSIVE_TRUE);

	btnReset.addEventListener('click', () => {
		POOL.fill(0);
		writeIdx = 0;
		collectedBits = 0;
		done = false;

		fill.style.width = '0%';
		status.textContent = getProcessingStatusText();
		out.textContent = '';

		// 非チェック時は必ずenabled状態
		if(document.getElementById('guri2view').checked){
			document.getElementById('generate-button').disabled = true;
		}
	});
})();
