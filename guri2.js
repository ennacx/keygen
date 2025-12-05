/**
 * Converts a Uint8Array into a hexadecimal string representation.
 *
 * The function iterates over each byte in the input Uint8Array, converts
 * each byte into its corresponding 2-character hexadecimal string, and
 * concatenates them into a single string. Each hexadecimal string is
 * zero-padded to ensure it is exactly 2 characters long.
 *
 * @param {Uint8Array} u8arr - The input array of 8-bit unsigned integers to be converted into a hexadecimal string.
 * @returns {string} A string containing the hexadecimal representation of the input Uint8Array.
 */
const toHex = (u8arr) => [...u8arr].map((b) => b.toString(16).padStart(2, '0')).join('');

(() => {
	// 目標ビット数 (2bits/ev見積 ⇒ 128サンプル ≒ 256bits)
	const TARGET_BITS = 256;
	const BITS_PER_EVENT = 2;

	// リングバッファ的に生バッファを溜める
	const POOL_BYTES = 1024;
	const POOL = new Uint8Array(POOL_BYTES);

	const PASSIVE_TRUE = { passive: true };

	let initialized = false;
	let writeIdx = 0;
	let collectedBits = 0;
	let done = false;

	const guriCheck = document.getElementById('guri2view');
	const zone = document.getElementById('guri2-zone');
	const fill = document.getElementById('guri2-fill');
	const status = document.getElementById('guri2-status');
	const out = document.getElementById('guri2-out');
	const btnGen = document.getElementById('generate-button');
	const btnReset = document.getElementById('gen-reset-button');

	/**
	 * Generates and returns a string indicating the processing status.
	 *
	 * The returned string includes the current number of collected bits
	 * and the target number of bits required.
	 *
	 * @function
	 * @returns {string} The processing status text in the format
	 *                   "収集中: {collectedBits} / {TARGET_BITS} bits".
	 */
	const getProcessingStatusText = () => `収集中: ${collectedBits} / ${TARGET_BITS} bits`;

	/**
	 * Asynchronously generates and returns a 256-bit (32-byte) seed material.
	 *
	 * This function hashes the global entropy pool (`POOL`) using the SHA-256
	 * algorithm provided by the Web Cryptography API. The resulting hash is
	 * returned as a `Uint8Array`, which can be used as seed material for further
	 * cryptographic operations.
	 *
	 * @function
	 * @returns {Promise<Uint8Array>} A promise that resolves to a 256-bit Uint8Array,
	 * representing the hashed output of the entropy pool.
	 */
	const getSeed = async () => {
		const digest = await crypto.subtle.digest('SHA-256', POOL);

		// 集めたプールをハッシュ化 (seedマテリアルとして扱える256bit(32byte))
		return new Uint8Array(digest);
	};

	/**
	 * Adds entropy to the random number generation pool by incorporating various
	 * sources of randomness such as the combination of input values, fine-grained
	 * timing data, and operating system-provided random numbers. This improves
	 * the overall unpredictability and reduces bias in the entropy pool.
	 *
	 * The function makes use of bitwise operations to fold lower bits with higher
	 * bits from the input values, as lower bits often have more variance. These
	 * derived values are then mixed into the entropy pool. It also tracks the
	 * total collected entropy and updates the progress status in the UI.
	 *
	 * Once the required amount of entropy has been collected (`TARGET_BITS`),
	 * the function finalizes the entropy collection process, updates the UI with
	 * the completion notification, and enables the user interface for subsequent
	 * actions such as generating a cryptographic seed.
	 *
	 * @param {number} x - The first input value to derive entropy from.
	 * @param {number} y - The second input value to derive entropy from.
	 */
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
				zone.textContent = "収集完了！";
				status.textContent = `${TARGET_BITS}bit分のエントロピーを収集しました。`;

				btnGen.disabled = false;

				getSeed().then((d) => {
					keygenReduceNum = d.reduce((a, b) => a ^ b, 0);

					out.textContent = `Seed (SHA-256):\n${toHex(d)}`;

					btnGen.click();
				});
			}
		} else{
			status.textContent = getProcessingStatusText();
		}
	};

	const onMouse = (e) => {
		if(initialized){
			addEntropy(e.clientX|0, e.clientY|0);
		}
	};
	const onTouch = (e) => {
		if(initialized){
			for(const t of e.touches){
				addEntropy(t.clientX|0, t.clientY|0);
			}
		}
	};
	const onClick = (e) => {
		if(!initialized){
			initialized = true;

			zone.textContent = "ここで素早く動かす / クリック / タップ";
		} else{
			addEntropy((e.clientX ^ e.button)|0, (e.clientY ^ Date.now())|0);
		}
	};

	const guri2Reset = () => {
		POOL.fill(0);
		initialized = false;
		writeIdx = 0;
		collectedBits = 0;
		done = false;

		fill.style.width = '0%';
		status.textContent = getProcessingStatusText();
		zone.textContent = "クリック / タップで開始";
		out.textContent = "(Ungenerated)";

		// 非チェック時、必ず生成ボタンはenabled状態
		if(guriCheck.checked){
			btnGen.disabled = true;
		}
	};

	zone.addEventListener('mousemove', onMouse);
	zone.addEventListener('mousedown', onClick);
	zone.addEventListener('touchmove', onTouch, PASSIVE_TRUE);
	zone.addEventListener('touchstart', onTouch, PASSIVE_TRUE);

	btnReset.addEventListener('click', guri2Reset);
})();
