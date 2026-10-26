const test = require("node:test");
const assert = require("node:assert");
const ui = require("../lib/ui");

// Capture everything written to stdout while running `fn`.
function capture(fn) {
	const chunks = [];
	const origWrite = process.stdout.write;
	const origLog = console.log;
	process.stdout.write = (s) => { chunks.push(String(s)); return true; };
	console.log = (...a) => { chunks.push(a.join(" ") + "\n"); };
	try { fn(); } finally { process.stdout.write = origWrite; console.log = origLog; }
	// strip ANSI for assertions
	return chunks.join("").replace(/\x1b\[[0-9;]*m/g, "");
}

test("sevColor maps severities to distinct chalk fns", () => {
	assert.strictEqual(typeof ui.sevColor("CRITICAL"), "function");
	assert.notStrictEqual(ui.sevColor("CRITICAL"), ui.sevColor("LOW"));
	// applying it returns a string containing the input
	assert.match(ui.sevColor("HIGH")("HIGH"), /HIGH/);
});

test("banner / section / ok / warn / info render without throwing", () => {
	const out = capture(() => {
		ui.banner();
		ui.section("Collection");
		ui.ok("done");
		ui.warn("careful");
		ui.info("note");
		ui.kv("source", "/x");
	});
	assert.match(out, /VigieVuln/);
	assert.match(out, /▸ Collection/);
	assert.match(out, /done/);
});

test("Progress emits [n/N] step lines finalized with ✓ / ⊘ (non-TTY)", () => {
	const out = capture(() => {
		const p = new ui.Progress(2);
		const a = p.start("first"); a.tick(1, 2); a.done("ok");
		const b = p.start("second"); b.skip("nope");
	});
	assert.match(out, /\[1\/2\][^\n]*✓[^\n]*first[^\n]*ok/);
	assert.match(out, /\[2\/2\][^\n]*⊘[^\n]*second[^\n]*nope/);
});

test("Progress.fail marks a step with ✗ and the message", () => {
	const out = capture(() => {
		const p = new ui.Progress(1);
		p.start("boom").fail("kaboom");
	});
	assert.match(out, /\[1\/1\][^\n]*✗[^\n]*boom[^\n]*kaboom/);
});

// ---- non-TTY progress heartbeat ----
// A registry-per-dependency step runs for minutes on a large reactor. In a TTY the spinner
// rewrites one line; with output redirected (CI, `> run.log`) nothing was printed at all
// until the step finished, so a working scan looked exactly like a hung one.
const { shouldBeat } = require("../lib/ui");

test("stays silent until the interval has passed", () => {
	assert.strictEqual(shouldBeat("5/400", "", 1000, 0, 15000), false);
});

test("beats once the counter moved and the interval elapsed", () => {
	assert.strictEqual(shouldBeat("120/400", "5/400", 20000, 0, 15000), true);
});

test("does not repeat the same count — a stalled step must not look busy", () => {
	assert.strictEqual(shouldBeat("120/400", "120/400", 99000, 0, 15000), false);
});

test("nothing to say when there is no count yet", () => {
	assert.strictEqual(shouldBeat("", "", 99000, 0, 15000), false);
});

test("the live counter reads as (done / total)", () => {
	// The step showed a bare spinner with no numbers: outdated only called tick() on every
	// 10th completion and never announced the total, so on a cold cache the first count
	// appeared only after the 10th dependency came back.
	const { Progress } = require("../lib/ui");
	const p = new Progress(1);
	const st = p.start("x");
	st.tick(0, 193);
	assert.strictEqual(st.live, "(0 / 193)");
	st.tick(47, 193);
	assert.strictEqual(st.live, "(47 / 193)");
	st.done("");
});
