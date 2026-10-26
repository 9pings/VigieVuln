/**
 * lib/ui.js — shared CLI presentation: banner, section headers, severity colors,
 * and a global step progress indicator for the cache/database update phase.
 *
 * The Progress indicator renders a "[n/N] <spinner> label — summary" checklist.
 * TTY: steps share one animated line; errors and intervening messages stay visible.
 * Non-TTY (pipes, CI, files): a single plain line per finished step, no escapes.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const chalk = require("chalk");
const { stripVTControlCharacters } = require("node:util");

// Leave the last column free so a progress update never wraps onto another row.
function fitLine(line) {
	const width = Math.max(1, (process.stdout.columns || 80) - 1);
	const plain = Array.from(stripVTControlCharacters(line));
	return plain.length > width ? plain.slice(0, width - 1).join("") + "…" : line;
}

const isTTY = !!(process.stdout && process.stdout.isTTY) && process.env.TERM !== "dumb";
const SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
// Non-TTY heartbeat interval. A step that queries one registry per dependency runs for
// minutes on a large reactor, and without an in-place spinner the log simply stops — which
// in CI is indistinguishable from a hang. One line per interval is enough to prove life
// without drowning the log.
const HEARTBEAT_MS = 15000;

/**
 * Pure: should a non-TTY step print a progress line now? Only when the counter actually
 * moved AND enough time has passed, so a fast step stays silent and a slow one does not.
 */
function shouldBeat(live, lastBeat, now, lastBeatAt, intervalMs = HEARTBEAT_MS) {
	if (!live || live === lastBeat) return false;
	return (now - lastBeatAt) >= intervalMs;
}

const TITLE_A = "VigieVuln";
const TITLE_B = "Autonomous Dependency Checker";

function banner(version) {
	const ver = version ? `v${version}` : "";
	const raw = `${TITLE_A} ${ver} · ${TITLE_B}`.replace("  ", " ");
	const bar = "─".repeat(raw.length + 2);
	console.log(chalk.cyan(`\n╭${bar}╮`));
	console.log(chalk.cyan("│ ") + chalk.bold.white(TITLE_A) + (ver ? " " + chalk.dim(ver) : "") + chalk.cyan(" · ") + chalk.whiteBright(TITLE_B) + chalk.cyan(" │"));
	console.log(chalk.cyan(`╰${bar}╯`));
}

function section(title) {
	console.log(chalk.bold.cyan("\n▸ ") + chalk.bold(title));
}

// "  label   value" aligned key/value line under a section.
function kv(label, value, { pad = 10 } = {}) {
	console.log("  " + chalk.dim(String(label).padEnd(pad)) + " " + value);
}

/**
 * Print a line while a spinner may be mid-render. The spinner owns the current line via \r,
 * so clear it first; its next tick redraws itself below. Used for retry notices, which must
 * survive in a CI log rather than flicker past inside the spinner's live suffix.
 */
function interject(msg) {
	if (isTTY) process.stdout.write("\r\x1b[K");
	console.log(msg);
}

function ok(msg) { console.log("  " + chalk.green("✓") + " " + msg); }
function warn(msg) { console.log("  " + chalk.yellow("⚠") + " " + msg); }
function info(msg) { console.log("  " + chalk.dim("·") + " " + msg); }

function sevColor(sev) {
	switch (String(sev || "").toUpperCase()) {
		case "CRITICAL": return chalk.bold.red;
		case "HIGH": return chalk.red;
		case "MEDIUM": return chalk.yellow;
		case "LOW": return chalk.blue;
		default: return chalk.gray;
	}
}

class Step {
	constructor(n, total, label, onEnd = null) {
		this.n = n; this.total = total; this.label = label; this.onEnd = onEnd;
		this.live = ""; this.frame = 0; this.timer = null; this.ended = false;
		this.lastBeat = ""; this.lastBeatAt = Date.now();
		this.prefix = chalk.dim(`[${n}/${total}]`);
		if (isTTY) {
			this._render();
			this.timer = setInterval(() => { this.frame++; this._render(); }, 80);
			if (this.timer.unref) this.timer.unref();
		}
	}
	_render() {
		if (!isTTY || this.ended) return;
		const sp = chalk.cyan(SPINNER[this.frame % SPINNER.length]);
		const live = this.live ? chalk.dim(" " + this.live) : chalk.dim(" …");
		process.stdout.write(`\r${fitLine(`  ${this.prefix} ${sp} ${this.label}${live}`)}\x1b[K`);
	}
	tick(processed, total) {
		this.live = total ? `(${processed} / ${total})` : String(processed || "");
		if (isTTY) return;   // the spinner timer already rewrites the line in place
		const now = Date.now();
		if (!shouldBeat(this.live, this.lastBeat, now, this.lastBeatAt)) return;
		this.lastBeat = this.live; this.lastBeatAt = now;
		console.log(`  ${this.prefix} ${chalk.dim("…")} ${this.label} ${chalk.dim(this.live)}`);
	}
	_finalize(symbol, color, summary) {
		if (this.ended) return;
		this.ended = true;
		if (this.timer) { clearInterval(this.timer); this.timer = null; }
		const line = `  ${this.prefix} ${color(symbol)} ${this.label}` + (summary ? chalk.dim(" — " + summary) : "");
		this.failed = symbol === "✗";
		if (isTTY) process.stdout.write(`\r${this.failed ? line : fitLine(line)}\x1b[K\n`);
		else console.log(line);
		if (this.onEnd) this.onEnd(this);
	}
	done(summary) { this._finalize("✓", chalk.green, summary); }
	skip(reason) { this._finalize("⊘", chalk.gray, reason); }
	fail(msg) { this._finalize("✗", chalk.red, msg); }
}

class Progress {
	// onStepEnd fires as each step finalises — the orchestrator uses it to stop the run the
	// moment a data source is declared unreachable, instead of after ten more minutes of steps.
	constructor(total, { onStepEnd = null } = {}) {
		this.total = total || 0; this.n = 0; this.onStepEnd = onStepEnd;
		this.lastOutput = null;
	}
	start(label) {
		// Reuse the completed row only if nothing else has been printed since.
		// Both streams matter: warnings/errors must never be erased by the next step.
		if (isTTY && this.lastOutput &&
			process.stdout.bytesWritten === this.lastOutput.stdout &&
			process.stderr.bytesWritten === this.lastOutput.stderr) {
			process.stdout.write("\x1b[1A\r\x1b[K");
		}
		this.lastOutput = null;
		this.n += 1;
		return new Step(this.n, this.total, label, step => {
			if (isTTY && !step.failed && Number.isFinite(process.stdout.bytesWritten)) {
				this.lastOutput = { stdout: process.stdout.bytesWritten, stderr: process.stderr.bytesWritten };
			}
			if (this.onStepEnd) this.onStepEnd(step);
		});
	}
}

module.exports = { banner, section, kv, ok, warn, info, interject, sevColor, Progress, shouldBeat, HEARTBEAT_MS, isTTY, TITLE_A, TITLE_B };
