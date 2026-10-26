// script(1) classic capture  ->  asciicast v2
// The CLI output is unchanged; playback is paced to make fast cached steps readable.
const fs = require("fs");
const [raw, out, colsS, rowsS] = process.argv.slice(2);
const cols = +colsS, rows = +rowsS;
let output = fs.readFileSync(raw, "utf8");
// util-linux script adds a header/footer which are not part of the CLI output.
output = output.replace(/^Script started on [^\n]*\n/, "")
	.replace(/\nScript done on [\s\S]*$/, "");

const CMD = "vigievuln -s test/fixtures/private-lib-detection --offline --no-report";
const PROMPT = "\u001b[38;5;114m❯\u001b[0m ";
const ev = [];
let t = 0;
const push = (dt, s) => { t += dt; ev.push([+t.toFixed(6), "o", s]); };

push(0.4, PROMPT);
for (const ch of CMD) push(0.04, ch);   // typing
push(0.55, "\r\n");                                               // Enter

// Each cursor-up starts the next step on the same terminal row. Add a short
// reading pause between steps and before Results; no delay is added to the CLI.
const blocks = output.split(/(?=\x1b\[1A\r\x1b\[K|\x1b\[1m\x1b\[36m)/);
for (const block of blocks) {
	if (block) push(0.4, block);
}

// Tokyo Night — the palette the previous demo.gif used.
const THEME = {
	fg: "#c0caf5", bg: "#1a1b26",
	palette: ["#15161e", "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#a9b1d6",
		"#414868", "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#c0caf5"].join(":"),
};
const header = { version: 2, width: cols, height: rows, timestamp: Math.floor(Date.now() / 1000), theme: THEME, env: { TERM: "xterm-256color", SHELL: "/bin/bash" } };
fs.writeFileSync(out, JSON.stringify(header) + "\n" + ev.map(e => JSON.stringify(e)).join("\n") + "\n", "utf8");
console.log(`events=${ev.length} duration=${t.toFixed(2)}s bytes=${Buffer.byteLength(output)}`);
