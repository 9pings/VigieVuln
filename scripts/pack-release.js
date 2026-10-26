#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const out = path.join(root, "dist");
fs.mkdirSync(out, { recursive: true });
const npm = process.env.npm_execpath ? process.execPath : "npm";
const npmArgs = process.env.npm_execpath ? [process.env.npm_execpath] : [];
if (process.platform === "win32" && !npmArgs.length) throw new Error("Use npm pack from cli/ on Windows, or run this helper on Linux/macOS");
const archives = [];
{
  const pkg = require(path.join(root, "package.json"));
  const [packed] = JSON.parse(execFileSync(npm, [...npmArgs, "pack", ".", "--json", "--ignore-scripts", "--pack-destination", out], { cwd: root, encoding: "utf8" }));
  for (const file of packed.files) {
    if (/(^|\/)(node_modules|test)(\/|$)|(^|\/)\.env$|\.(?:db|pem|log)$/.test(file.path)) throw new Error(`Unexpected packaged file: ${file.path}`);
  }
  const filename = path.join(out, packed.filename);
  archives.push(`${crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex")}  ${packed.filename}`);
  console.log(`${pkg.name}@${pkg.version}: ${packed.filename} (${packed.entryCount} files)`);
}
fs.writeFileSync(path.join(out, "SHA256SUMS"), archives.join("\n") + "\n");
