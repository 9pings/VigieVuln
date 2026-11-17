/**
 * lib/codecs/binary/sniff.js — file-type confirmation for the binary codec.
 *
 * ELF is identified by magic irrespective of filename. PE and Mach-O retain
 * extension and magic confirmation, avoiding ambiguous signatures.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

// Format detectors are ordered; extensions remain hints for formats whose
// signatures can overlap other file types (notably Mach-O fat binaries).
const detectors = [
 { kind: "pe", matches: b => b[0] === 0x4d && b[1] === 0x5a },
 { kind: "elf", matches: b => b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46 },
 { kind: "zip", matches: b => b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04 },
 { kind: "macho", matches: b => {
   const signatures = [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcafebabf];
   return signatures.includes(b.readUInt32BE(0)) || signatures.includes(b.readUInt32LE(0));
 } },
];
function sniffKind(buf) {
 if (!buf || buf.length < 4) return null;
 return detectors.find(d => d.matches(buf))?.kind || null;
}

const EXT_PE = /\.(dll|exe)$/i;
const EXT_MACHO = /\.dylib$/i;
const EXT_ELF = /\.so(\.\d+)*$/i;   // .so, .so.1, .so.1.2.3

function extKind(name) {
	if (EXT_PE.test(name)) return "pe";
	if (EXT_MACHO.test(name)) return "macho";
	if (EXT_ELF.test(name)) return "elf";
	return null;
}

module.exports = { sniffKind, extKind, detectors };
