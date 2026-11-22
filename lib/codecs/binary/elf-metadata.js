// Parse file-backed ELF structures without executing the inspected file.
const fs = require('fs');
const MAX_SEGMENT = 32 * 1024 * 1024;
function extractElfMetadataFile(fd, size, options = {}) {
 try {
  const max = options.maxMetadataBytes || MAX_SEGMENT;
  function read(pos, n) {
   if (!Number.isSafeInteger(pos) || !Number.isSafeInteger(n) || pos < 0 || n < 0 || n > max || pos + n > size) throw Error('ELF bounds or metadata limit');
   const b = Buffer.alloc(n); let off = 0;
   while (off < n) { const got = fs.readSync(fd, b, off, n - off, pos + off); if (!got) throw Error('ELF truncated'); off += got; }
   return b;
  }
  const h = read(0, 16);
  if (!h.subarray(0, 4).equals(Buffer.from([127,69,76,70])) || ![1,2].includes(h[4]) || ![1,2].includes(h[5])) throw Error('unsupported ELF class or byte order');
  const bits = h[4] === 1 ? 32 : 64, le = h[5] === 1;
  const u16 = (b,p) => le ? b.readUInt16LE(p) : b.readUInt16BE(p);
  const u32 = (b,p) => le ? b.readUInt32LE(p) : b.readUInt32BE(p);
  const word = (b,p) => { const v = bits === 32 ? BigInt(u32(b,p)) : le ? b.readBigUInt64LE(p) : b.readBigUInt64BE(p); if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('ELF integer exceeds safe range'); return Number(v); };
  const header = read(0, bits === 32 ? 52 : 64);
  const phoff = word(header, bits === 32 ? 28 : 32), phentsize = u16(header, bits === 32 ? 42 : 54), phnum = u16(header, bits === 32 ? 44 : 56);
  if (phnum > 4096 || (phnum && phentsize < (bits === 32 ? 32 : 56))) throw Error('unsupported ELF program header table');
  const table = read(phoff, phnum * phentsize), segments = [];
  for (let i = 0; i < phnum; i++) { const p = i * phentsize; const type = u32(table,p), flags = u32(table,p + (bits === 32 ? 24 : 4)); const offset = word(table,p + (bits === 32 ? 4 : 8)), vaddr = word(table,p + (bits === 32 ? 8 : 16)), filesz = word(table,p + (bits === 32 ? 16 : 32)); if (offset + filesz > size) throw Error('ELF segment outside file'); segments.push({ type, flags, offset, vaddr, filesz }); }
  const mapped = (addr,n) => { const s = segments.find(x => x.type === 1 && addr >= x.vaddr && addr - x.vaddr + n <= x.filesz); if (!s) throw Error('ELF unmapped address'); return s.offset + addr - s.vaddr; };
  const result = { format:'elf', bits, endian: le ? 'little' : 'big', machine: u16(header,18), type: u16(header,16), needed: [] };
  const interp = segments.find(s => s.type === 3); if (interp && interp.filesz) result.interpreter = read(interp.offset,interp.filesz).toString('utf8').replace(/\0.*$/s,'');
  for (const s of segments.filter(x => x.type === 4)) {
   const b = read(s.offset,s.filesz); let p = 0;
   while (p + 12 <= b.length) { const namesz = u32(b,p), descsz = u32(b,p+4), type = u32(b,p+8); p += 12; const a = Math.ceil(namesz/4)*4, d = Math.ceil(descsz/4)*4; if (p + a + d > b.length) break; if (type === 3 && b.subarray(p,p+namesz).toString('ascii').replace(/\0+$/,'') === 'GNU' && descsz <= 1024) result.buildId = b.subarray(p+a,p+a+descsz).toString('hex'); p += a+d; }
  }
  const dynamic = segments.find(s => s.type === 2);
  if (dynamic) {
   const b = read(dynamic.offset,dynamic.filesz), step = bits === 32 ? 8 : 16; let str = null, strsz = null, soname = null; const needed=[];
   for (let p=0; p+step<=b.length; p+=step) { const tag=word(b,p), val=word(b,p+step/2); if (!tag) break; if(tag===5) str=val; else if(tag===10) strsz=val; else if(tag===1) needed.push(val); else if(tag===14) soname=val; }
   if (str !== null && strsz !== null && strsz <= max) { const strings=read(mapped(str,strsz),strsz); const get = n => { if(n>=strings.length) throw Error('ELF string offset'); const end=strings.indexOf(0,n); if(end<0) throw Error('ELF unterminated string'); return strings.toString('utf8',n,end); }; result.needed=needed.map(get); if(soname!==null) result.soname=get(soname); }
  }
  result.go = require('./go-buildinfo').extractGoBuildInfo({read, segments, mapped, max});
  if (!result.go) delete result.go;
  if (options.imageBinaryName) {
   try {
    const products = require('../../artifacts/elf-product').embeddedProducts(options.imageBinaryName, {read, header, size, bits, word, u16, u32, mapped, max, segments, machine:result.machine, soname:result.soname});
    if (products.length) result.products = products;
   } catch { result.productReadError = true; }
  }
  return result;
 } catch (error) { return { format:'elf', status:'unavailable', reason:error.message }; }
}
module.exports = { extractElfMetadataFile, MAX_SEGMENT };
