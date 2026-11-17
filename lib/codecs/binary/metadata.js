// Format registry keeps new binary parsers independent of the walker.
const extractors = new Map([
 ['pe', (fd,size) => require('./pe-metadata').extractPeMetadataFile(fd,size)],
 ['elf', (fd,size,opts) => require('./elf-metadata').extractElfMetadataFile(fd,size,opts)],
]);
function extractMetadata(kind,fd,size,opts) { const fn=extractors.get(kind); return fn ? fn(fd,size,opts) : {format:kind,status:'unsupported'}; }
module.exports={extractors,extractMetadata};
