// Bun embeds the asset in the standalone CLI. Node reads it from the installed package.
import filename from '7z-wasm/7zz.wasm' with {type:'file'};
export default filename;
