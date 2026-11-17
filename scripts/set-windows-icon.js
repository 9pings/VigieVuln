#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const ResEdit = require('resedit');

// Bun's native --windows-icon requires Windows. Update only its existing
// resource allocation so cross-builds retain every code/payload offset.
function resourcesFor(executable) {
  const section = executable.getSectionByEntry(2); // IMAGE_DIRECTORY_ENTRY_RESOURCE
  if (!section?.data) throw Error('Windows executable has no resource section');
  // resedit cannot resize resources followed by Bun's payload section. Parse
  // a resource-only view at the original RVA, then generate with noGrow=true.
  const view = ResEdit.NtExecutable.createEmpty(executable.is32bit());
  view.setSectionByEntry(2, {info:{...section.info}, data:section.data});
  view.getSectionByEntry(2).info.virtualAddress = section.info.virtualAddress;
  view.newHeader.optionalHeaderDataDirectory.set(2, {
    virtualAddress:section.info.virtualAddress, size:section.info.virtualSize,
  });
  return {section, resources:ResEdit.NtExecutableResource.from(view)};
}

function setWindowsIcon(filename, iconPath) {
  const binary = fs.readFileSync(filename);
  const executable = ResEdit.NtExecutable.from(binary);
  const {section, resources} = resourcesFor(executable);
  const icon = ResEdit.Data.IconFile.from(fs.readFileSync(iconPath));
  if (!icon.icons.length) throw Error('Windows icon contains no images');
  const groups = ResEdit.Resource.IconGroupEntry.fromEntries(resources.entries);
  for (const group of groups.length ? groups : [{id:1, lang:1033}]) {
    ResEdit.Resource.IconGroupEntry.replaceIconsForResource(
      resources.entries, group.id, group.lang, icon.icons.map(item => item.data),
    );
  }
  const data = resources.generateResourceData(section.info.virtualAddress, executable.getFileAlignment(), true);
  const start = section.info.pointerToRawData;
  if (data.bin.byteLength !== section.info.sizeOfRawData || start + data.bin.byteLength > binary.length)
    throw Error('Icon update would change the executable layout');
  Buffer.from(data.bin).copy(binary, start);
  // Parse the result before replacing the build output.
  const verified = resourcesFor(ResEdit.NtExecutable.from(binary)).resources;
  const saved = ResEdit.Resource.IconGroupEntry.fromEntries(verified.entries);
  if (!saved.length || saved.some(group => group.icons.length !== icon.icons.length))
    throw Error('Windows icon verification failed');
  const temporary = filename + '.icon.tmp';
  try {
    fs.writeFileSync(temporary, binary, {mode:fs.statSync(filename).mode});
    fs.renameSync(temporary, filename);
  } finally { fs.rmSync(temporary, {force:true}); }
  console.log(`VV icon embedded: ${filename} (${icon.icons.length} sizes)`);
}

if (require.main === module) {
  const filename = process.argv[2];
  if (!filename) throw Error('Usage: node scripts/set-windows-icon.js <executable> [icon.ico]');
  setWindowsIcon(filename, process.argv[3] || path.join(__dirname, '../docs/assets/vigievuln.ico'));
}
module.exports = {setWindowsIcon, resourcesFor};
