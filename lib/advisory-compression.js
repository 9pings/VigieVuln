'use strict';

const zlib = require('node:zlib');
const { DICTIONARY } = require('./compression-dictionary');

const MAX_BYTES = 16 * 1024 * 1024;

function compress(bytes) {
  if (bytes.length < 1 || bytes.length > MAX_BYTES) throw new Error('advisory body exceeds SQLite cache limit');
  return zlib.deflateRawSync(bytes, { level: 1, dictionary: DICTIONARY });
}

function decompress(compressed, expectedBytes) {
  if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 1 || expectedBytes > MAX_BYTES) {
    throw new Error('invalid advisory body size');
  }
  const body = zlib.inflateRawSync(Buffer.from(compressed), {
    dictionary: DICTIONARY,
    maxOutputLength: expectedBytes,
  });
  if (body.length !== expectedBytes) throw new Error('advisory body size mismatch');
  return body;
}

module.exports = { compress, decompress };
