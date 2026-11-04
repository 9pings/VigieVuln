'use strict';

const {createCacheRepository} = require('./cache-repository');

function load(cacheDir, key, fallback) {
  try { return createCacheRepository(cacheDir).get('auxiliary', key)?.value ?? fallback; }
  catch { return fallback; }
}

function save(cacheDir, key, value) {
  try {
    createCacheRepository(cacheDir).put('auxiliary', key, value, {
      fetchedAt: Number.isSafeInteger(value?.meta?.fetchedAt) && value.meta.fetchedAt > 0 ? value.meta.fetchedAt : Date.now(),
    });
  } catch { /* Optional cache. */ }
}

module.exports = {load, save};
