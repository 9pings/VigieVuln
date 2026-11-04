'use strict';

const fs = require('node:fs');
const path = require('node:path');

function openSqlite(file, {readonly = false} = {}) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), {recursive:true, mode:0o700});
  const db = typeof Bun !== 'undefined'
    ? new (require('bun:sqlite').Database)(file, {readonly, create:!readonly})
    : new (require('node:sqlite').DatabaseSync)(file, {readOnly:readonly});
  db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
  if (!readonly) db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
  const statements=new Map();
  const prepared=new Set();
  const prepare = sql => {
    let statement=statements.get(sql);
    if (!statement) {
      statement=db.prepare(sql);
      if(typeof Bun !== 'undefined') prepared.add(statement);
      if (statements.size>=128) statements.delete(statements.keys().next().value);
      statements.set(sql,statement);
    }
    return statement;
  };
  return {
    // Bun's default close defers releasing the file while prepared statements
    // exist. Finalize them immediately so Windows can rename/delete the cache.
    file, prepare, exec:sql=>db.exec(sql), close:()=>{
      statements.clear();
      if(typeof Bun !== 'undefined') for(const statement of prepared) statement.finalize();
      prepared.clear();
      if(typeof Bun !== 'undefined') db.close(true); else db.close();
    },
    transaction(action) {
      db.exec('BEGIN IMMEDIATE');
      try {
        const result=action();
        if (result && typeof result.then === 'function') throw new Error('SQLite transaction callback must be synchronous');
        db.exec('COMMIT'); return result;
      }
      catch(error) { try { db.exec('ROLLBACK'); } catch {} throw error; }
    },
  };
}

module.exports = {openSqlite};
