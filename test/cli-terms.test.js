'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {ensureSignedIn} = require('../lib/cli-project-commands');

const session = {token:'existing-session',expiresAt:Date.now()+60000};
const user = {id:'id',email:'user@example.test'};
const terms = {version:'v1',url:'https://www.vigievuln.fr/terms/v1',accepted:false};
function fixture({existing=true, accepted=false, answer='yes', interactive=true}={}) {
  let saved=existing?session:null;
  const calls=[], warnings=[];
  const store={read:()=>saved};
  const account={
    me:async()=>{calls.push('me');return {account:user,terms:{...terms,accepted}};},
    login:async()=>{calls.push('login');saved=session;return {account:user,terms:{...terms,accepted}};},
    acceptTerms:async version=>{calls.push(['accept',version]);},
  };
  const ask=async label=>{calls.push(label);return label.startsWith('Email')?'user@example.test':label.startsWith('Password')?'password':answer;};
  return {store,calls,warnings,run:()=>ensureSignedIn({account,store,ask,interactive,warn:x=>warnings.push(x)})};
}

test('already accepted terms do not prompt or submit consent', async()=>{
  const f=fixture({accepted:true});
  assert.deepEqual(await f.run(),{session,account:user});
  assert.deepEqual(f.calls,['me']);assert.deepEqual(f.warnings,[]);
});

for (const existing of [true,false]) test(`explicit acceptance follows ${existing?'existing session':'login'}`,async()=>{
  const f=fixture({existing});
  assert.deepEqual(await f.run(),{session,account:user});
  assert.deepEqual(f.calls.at(-1),['accept','v1']);
  assert.match(f.warnings.join('\n'),/https:\/\/www\.vigievuln\.fr\/terms\/v1/);
  assert.match(f.warnings.join('\n'),/v1/);
});

for (const answer of ['', 'no', 'y']) test(`answer ${JSON.stringify(answer)} does not accept terms`,async()=>{
  const f=fixture({answer});
  await assert.rejects(f.run(),/terms not accepted/);
  assert.deepEqual(f.store.read(),session);
  assert.ok(!f.calls.some(x=>Array.isArray(x)));
});

test('noninteractive pending terms fails explicitly and preserves the session',async()=>{
  const f=fixture({interactive:false});
  await assert.rejects(f.run(),/terms acceptance required.*vigievuln login/);
  assert.deepEqual(f.store.read(),session);
  assert.deepEqual(f.calls,['me']);
  assert.match(f.warnings.join('\n'),/\/terms/);
});
