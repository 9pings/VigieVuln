'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { routeArguments } = require('../lib/cli-command-routing');
const CLI = path.join(__dirname, '../vigievuln.js');
const ID = '12345678-1234-1234-1234-123456789abc';
const OTHER = 'aaaaaaaa-1234-1234-1234-123456789abc';
const PROJECT = { id: ID, name: 'My Project', revision: 7 };

function fixture(t, settings = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-commands-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const src = path.join(home, 'private source'), capture = path.join(home, 'calls.jsonl');
  fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, 'package.json'), JSON.stringify({ name: 'secret-root', dependencies: { demo: '1.2.3', '@private/hidden': '2.0.0' } }));
  fs.mkdirSync(path.join(home, '.vigievuln'), { mode: 0o700 });
  const sessionFile = path.join(home, '.vigievuln/account-session.json');
  if (settings.session !== false) fs.writeFileSync(sessionFile, JSON.stringify({ token: 'account_session', expiresAt: settings.expired ? 1 : Date.now() + 3600000 }), { mode: 0o600 });
  const hook = path.join(home, 'mock.cjs');
  fs.writeFileSync(hook, `
    const fs=require('node:fs');const settings=${JSON.stringify(settings)};
    require('node:os').homedir=()=>${JSON.stringify(home)};
    for(const id of ['http','https']){const m=require(id);m.get=m.request=()=>{throw Error('external network forbidden')}}
    if(settings.tty){
      Object.defineProperty(process.stdin,'isTTY',{value:true});Object.defineProperty(process.stderr,'isTTY',{value:true});
      const answers=['person@example.test','private_password'];
      require('node:readline').createInterface=()=>({question:(_q,cb)=>cb(answers.shift()),close(){}});
    }
    if(settings.forbidSession){require(${JSON.stringify(path.join(__dirname, '../lib/account-session'))}).createAccountSessionStore=()=>{throw Error('session accessed during local export')};}
    globalThis.fetch=async(url,init={})=>{
      const request={url,method:init.method,body:init.body?JSON.parse(init.body):null};
      fs.appendFileSync(${JSON.stringify(capture)},JSON.stringify(request)+'\\n');
      if(settings.noNetwork)throw Error('network forbidden');
      if(url==='https://www.vigievuln.fr/v1/accounts/me')return settings.revoked?new Response('',{status:401}):Response.json({account:{id:'account',email:'person@example.test'}});
      if(url==='https://www.vigievuln.fr/v1/accounts/login')return Response.json({token:'new_session',tokenType:'Bearer',expiresAt:Date.now()+3600000,account:{id:'account',email:'person@example.test'}});
      if(url==='https://www.vigievuln.fr/v1/accounts/logout')return Response.json({revoked:1});
      if(url==='https://www.vigievuln.fr/v1/projects' && init.method==='GET')return Response.json({projects:settings.projects||[]});
      if(url==='https://www.vigievuln.fr/v1/projects/${ID}' && init.method==='GET')return Response.json({project:settings.current||${JSON.stringify(PROJECT)}});
      if(url==='https://www.vigievuln.fr/v1/projects' && init.method==='POST')return Response.json({project:{id:'${ID}',name:request.body.name,revision:1}});
      if(url==='https://www.vigievuln.fr/v1/projects/${ID}' && init.method==='PUT')return settings.conflict?new Response('',{status:409}):Response.json({project:{...${JSON.stringify(PROJECT)},revision:8}});
      throw Error('unexpected endpoint '+url);
    };`);
  return { home, src, sessionFile,
    calls: () => fs.existsSync(capture) ? fs.readFileSync(capture, 'utf8').trim().split('\n').map(JSON.parse) : [],
    run: args => spawnSync(process.execPath, [CLI, ...args], { cwd: home, encoding: 'utf8', timeout: 20000,
      env: { ...process.env, HOME: home, USERPROFILE: home, NODE_OPTIONS: `--require=${hook}`, VIGIEVULN_ENV: '', FAD_CHECKER_ENV: '', FORCE_COLOR: '0' } }) };
}
function success(run) { assert.equal(run.status, 0, `${run.error || ''}\n${run.stderr}\n${run.stdout}`); }
const writes = f => f.calls().filter(c => ['POST','PUT'].includes(c.method) && c.url.includes('/projects'));

test('routing preserves old argv and maps scan/config/cache/auth without consuming option values', () => {
  for (const args of [['-s','source','--offline'], ['serve-cache','--port','0'], ['--completion','bash'], ['project','status']])
    assert.deepEqual(routeArguments(args).args, args);
  assert.deepEqual(routeArguments(['scan','source path','--offline','--report-json','a.json']).args, ['--src','source path','--offline','--report-json','a.json']);
  assert.deepEqual(routeArguments(['scan','--src','source','--offline']).args, ['--src','source','--offline']);
  assert.deepEqual(routeArguments(['config','show']).args, ['--show-config']);
  assert.deepEqual(routeArguments(['cache','import','a.tar.gz','--replace','--force']).args, ['--import-cache','a.tar.gz','--replace','--force']);
  assert.deepEqual(routeArguments(['cache','export','a.tar.gz','--include-config']).args, ['--export-cache','a.tar.gz','--include-config']);
  for (const [cmd, alias] of [['login','login'],['logout','logout'],['whoami','status']]) assert.deepEqual(routeArguments([cmd]).args, ['auth',alias]);
  for (const args of [['scan','.','-s','other'],['scan','.','--source=other'],['cache','import'],['cache','export','out','--force'],['config','show','secret']]) assert.throws(() => routeArguments(args));
});

test('watch new project collects offline, then uploads sanitized inventory with a privacy warning', t => {
  const f = fixture(t);
  const run = f.run(['watch', f.src, '--name', 'My Project', '-e', '^@private']);
  success(run);
  assert.deepEqual(f.calls().map(c => [c.url.split('/v1/')[1],c.method]), [['accounts/me','GET'],['projects','GET'],['projects','POST']]);
  const body = writes(f)[0].body;
  assert.equal(body.name, 'My Project');
  assert.deepEqual(body.descriptor.deps.map(d => [d.name,d.version,d.relation]), [['demo','1.2.3','direct']]);
  assert.ok(!JSON.stringify(body).includes(f.src));
  assert.ok(!JSON.stringify(body).includes('secret-root'));
  assert.match(run.stderr, /private package names/);
  assert.doesNotMatch(run.stderr + run.stdout, /Register:|private_password/);
});

test('watch same unique name uses list revision CAS without rename; --id explicitly selects another name', t => {
  for (const explicit of [false,true]) {
    const f = fixture(t, { projects: [PROJECT] });
    success(f.run(['watch',f.src,...(explicit?['--id',ID]:['--name','My Project'])]));
    assert.equal(writes(f).length,1);
    assert.equal(writes(f)[0].method,'PUT');
    assert.equal(writes(f)[0].body.revision,7);
    assert.equal(writes(f)[0].body.name,undefined);
  }
});

for (const [label,projects] of [['other name',[{...PROJECT,name:'Other project'}]], ['ambiguous name',[PROJECT,{...PROJECT,id:OTHER}]], ['invalid revision',[{...PROJECT,revision:0}]]])
  test(`watch refuses ${label} before upload`, t => {
    const f = fixture(t,{projects});
    const run=f.run(['watch',f.src,'--name','My Project']);
    assert.equal(run.status,2);
    assert.equal(writes(f).length,0);
    assert.match(run.stderr,/--id|invalid project service response/);
  });

test('watch revision conflict is visible, never retries or creates a replacement', t => {
  const f=fixture(t,{projects:[PROJECT],conflict:true});
  const run=f.run(['watch',f.src,'--name','My Project']);
  assert.equal(run.status,2);assert.match(run.stderr,/revision conflict/);assert.equal(writes(f).length,1);
});

for (const mode of ['absent','expired','revoked']) test(`watch ${mode} session requires login in noninteractive mode, never uploads`, t => {
  const f=fixture(t,{session:mode!=='absent',expired:mode==='expired',revoked:mode==='revoked'});
  const run=f.run(['watch',f.src,'--name','My Project']);
  assert.equal(run.status,2);assert.match(run.stderr,/vigievuln login/);
  assert.doesNotMatch(run.stderr,/Register:/);assert.equal(writes(f).length,0);
  assert.equal(f.calls().length,mode==='revoked'?1:0);
});

for (const mode of ['absent','expired','revoked']) test(`watch ${mode} session can login in a terminal before upload`, t => {
  const f=fixture(t,{session:mode!=='absent',expired:mode==='expired',revoked:mode==='revoked',tty:true});
  const run=f.run(['watch',f.src,'--name','My Project']);success(run);
  assert.match(run.stderr,/Register:/);assert.equal(writes(f).length,1);
  assert.equal(f.calls().filter(c=>c.url.endsWith('/login')).length,1);
  assert.doesNotMatch(run.stdout+run.stderr,/private_password/);
});

for (const session of [false,true]) test(`watch export is local only, ignores session entirely (stored=${session})`, t => {
  const f=fixture(t,{session,noNetwork:true,forbidSession:true});
  const output=path.join(f.home,'review.json');
  const run=f.run(['watch',f.src,'--export',output,'--name','optional label']);success(run);
  assert.equal(f.calls().length,0);assert.match(run.stdout,/Nothing uploaded/);
  assert.match(run.stderr,/private package names/);assert.doesNotMatch(run.stderr,/Register:|login required/);
  assert.equal(JSON.parse(fs.readFileSync(output)).schema,'fad-deps/2');
  if(process.platform!=='win32')assert.equal(fs.statSync(output).mode&0o777,0o600);
  const original=fs.readFileSync(output,'utf8');
  assert.notEqual(f.run(['watch',f.src,'--export',output]).status,0);
  assert.equal(fs.readFileSync(output,'utf8'),original);
});

test('watch filters paths and keeps unknown dependencies visibly unknown without resolving them', t => {
  const f=fixture(t,{noNetwork:true});
  fs.mkdirSync(path.join(f.src,'private'));
  fs.writeFileSync(path.join(f.src,'private/package.json'),JSON.stringify({dependencies:{hidden:'9.9.9'}}));
  fs.writeFileSync(path.join(f.src,'pom.xml'),'<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>org.test</groupId><artifactId>unresolved</artifactId></dependency></dependencies></project>');
  const output=path.join(f.home,'review.json');
  const run=f.run(['watch',f.src,'--export',output,'--exclude-path','private']);success(run);
  const deps=JSON.parse(fs.readFileSync(output)).deps;
  assert.ok(!deps.some(d=>d.name==='hidden'));
  assert.ok(deps.some(d=>d.name==='unresolved' && d.version===null && d.relation==='unknown'));
  assert.match(run.stderr,/unknown relations.*excluded from monitoring/);assert.equal(f.calls().length,0);
});

test('watch rejects conflicting options and empty inventories without account traffic', t => {
  const f=fixture(t,{noNetwork:true});
  for(const options of [[],['--name','one','--id',ID],['--id','bad'],['--export','out','--id',ID],['--name','x','--bogus'],['--name','x','--ecosystem','bogus']]) {
    assert.notEqual(f.run(['watch',f.src,...options]).status,0);
  }
  fs.unlinkSync(path.join(f.src,'package.json'));
  const run=f.run(['watch',f.src,'--name','Empty']);
  assert.equal(run.status,2);assert.match(run.stderr,/empty project inventory/);assert.equal(f.calls().length,0);
});

for(const command of ['login','whoami','auth status','auth whoami']) test(`${command} checks an existing session without login/registration or proxy mutation`, t => {
  const f=fixture(t);const run=f.run(command.split(' '));success(run);
  assert.match(run.stdout,/Signed in as person@example.test/);assert.doesNotMatch(run.stderr,/Register:/);
  assert.deepEqual(f.calls().map(c=>c.url),['https://www.vigievuln.fr/v1/accounts/me']);
  assert.equal(fs.existsSync(path.join(f.home,'.fad-checker/config.json')),false);
});

test('logout and auth logout revoke and clear locally without asking to sign in', t => {
  for(const args of [['logout'],['auth','logout']]) {
    const f=fixture(t);success(f.run(args));assert.equal(fs.existsSync(f.sessionFile),false);
    success(f.run(args));assert.equal(f.calls().length,1);
  }
});

test('help documents local export, privacy, CAS and 100 distinct direct coordinates; completion remains intact', t => {
  const f=fixture(t,{noNetwork:true,forbidSession:true});
  for(const args of [['--help'],['scan','--help'],['watch','--help'],['login','--help'],['project','--help'],['cache','--help'],['config','--help']]) success(f.run(args));
  const help=f.run(['watch','--help']).stdout;
  for(const pattern of [/100 distinct direct coordinates/,/versions count once/,/Unknown relations/,/No vulnerability scan/,/no login, upload/,/revision/,/private package names/]) assert.match(help,pattern);
  assert.match(f.run(['--help']).stdout,/config show/);
  for(const shell of ['bash','zsh']) {
    const run=f.run(['--completion',shell]);success(run);
    assert.equal(run.stdout,fs.readFileSync(path.join(__dirname,'../completions',`vigievuln.${shell}`),'utf8'));
  }
  assert.equal(f.calls().length,0);
});

test('scan positional alias and legacy -s produce identical local project descriptors', t => {
  const f=fixture(t,{noNetwork:true});
  const files=['old.json','new.json'].map(file=>path.join(f.home,file));
  success(f.run(['-s',f.src,'--prepare-project',files[0]]));
  success(f.run(['scan',f.src,'--prepare-project',files[1]]));
  assert.deepEqual(JSON.parse(fs.readFileSync(files[0])),JSON.parse(fs.readFileSync(files[1])));
  assert.equal(f.calls().length,0);
});

test('config and cache aliases execute existing masked config and archive handlers offline', t => {
  const f=fixture(t,{noNetwork:true});
  const cache=path.join(f.home,'.fad-checker');fs.mkdirSync(cache);
  fs.writeFileSync(path.join(cache,'config.json'),JSON.stringify({proxyCacheToken:'secret-proxy'}));
  fs.writeFileSync(path.join(cache,'sample.json'),JSON.stringify({hello:'world'}));
  const shown=f.run(['config','show']);success(shown);assert.doesNotMatch(shown.stdout,/secret-proxy/);
  assert.equal(shown.stdout,f.run(['--show-config']).stdout);
  const archive=path.join(f.home,'cache.tar.gz');success(f.run(['cache','export',archive]));
  fs.unlinkSync(path.join(cache,'sample.json'));success(f.run(['cache','import',archive]));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(cache,'sample.json'))),{hello:'world'});
  assert.equal(f.calls().length,0);
});

for (const expired of [false,true]) test(`account commands require login for ${expired?'expired':'missing'} sessions without advertising registration`, t => {
  for(const args of [['login'],['whoami'],['auth','status'],['project','status']]) {
    const f=fixture(t,{session:expired,expired});
    const run=f.run(args);
    assert.equal(run.status,2);
    assert.match(run.stderr,/login required.*vigievuln login/);
    assert.doesNotMatch(run.stderr+run.stdout,/Register:/);
    assert.equal(f.calls().length,0);
  }
});

test('top-level login prompts only when necessary and persists an account session, not a proxy key', t => {
  const f=fixture(t,{session:false,tty:true});
  const first=f.run(['login']);success(first);assert.match(first.stderr,/Register:/);
  const stored=JSON.parse(fs.readFileSync(f.sessionFile));
  assert.deepEqual(Object.keys(stored).sort(),['expiresAt','token']);
  const second=f.run(['login']);success(second);assert.doesNotMatch(second.stderr,/Register:|Email:|Password:/);
  assert.deepEqual(f.calls().map(c=>c.url.split('/').pop()),['login','me']);
  assert.equal(fs.existsSync(path.join(f.home,'.fad-checker/config.json')),false);
});

test('legacy auth login and project status also prompt when a terminal needs authentication', t => {
  for(const args of [['auth','login'],['project','status']]) {
    const f=fixture(t,{session:false,tty:true});
    const run=f.run(args);success(run);assert.match(run.stderr,/Register:/);
    assert.equal(f.calls()[0].url,'https://www.vigievuln.fr/v1/accounts/login');
  }
});
