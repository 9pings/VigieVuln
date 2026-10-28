'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createAccountSessionStore, validateAccountSession } = require('../lib/account-session');

const NOW = 1800000000000;
const SESSION = { token: 'fad_account-session', expiresAt: NOW + 60000 };
const posix = { skip: typeof process.getuid !== 'function' };

function fixture(t, fsImpl = fs) {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-account-'));
  t.after(() => fs.rmSync(homeDir, { recursive: true, force: true }));
  const store = createAccountSessionStore({ homeDir, fsImpl, now: () => NOW });
  return { homeDir, store, directory: path.dirname(store.filePath) };
}

test('session path is distinct from proxy config; absent reads/clears do not create files', posix, t => {
  const { homeDir, store } = fixture(t);
  assert.equal(store.filePath, path.join(homeDir, '.vigievuln', 'account-session.json'));
  assert.equal(store.read(), null);
  store.clear();
  store.clear();
  assert.deepEqual(fs.readdirSync(homeDir), []);
  assert.equal(createAccountSessionStore().filePath, path.join(os.homedir(), '.vigievuln', 'account-session.json'));
});

test('only session and expiry persist, in a 0700 directory and an atomic 0600 file', posix, t => {
  const { homeDir, store, directory } = fixture(t);
  fs.mkdirSync(path.join(homeDir, '.vigie-vuln'));
  const proxyPath = path.join(homeDir, '.vigie-vuln', 'config.json');
  const proxyConfig = '{"proxyCacheToken":"separate-proxy-secret"}';
  fs.writeFileSync(proxyPath, proxyConfig);
  store.write({ ...SESSION, password: 'never-save', email: 'private@example.test', proxyCacheToken: 'never-save', account: {} });
  assert.deepEqual(JSON.parse(fs.readFileSync(store.filePath)), SESSION);
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(store.filePath).mode & 0o777, 0o600);
  assert.deepEqual(store.read(), SESSION);
  const previousInode = fs.statSync(store.filePath).ino;
  store.write({ ...SESSION, token: 'replacement' });
  assert.notEqual(fs.statSync(store.filePath).ino, previousInode);
  assert.equal(store.read().token, 'replacement');
  assert.deepEqual(fs.readdirSync(directory), ['account-session.json']);
  store.clear();
  assert.equal(store.read(), null);
  assert.equal(fs.readFileSync(proxyPath, 'utf8'), proxyConfig);
});

test('invalid sessions fail before any file is written; token header injection is refused', posix, t => {
  const { homeDir, store } = fixture(t);
  for (const value of [null, [], {}, { ...SESSION, token: '' }, { ...SESSION, token: 'secret\r\nx-header: injected' },
    { ...SESSION, token: 'x'.repeat(201) }, { ...SESSION, expiresAt: String(SESSION.expiresAt) },
    { ...SESSION, expiresAt: Infinity }, { ...SESSION, expiresAt: NaN }, { ...SESSION, expiresAt: 1.5 },
    { ...SESSION, expiresAt: NOW }, { ...SESSION, expiresAt: NOW - 1 }]) {
    assert.throws(() => store.write(value), error => ['INVALID_SESSION', 'SESSION_EXPIRED'].includes(error.code));
  }
  assert.deepEqual(fs.readdirSync(homeDir), []);
  assert.deepEqual(validateAccountSession(SESSION, NOW), SESSION);
});

test('expired sessions are removed at the exact expiry boundary', posix, t => {
  const { homeDir, store } = fixture(t);
  store.write(SESSION);
  const expired = createAccountSessionStore({ homeDir, now: () => SESSION.expiresAt });
  assert.equal(expired.read(), null);
  assert.equal(fs.existsSync(store.filePath), false);
});

test('corrupt, malformed and oversized session files never expose their contents', posix, t => {
  const { store } = fixture(t);
  store.write(SESSION);
  for (const contents of ['secret-password-not-json', 'null', '[]', '{"token":"secret-password"}', 'x'.repeat(4097)]) {
    fs.writeFileSync(store.filePath, contents);
    assert.throws(() => store.read(), error => {
      assert.equal(error.code, 'INVALID_SESSION');
      assert.doesNotMatch(error.stack, /secret-password/);
      return true;
    });
  }
  store.clear();
});

test('insecure permissions and special file types are rejected without fixing them silently', posix, t => {
  const { store, directory } = fixture(t);
  store.write(SESSION);
  fs.chmodSync(store.filePath, 0o644);
  for (const action of [() => store.read(), () => store.write(SESSION), () => store.clear()]) {
    assert.throws(action, { code: 'UNSAFE_SESSION_FILE' });
  }
  fs.chmodSync(store.filePath, 0o600);
  fs.chmodSync(directory, 0o755);
  assert.throws(() => store.read(), { code: 'UNSAFE_SESSION_FILE' });
  assert.throws(() => store.write(SESSION), { code: 'UNSAFE_SESSION_FILE' });
  fs.chmodSync(directory, 0o700);
  store.clear();
  fs.mkdirSync(store.filePath, { mode: 0o600 });
  assert.throws(() => store.read(), { code: 'UNSAFE_SESSION_FILE' });
});

test('file symlinks, dangling symlinks and hard links cannot be read, replaced or deleted', posix, t => {
  const { homeDir, store } = fixture(t);
  store.write(SESSION);
  store.clear();
  const target = path.join(homeDir, 'target');
  fs.writeFileSync(target, 'untouched', { mode: 0o600 });
  for (const type of ['symlink', 'dangling', 'hardlink']) {
    if (type === 'hardlink') fs.linkSync(target, store.filePath);
    else fs.symlinkSync(type === 'dangling' ? target + '-missing' : target, store.filePath);
    for (const action of [() => store.read(), () => store.write(SESSION), () => store.clear()]) {
      assert.throws(action, { code: 'UNSAFE_SESSION_FILE' });
    }
    fs.unlinkSync(store.filePath);
    assert.equal(fs.readFileSync(target, 'utf8'), 'untouched');
  }
});

test('a symlinked storage directory cannot redirect credentials into the proxy cache', posix, t => {
  const { homeDir, store, directory } = fixture(t);
  const proxy = path.join(homeDir, '.vigie-vuln');
  fs.mkdirSync(proxy, { mode: 0o700 });
  fs.symlinkSync(proxy, directory);
  for (const action of [() => store.read(), () => store.write(SESSION), () => store.clear()]) {
    assert.throws(action, { code: 'UNSAFE_SESSION_FILE' });
  }
  assert.deepEqual(fs.readdirSync(proxy), []);
});

test('foreign ownership and unsafe opened descriptors are refused', posix, t => {
  const { homeDir, store } = fixture(t);
  store.write(SESSION);
  for (const method of ['lstatSync', 'fstatSync']) {
    const fsImpl = { ...fs, [method](...args) {
      const stat = fs[method](...args);
      stat.uid = process.getuid() + 1;
      return stat;
    } };
    const unsafe = createAccountSessionStore({ homeDir, fsImpl, now: () => NOW });
    assert.throws(() => unsafe.read(), { code: 'UNSAFE_SESSION_FILE' });
    assert.throws(() => unsafe.write(SESSION), { code: 'UNSAFE_SESSION_FILE' });
  }
});

test('write, sync and rename failures preserve the previous session and remove temporary files', posix, t => {
  const { homeDir, store, directory } = fixture(t);
  store.write(SESSION);
  for (const method of ['writeFileSync', 'fsyncSync', 'renameSync']) {
    const fsImpl = { ...fs, [method]() { throw new Error('secret-from-filesystem'); } };
    const broken = createAccountSessionStore({ homeDir, fsImpl, now: () => NOW });
    assert.throws(() => broken.write({ ...SESSION, token: 'replacement' }), error => {
      assert.equal(error.code, 'SESSION_IO');
      assert.doesNotMatch(error.stack, /secret-from-filesystem/);
      return true;
    });
    assert.deepEqual(store.read(), SESSION);
    assert.deepEqual(fs.readdirSync(directory), ['account-session.json']);
  }
});

test('permission failures reading or clearing are reported, never treated as absent sessions', posix, t => {
  const { homeDir, store } = fixture(t);
  store.write(SESSION);
  for (const [method, operation] of [['openSync', 'read'], ['unlinkSync', 'clear']]) {
    const fsImpl = { ...fs, [method]() { throw Object.assign(new Error('secret'), { code: 'EACCES' }); } };
    const broken = createAccountSessionStore({ homeDir, fsImpl, now: () => NOW });
    assert.throws(() => broken[operation](), { code: 'SESSION_IO' });
  }
  assert.deepEqual(store.read(), SESSION);
});

function simulatedWindows(options = {}) {
  const calls = [];
  let saved = null;
  const store = createAccountSessionStore({
    platform: 'win32', homeDir: 'C:\\Users\\test', windowsRoot: 'C:\\Windows', now: () => NOW,
    fsImpl: new Proxy({}, { get() { assert.fail('Windows must not fall back to POSIX filesystem operations'); } }),
    spawnSyncImpl(executable, args, settings) {
      const [source, ...request] = settings.input.split('\n');
      const data = JSON.parse(request.join('\n'));
      calls.push({ executable, args, settings, source, data });
      if (data.operation === 'write') saved = data.session;
      if (data.operation === 'clear') saved = null;
      return { status: 0, stdout: JSON.stringify({ value: data.operation === 'read' ? saved : null }) };
    },
    ...options,
  });
  return { store, calls };
}

test('simulated Windows uses a fixed native bridge; credentials never enter argv or compiled source', () => {
  const homeDir = 'C:\\Users\\O\'Brien; $(throw "injected") & é';
  const { store, calls } = simulatedWindows({ homeDir });
  assert.equal(store.filePath, path.win32.join(homeDir, '.vigievuln', 'account-session.json'));
  assert.equal(store.read(), null);
  store.clear();
  store.write({ ...SESSION, password: 'never-save', email: 'private@example.test', account: {}, proxyCacheToken: 'proxy-secret' });
  assert.deepEqual(store.read(), SESSION);
  store.write({ ...SESSION, token: 'replacement' });
  assert.equal(store.read().token, 'replacement');
  store.clear();
  assert.equal(store.read(), null);
  for (const call of calls) {
    assert.equal(call.executable, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    assert.deepEqual(call.args, calls[0].args);
    assert.equal(call.source, calls[0].source);
    assert.equal(call.settings.shell, false);
    assert.equal(call.settings.windowsHide, true);
    assert.equal(call.settings.cwd, 'C:\\Windows');
    assert.equal(call.settings.timeout, 15000);
    assert.equal(call.settings.maxBuffer, 16384);
    assert.equal(call.settings.env, undefined);
    assert.equal(call.data.homeDir, homeDir);
    assert.deepEqual(Object.keys(call.data).sort(), call.data.operation === 'write' ? ['homeDir', 'operation', 'session'] : ['homeDir', 'operation']);
    const code = Buffer.from(call.source, 'base64').toString('utf8') +
      Buffer.from(call.args.at(-1), 'base64').toString('utf16le');
    assert.ok(!code.includes(homeDir));
    assert.doesNotMatch(code + JSON.stringify(call.args), /fad_account-session|never-save|private@example|proxy-secret/);
    assert.doesNotMatch(call.settings.input, /never-save|private@example|proxy-secret/);
  }
  assert.deepEqual(JSON.parse(calls.find(c => c.data.operation === 'write').data.session), SESSION);
});

test('simulated Windows rejects invalid writes before launching any process', () => {
  const { store, calls } = simulatedWindows();
  for (const value of [null, [], {}, { ...SESSION, token: 'bad\r\ninjected' }, { ...SESSION, expiresAt: NOW },
    { ...SESSION, token: 'x'.repeat(201) }, { ...SESSION, expiresAt: String(SESSION.expiresAt) }]) {
    assert.throws(() => store.write(value), error => ['INVALID_SESSION', 'SESSION_EXPIRED'].includes(error.code));
  }
  assert.equal(calls.length, 0);
});

test('simulated Windows revalidates decrypted sessions and clears at the expiry boundary', () => {
  const operations = [];
  let value = { ...SESSION, expiresAt: NOW };
  const { store } = simulatedWindows({ spawnSyncImpl(_exe, _args, settings) {
    const request = JSON.parse(settings.input.split('\n')[1]);
    operations.push(request.operation);
    return { status: 0, stdout: JSON.stringify({ value: request.operation === 'read' ? JSON.stringify(value) : null }) };
  } });
  assert.equal(store.read(), null);
  assert.deepEqual(operations, ['read', 'clear']);
  for (value of [null, [], {}, { ...SESSION, token: 'bad\nsecret' }]) {
    assert.throws(() => store.read(), { code: 'INVALID_SESSION' });
  }
  value = { ...SESSION, password: 'never-save' };
  assert.deepEqual(store.read(), SESSION);
  assert.equal(operations.filter(op => op === 'clear').length, 1);
});

test('simulated Windows fails closed on native errors and never exposes child output or secrets', () => {
  const secret = 'private-path-and-secret-token';
  const failures = [
    undefined, { status: 1, stdout: secret, stderr: secret }, { status: null, signal: 'SIGTERM', stdout: secret },
    { status: 0, error: Object.assign(new Error(secret), { code: 'ETIMEDOUT' }), stdout: secret },
    ...[secret, '{}', 'null', '[]', '{"value":{}}', '{"error":"toString"}', '{"error":"private-path-and-secret-token"}',
      JSON.stringify({ value: null }) + ' '.repeat(16384)].map(stdout => ({ status: 0, stdout })),
  ];
  for (const result of failures) {
    const { store } = simulatedWindows({ spawnSyncImpl() { return result; } });
    for (const action of [() => store.read(), () => store.write(SESSION), () => store.clear()]) {
      assert.throws(action, error => {
        assert.equal(error.code, 'SESSION_IO');
        assert.doesNotMatch(error.stack + JSON.stringify(error), new RegExp(secret));
        return true;
      });
    }
  }
  const { store } = simulatedWindows({ spawnSyncImpl() { throw new Error(secret); } });
  assert.throws(() => store.read(), error => error.code === 'SESSION_IO' && !error.stack.includes(secret));
  for (const code of ['UNSAFE_SESSION_FILE', 'INVALID_SESSION', 'WINDOWS_SESSION_UNAVAILABLE', 'SESSION_IO']) {
    const { store } = simulatedWindows({ spawnSyncImpl() { return { status: 0, stdout: JSON.stringify({ error: code, detail: secret }) }; } });
    for (const action of [() => store.read(), () => store.write(SESSION), () => store.clear()]) {
      assert.throws(action, error => error.code === code && !error.stack.includes(secret));
    }
  }
});

test('simulated Windows refuses an untrusted executable search location and propagates expired-session cleanup errors', () => {
  for (const windowsRoot of ['', 'Windows', '\\\\server\\Windows', 'C:\\..\\Windows', 'C:\\Windows\n']) {
    const { store, calls } = simulatedWindows({ windowsRoot });
    assert.throws(() => store.write(SESSION), { code: 'WINDOWS_SESSION_UNAVAILABLE' });
    assert.equal(calls.length, 0);
  }
  const { store } = simulatedWindows({ spawnSyncImpl(_exe, _args, settings) {
    const request = JSON.parse(settings.input.split('\n')[1]);
    return { status: 0, stdout: JSON.stringify(request.operation === 'read' ?
      { value: JSON.stringify({ ...SESSION, expiresAt: NOW }) } : { error: 'SESSION_IO' }) };
  } });
  assert.throws(() => store.read(), { code: 'SESSION_IO' });
});

// Real native tests run on Windows. WSL can opt in with the absolute path to
// Windows PowerShell (not Linux pwsh); nothing is installed or downloaded.
const nativePowerShell = process.platform === 'win32'
  ? path.win32.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  : process.env.VV_TEST_WINDOWS_POWERSHELL;
const native = { skip: !nativePowerShell };

function nativeCommand(script, input = '') {
  const result = spawnSync(nativePowerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
    Buffer.from("$ErrorActionPreference = 'Stop'; [Console]::InputEncoding = New-Object Text.UTF8Encoding($false, $true); [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false, $true); " + script, 'utf16le').toString('base64')],
  { input, encoding: 'utf8', shell: false, windowsHide: true, timeout: 15000, maxBuffer: 16384 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

function nativeFixture(t, suffix = '') {
  const config = JSON.parse(nativeCommand(`
    $suffix = [Console]::In.ReadToEnd()
    $p = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'vv-session-' + $suffix + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($p)
    [Console]::Write((@{homeDir=$p; windowsRoot=$env:SystemRoot} | ConvertTo-Json -Compress))
  `, suffix));
  t.after(() => nativeCommand('[IO.Directory]::Delete([Console]::In.ReadToEnd(), $true)', config.homeDir));
  const options = { ...config, platform: 'win32', now: () => NOW,
    spawnSyncImpl(_executable, args, settings) {
      // WSL launches the actual Windows binary, with the production source,
      // arguments and stdin. Only its Linux executable/cwd spelling differs.
      return spawnSync(nativePowerShell, args, { ...settings, cwd: process.platform === 'win32' ? settings.cwd : undefined });
    },
  };
  return { store: createAccountSessionStore(options), options, edit(script) {
    return nativeCommand(`
      $homePath = [Console]::In.ReadToEnd()
      $dir = [IO.Path]::Combine($homePath, '.vigievuln')
      $file = [IO.Path]::Combine($dir, 'account-session.json')
      ${script}
    `, config.homeDir);
  } };
}

test('native Windows Unicode home works even when the process starts with code page 850', native, t => {
  const { options, edit } = nativeFixture(t, 'é-漢字-😀-');
  const unicodeOptions = { ...options, spawnSyncImpl(executable, args, settings) {
    const bootstrap = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    const legacy = '[Console]::InputEncoding = [Text.Encoding]::GetEncoding(850); ' + bootstrap;
    return options.spawnSyncImpl(executable, [...args.slice(0, -1), Buffer.from(legacy, 'utf16le').toString('base64')], settings);
  } };
  const store = createAccountSessionStore(unicodeOptions);
  assert.ok(store.filePath.includes('é-漢字-😀-'));
  assert.equal(store.read(), null);
  store.write({ ...SESSION, password: 'never-save' });
  assert.deepEqual(createAccountSessionStore(unicodeOptions).read(), SESSION);
  assert.equal(edit('[Console]::Write([IO.File]::Exists($file))'), 'True');
  store.write({ ...SESSION, token: 'unicode-replacement' });
  assert.equal(store.read().token, 'unicode-replacement');
  store.clear();
  assert.equal(store.read(), null);
  assert.equal(edit('[Console]::Write([IO.Directory]::GetFileSystemEntries($dir).Length)'), '0');
});

test('native Windows DPAPI round trip, private ACLs, replacement, expiry and corrupt data', native, t => {
  const { store, options, edit } = nativeFixture(t);
  assert.equal(store.read(), null);
  store.clear();
  assert.equal(edit('[Console]::Write([IO.Directory]::GetFileSystemEntries($homePath).Length)'), '0');
  store.write({ ...SESSION, password: 'never-save', email: 'private@example.test' });
  assert.deepEqual(createAccountSessionStore(options).read(), SESSION);
  const inspected = JSON.parse(edit(`
    Add-Type -AssemblyName System.Security
    $bytes = [IO.File]::ReadAllBytes($file)
    $offset = [Text.Encoding]::ASCII.GetByteCount("VVSESSION-DPAPI-1\n")
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes[$offset..($bytes.Length-1)],
      [Text.Encoding]::UTF8.GetBytes('VigieVuln/account-session/v1'), [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $acl = [IO.File]::GetAccessControl($file)
    $dirAcl = [IO.Directory]::GetAccessControl($dir)
    [Console]::Write((@{plain=[Text.Encoding]::UTF8.GetString($plain); disk=[Convert]::ToBase64String($bytes);
      owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
      user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
      protected=$acl.AreAccessRulesProtected; directoryProtected=$dirAcl.AreAccessRulesProtected;
      rules=$acl.Access.Count; directoryRules=$dirAcl.Access.Count} | ConvertTo-Json -Compress))
  `));
  assert.deepEqual(JSON.parse(inspected.plain), SESSION);
  assert.doesNotMatch(Buffer.from(inspected.disk, 'base64').toString('utf8'), /fad_account-session|never-save|private@example/);
  assert.equal(inspected.owner, inspected.user);
  assert.equal(inspected.protected, true);
  assert.equal(inspected.directoryProtected, true);
  assert.equal(inspected.rules, 1);
  assert.equal(inspected.directoryRules, 1);
  store.write({ ...SESSION, token: 'replacement' });
  assert.equal(store.read().token, 'replacement');
  assert.equal(edit('[Console]::Write([IO.Directory]::GetFiles($dir).Length)'), '1');
  assert.equal(createAccountSessionStore({ ...options, now: () => SESSION.expiresAt }).read(), null);
  assert.equal(store.read(), null);
  for (const damage of [
    "[IO.File]::WriteAllText($file, 'plaintext-secret')",
    '[IO.File]::WriteAllBytes($file, (New-Object byte[] 4097))',
    '$b=[IO.File]::ReadAllBytes($file); $b[$b.Length-1]=$b[$b.Length-1] -bxor 255; [IO.File]::WriteAllBytes($file,$b)',
  ]) {
    store.write(SESSION); edit(damage);
    assert.throws(() => store.read(), error => error.code === 'INVALID_SESSION' && !error.stack.includes('plaintext-secret'));
    store.clear();
  }
});

test('native Windows refuses permissive/inherited ACLs, hard links and directory junctions', native, t => {
  const { store, options, edit } = nativeFixture(t);
  const refused = () => {
    for (const action of [() => store.read(), () => store.write(SESSION), () => store.clear()]) {
      assert.throws(action, { code: 'UNSAFE_SESSION_FILE' });
    }
  };
  store.write(SESSION);
  edit(`
    $acl=[IO.File]::GetAccessControl($file)
    $rule=New-Object Security.AccessControl.FileSystemAccessRule(
      (New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), 'Read', 'Allow')
    $acl.AddAccessRule($rule); [IO.File]::SetAccessControl($file,$acl)
  `);
  refused();
  assert.equal(edit('[Console]::Write([IO.File]::GetAccessControl($file).Access.Count)'), '2');
  edit('[IO.File]::Delete($file)');
  store.write(SESSION);
  edit('$acl=[IO.Directory]::GetAccessControl($dir); $acl.SetAccessRuleProtection($false,$true); [IO.Directory]::SetAccessControl($dir,$acl)');
  refused();
  edit('[IO.Directory]::Delete($dir,$true)');
  store.write(SESSION);
  edit("[void](New-Item -ItemType HardLink -Path ([IO.Path]::Combine($homePath,'target')) -Value $file)");
  refused();
  edit('[IO.File]::Delete($file)');
  assert.equal(edit("[Console]::Write([IO.File]::Exists([IO.Path]::Combine($homePath,'target')))"), 'True');
  edit(`
    [IO.Directory]::Delete($dir)
    $target=[IO.Path]::Combine($homePath,'elsewhere'); [void][IO.Directory]::CreateDirectory($target)
    [void](New-Item -ItemType Junction -Path $dir -Value $target)
  `);
  refused();
  assert.equal(edit("[Console]::Write([IO.Directory]::GetFileSystemEntries([IO.Path]::Combine($homePath,'elsewhere')).Length)"), '0');
  const redirected = createAccountSessionStore({ ...options, homeDir: path.win32.join(options.homeDir, '.vigievuln') });
  assert.throws(() => redirected.write(SESSION), { code: 'UNSAFE_SESSION_FILE' });
  edit("[IO.Directory]::Delete([IO.Path]::Combine($homePath,'elsewhere'))");
  refused();
  // Remove the junction itself before fixture cleanup, never recurse through it.
  edit('[IO.Directory]::Delete($dir)');
});
