'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { spawnSync } = require('node:child_process');

class AccountSessionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AccountSessionError';
    this.code = code;
  }
}

// The account API uses epoch milliseconds. Never persist credentials or the
// entire login response: the only permitted fields are token and expiresAt.
function validateAccountSession(value, now = Date.now()) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      typeof value.token !== 'string' || !/^[A-Za-z0-9_-]{1,200}$/.test(value.token) ||
      !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= 0) {
    throw new AccountSessionError('INVALID_SESSION', 'Invalid account session. Sign in again.');
  }
  if (value.expiresAt <= now) {
    throw new AccountSessionError('SESSION_EXPIRED', 'Account session expired. Sign in again.');
  }
  return { token: value.token, expiresAt: value.expiresAt };
}

/**
 * Synchronous, small private credential store, separate from ~/.fad-checker.
 * Options are trusted injection points for local tests, not CLI input.
 * Windows uses the native helper below; POSIX retains its permission checks.
 * The home directory and its ancestors must be trusted. Atomic replacement
 * prevents partial reads, but does not provide cross-process session locking.
 */
function createAccountSessionStore({ homeDir = os.homedir(), fsImpl = fs, now = Date.now,
  platform = process.platform, spawnSyncImpl = spawnSync, windowsRoot = process.env.SystemRoot } = {}) {
  if (platform === 'win32') return createWindowsSessionStore({ homeDir, now, spawnSyncImpl, windowsRoot });
  const directory = path.join(path.resolve(homeDir), '.vigievuln');
  const filePath = path.join(directory, 'account-session.json');
  const unsafe = () => new AccountSessionError('UNSAFE_SESSION_FILE', 'Account session storage must be private, owned by the current user and free of links.');

  function check(stat, isDirectory) {
    if (typeof process.getuid !== 'function' || stat.uid !== process.getuid() ||
        (stat.mode & 0o7777) !== (isDirectory ? 0o700 : 0o600) ||
        (isDirectory ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1)) throw unsafe();
  }

  function checkDirectory(create = false) {
    if (create) {
      try { fsImpl.mkdirSync(directory, { mode: 0o700 }); }
      catch (error) { if (error.code !== 'EEXIST') throw error; }
    }
    try { check(fsImpl.lstatSync(directory), true); return true; }
    catch (error) { if (error.code === 'ENOENT' && !create) return false; throw error; }
  }

  function checkFile() {
    try { check(fsImpl.lstatSync(filePath), false); return true; }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  }

  // Do not leak contents, paths or injected filesystem error messages.
  function guarded(operation) {
    try { return operation(); }
    catch (error) {
      if (error instanceof AccountSessionError) throw error;
      throw new AccountSessionError('SESSION_IO', 'Unable to access private account session storage.');
    }
  }

  function clear() {
    return guarded(() => {
      if (!checkDirectory() || !checkFile()) return;
      fsImpl.unlinkSync(filePath);
    });
  }

  function read() {
    return guarded(() => {
      if (!checkDirectory() || !checkFile()) return null;
      let fd;
      let value;
      try {
        fd = fsImpl.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        const stat = fsImpl.fstatSync(fd);
        check(stat, false);
        if (stat.size > 4096) throw new AccountSessionError('INVALID_SESSION', 'Invalid account session file. Sign in again.');
        // A bounded read also handles a file growing after fstat.
        const buffer = Buffer.alloc(4097);
        let length = 0;
        let count;
        do {
          count = fsImpl.readSync(fd, buffer, length, buffer.length - length, null);
          length += count;
        } while (count && length < buffer.length);
        if (length > 4096) throw new AccountSessionError('INVALID_SESSION', 'Invalid account session file. Sign in again.');
        try { value = JSON.parse(buffer.toString('utf8', 0, length)); }
        catch { throw new AccountSessionError('INVALID_SESSION', 'Invalid account session file. Sign in again.'); }
      } finally { if (fd !== undefined) fsImpl.closeSync(fd); }
      try { return validateAccountSession(value, now()); }
      catch (error) {
        if (error.code !== 'SESSION_EXPIRED') throw error;
        clear();
        return null;
      }
    });
  }

  function write(value) {
    return guarded(() => {
      const session = validateAccountSession(value, now());
      checkDirectory(true);
      checkFile();
      const temporary = path.join(directory, `.account-session-${randomUUID()}.tmp`);
      let fd;
      let created = false;
      try {
        fd = fsImpl.openSync(temporary, 'wx', 0o600);
        created = true;
        fsImpl.fchmodSync(fd, 0o600);
        check(fsImpl.fstatSync(fd), false);
        fsImpl.writeFileSync(fd, JSON.stringify(session) + '\n', 'utf8');
        fsImpl.fsyncSync(fd);
        fsImpl.closeSync(fd);
        fd = undefined;
        checkDirectory();
        checkFile();
        fsImpl.renameSync(temporary, filePath);
      } finally {
        try { if (fd !== undefined) fsImpl.closeSync(fd); }
        finally {
          if (created) {
            try { fsImpl.unlinkSync(temporary); }
            catch (error) { if (error.code !== 'ENOENT') throw error; }
          }
        }
      }
    });
  }

  return { filePath, read, write, clear };
}

// Windows PowerShell 5.1 and .NET Framework are OS components. No PATH lookup,
// shell, profile, downloaded module, execution-policy bypass or generated script
// file is used. Both source and request travel over stdin, in separate frames:
// only the constant first line is compiled, NEVER request data. This also avoids
// Windows' command-line length limit. Add-Type may create compiler temporaries,
// but its input contains no session, path or other user data.
const WINDOWS_BOOTSTRAP = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  [Console]::InputEncoding = New-Object Text.UTF8Encoding($false, $true)
  [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false, $true)
  $source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::ReadLine()))
  Add-Type -TypeDefinition $source -ReferencedAssemblies System.Security.dll,System.Web.Extensions.dll
  [VigieVulnSession]::Run([Console]::In.ReadToEnd())
} catch {
  [Console]::Out.Write('{"error":"SESSION_IO"}')
  exit 1
}
`;

// Deliberately restricted to local NTFS and ordinary DOS paths. Existing ACLs
// are checked, never silently repaired. All ancestors are held open without
// delete sharing; storage objects are inspected through OPEN_REPARSE_POINT
// handles. Reads, deletion and temporary-file publication use those handles.
// As on POSIX, the home/ancestors, OS, process environment and same-user processes
// are trusted. This is not a defence against administrators or the current user.
const WINDOWS_SOURCE = String.raw`
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

public static class VigieVulnSession {
  const uint Read = 0x80000000, Write = 0x40000000, Delete = 0x10000;
  const uint Reparse = 0x400, Directory = 0x10, OpenReparse = 0x00200000, Backup = 0x02000000;
  const int FullControl = 0x1f01ff;
  static readonly byte[] Header = Encoding.ASCII.GetBytes("VVSESSION-DPAPI-1\n");
  static readonly byte[] Entropy = Encoding.UTF8.GetBytes("VigieVuln/account-session/v1");
  static readonly SecurityIdentifier User = WindowsIdentity.GetCurrent().User;

  [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
    public int Length; public IntPtr Descriptor; public int Inherit;
  }
  [StructLayout(LayoutKind.Sequential)] struct Info {
    public uint Attributes;
    public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Modified;
    public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFileW(string path, uint access, uint share, ref SecurityAttributes sa, uint creation, uint flags, IntPtr template);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CreateDirectoryW(string path, ref SecurityAttributes sa);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
  [DllImport("kernel32.dll")] static extern uint GetFileType(SafeFileHandle handle);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern uint GetDriveTypeW(string root);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool GetVolumeInformationW(string root, IntPtr label, uint labelSize, out uint serial, out uint component, out uint flags, StringBuilder fs, uint fsSize);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern uint GetSecurityInfo(SafeFileHandle handle, int type, uint flags, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool ReadFile(SafeFileHandle handle, byte[] data, uint size, out uint read, IntPtr overlapped);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool WriteFile(SafeFileHandle handle, byte[] data, uint size, out uint written, IntPtr overlapped);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle handle);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind, byte[] data, uint size);

  class StoreError : Exception {
    public readonly string Code;
    public StoreError(string code) { Code = code; }
  }
  static void Unsafe() { throw new StoreError("UNSAFE_SESSION_FILE"); }
  static void Invalid() { throw new StoreError("INVALID_SESSION"); }
  static void IO() { throw new StoreError("SESSION_IO"); }

  static Info Check(SafeFileHandle handle, bool directory, bool privateAcl) {
    Info info;
    if (!GetFileInformationByHandle(handle, out info)) { IO(); }
    if (GetFileType(handle) != 1 || (info.Attributes & Reparse) != 0 ||
        ((info.Attributes & Directory) != 0) != directory || (!directory && info.Links != 1)) Unsafe();
    if (!privateAcl) return info;
    IntPtr owner, group, dacl, sacl, descriptor;
    uint result = GetSecurityInfo(handle, 1, 5, out owner, out group, out dacl, out sacl, out descriptor);
    if (result != 0) IO();
    try {
      byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)];
      Marshal.Copy(descriptor, bytes, 0, bytes.Length);
      RawSecurityDescriptor sd = new RawSecurityDescriptor(bytes, 0);
      if (!User.Equals(sd.Owner) || (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
          sd.DiscretionaryAcl == null || sd.DiscretionaryAcl.Count != 1) Unsafe();
      CommonAce ace = sd.DiscretionaryAcl[0] as CommonAce;
      AceFlags expected = directory ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : AceFlags.None;
      if (ace == null || ace.IsCallback || ace.AceQualifier != AceQualifier.AccessAllowed ||
          !User.Equals(ace.SecurityIdentifier) || ace.AccessMask != FullControl || ace.AceFlags != expected) Unsafe();
    } finally { LocalFree(descriptor); }
    return info;
  }

  static SafeFileHandle Open(string path, uint access, bool directory, bool missing) {
    SecurityAttributes sa = new SecurityAttributes();
    sa.Length = Marshal.SizeOf(sa);
    SafeFileHandle handle = CreateFileW(path, access, directory ? 3u : 1u, ref sa, 3, OpenReparse | Backup, IntPtr.Zero);
    if (!handle.IsInvalid) return handle;
    int error = Marshal.GetLastWin32Error();
    handle.Dispose();
    if (missing && error == 2) return null;
    IO(); return null;
  }

  // The DACL is attached at creation, including to empty temporary files.
  static SafeFileHandle CreatePrivate(string path, bool directory) {
    RawSecurityDescriptor sd = new RawSecurityDescriptor("O:" + User.Value + "D:P(A;" + (directory ? "OICI" : "") + ";FA;;;" + User.Value + ")");
    byte[] bytes = new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes, 0);
    IntPtr memory = Marshal.AllocHGlobal(bytes.Length);
    try {
      Marshal.Copy(bytes, 0, memory, bytes.Length);
      SecurityAttributes sa = new SecurityAttributes();
      sa.Length = Marshal.SizeOf(sa); sa.Descriptor = memory;
      if (directory) {
        if (!CreateDirectoryW(path, ref sa) && Marshal.GetLastWin32Error() != 183) IO();
        return Open(path, 0x20080, true, false);
      }
      SafeFileHandle handle = CreateFileW(path, Read | Write | Delete, 0, ref sa, 1, OpenReparse, IntPtr.Zero);
      if (handle.IsInvalid) { handle.Dispose(); IO(); }
      return handle;
    } finally { Marshal.FreeHGlobal(memory); }
  }

  static void Remove(SafeFileHandle handle) {
    if (!SetFileInformationByHandle(handle, 4, new byte[] { 1 }, 1)) IO();
  }
  static void Rename(SafeFileHandle handle, string destination) {
    byte[] name = Encoding.Unicode.GetBytes(destination);
    // FILE_RENAME_INFO: DWORD flags, aligned HANDLE, DWORD length, WCHAR[].
    int lengthOffset = 2 * IntPtr.Size, nameOffset = lengthOffset + 4;
    byte[] data = new byte[nameOffset + name.Length + 2];
    data[0] = 1;
    Buffer.BlockCopy(BitConverter.GetBytes(name.Length), 0, data, lengthOffset, 4);
    Buffer.BlockCopy(name, 0, data, nameOffset, name.Length);
    if (!SetFileInformationByHandle(handle, 3, data, (uint)data.Length)) IO();
  }
  static void CheckExisting(string file) {
    using (SafeFileHandle handle = Open(file, 0x20080, false, true)) {
      if (handle != null) Check(handle, false, true);
    }
  }

  static object Execute(Dictionary<string, object> request) {
    string operation = (string)request["operation"], home = (string)request["homeDir"];
    if (operation != "read" && operation != "write" && operation != "clear") IO();
    // Reject UNC/device paths, alternate streams and DOS path aliases.
    if (!System.Text.RegularExpressions.Regex.IsMatch(home, @"^[A-Za-z]:\\") || home.IndexOf(':', 2) >= 0 ||
        home.IndexOf('/') >= 0 || home.IndexOf('\0') >= 0 || Path.GetFullPath(home) != home) Unsafe();
    string root = home.Substring(0, 3);
    uint serial, component, flags;
    StringBuilder format = new StringBuilder(32);
    if (GetDriveTypeW(root) != 3 || !GetVolumeInformationW(root, IntPtr.Zero, 0, out serial, out component, out flags, format, 32) ||
        format.ToString() != "NTFS") throw new StoreError("WINDOWS_SESSION_UNAVAILABLE");

    byte[] encrypted = null;
    if (operation == "write") {
      byte[] plain = Encoding.UTF8.GetBytes((string)request["session"]);
      try { encrypted = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser); }
      finally { Array.Clear(plain, 0, plain.Length); }
    }
    List<SafeFileHandle> parents = new List<SafeFileHandle>();
    try {
      string current = root;
      SafeFileHandle parent = Open(current, 0x80, true, false); parents.Add(parent); Check(parent, true, false);
      foreach (string part in home.Substring(3).Split(new char[] {'\\'}, StringSplitOptions.RemoveEmptyEntries)) {
        if (part.EndsWith(".") || part.EndsWith(" ")) Unsafe();
        current = Path.Combine(current, part);
        parent = Open(current, 0x80, true, false); parents.Add(parent); Check(parent, true, false);
      }
      string directory = Path.Combine(home, ".vigievuln"), file = Path.Combine(directory, "account-session.json");
      using (SafeFileHandle dir = operation == "write" ? CreatePrivate(directory, true) : Open(directory, 0x20080, true, true)) {
        if (dir == null) return null;
        Check(dir, true, true);
        if (operation == "write") {
          CheckExisting(file);
          string temporary = Path.Combine(directory, ".account-session-" + Guid.NewGuid().ToString("N") + ".tmp");
          using (SafeFileHandle handle = CreatePrivate(temporary, false)) {
            bool committed = false;
            try {
              Check(handle, false, true);
              byte[] data = new byte[Header.Length + encrypted.Length];
              Buffer.BlockCopy(Header, 0, data, 0, Header.Length);
              Buffer.BlockCopy(encrypted, 0, data, Header.Length, encrypted.Length);
              uint written;
              if (data.Length > 4096 || !WriteFile(handle, data, (uint)data.Length, out written, IntPtr.Zero) || written != data.Length || !FlushFileBuffers(handle)) IO();
              Check(handle, false, true); CheckExisting(file);
              Rename(handle, file); committed = true;
            } finally { if (!committed) Remove(handle); }
          }
          return null;
        }
        using (SafeFileHandle handle = Open(file, Read | (operation == "clear" ? Delete : 0), false, true)) {
          if (handle == null) return null;
          Info info = Check(handle, false, true);
          if (operation == "clear") { Remove(handle); return null; }
          if (info.SizeHigh != 0 || info.SizeLow > 4096 || info.SizeLow <= Header.Length) Invalid();
          byte[] data = new byte[info.SizeLow]; uint count;
          if (!ReadFile(handle, data, (uint)data.Length, out count, IntPtr.Zero) || count != data.Length) IO();
          for (int i = 0; i < Header.Length; i++) if (data[i] != Header[i]) Invalid();
          byte[] cipher = new byte[data.Length - Header.Length];
          Buffer.BlockCopy(data, Header.Length, cipher, 0, cipher.Length);
          byte[] plain;
          try { plain = ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.CurrentUser); }
          catch (CryptographicException) { Invalid(); return null; }
          try { return new UTF8Encoding(false, true).GetString(plain); }
          finally { Array.Clear(plain, 0, plain.Length); }
        }
      }
    } finally { for (int i = parents.Count - 1; i >= 0; i--) parents[i].Dispose(); }
  }
  public static void Run(string input) {
    JavaScriptSerializer json = new JavaScriptSerializer(); json.MaxJsonLength = 16384;
    object response;
    try { response = new { value = Execute(json.Deserialize<Dictionary<string, object>>(input)) }; }
    catch (StoreError error) { response = new { error = error.Code }; }
    catch { response = new { error = "SESSION_IO" }; }
    // Write directly to stdout rather than the PowerShell object pipeline.
    Console.Out.Write(json.Serialize(response));
  }
}
`;

function createWindowsSessionStore({ homeDir, now, spawnSyncImpl, windowsRoot }) {
  const resolvedHome = path.win32.resolve(homeDir);
  const filePath = path.win32.join(resolvedHome, '.vigievuln', 'account-session.json');
  const messages = {
    SESSION_IO: 'Unable to access private account session storage.',
    INVALID_SESSION: 'Invalid account session file. Sign in again.',
    UNSAFE_SESSION_FILE: 'Account session storage must be private, owned by the current user and free of links.',
    WINDOWS_SESSION_UNAVAILABLE: 'Private account sessions require Windows PowerShell 5.1, DPAPI and a local NTFS home directory.',
  };
  const fail = code => new AccountSessionError(code, messages[code]);
  function run(operation, session) {
    try {
      if (typeof windowsRoot !== 'string' || !/^[a-z]:\\[^\r\n\0]*$/i.test(windowsRoot) || windowsRoot.includes('..')) {
        throw fail('WINDOWS_SESSION_UNAVAILABLE');
      }
      const result = spawnSyncImpl(path.win32.join(windowsRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
        ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(WINDOWS_BOOTSTRAP, 'utf16le').toString('base64')], {
          shell: false, windowsHide: true, cwd: windowsRoot, encoding: 'utf8', timeout: 15000, maxBuffer: 16384,
          input: Buffer.from(WINDOWS_SOURCE, 'utf8').toString('base64') + '\n' + JSON.stringify({
            operation, homeDir: resolvedHome, ...(session ? { session: JSON.stringify(session) } : {}),
          }),
        });
      if (!result || result.error || result.signal || result.status !== 0 || typeof result.stdout !== 'string' ||
          Buffer.byteLength(result.stdout, 'utf8') > 16384) throw fail('SESSION_IO');
      const response = JSON.parse(result.stdout);
      if (!response || typeof response !== 'object' || Array.isArray(response)) throw fail('SESSION_IO');
      if (Object.hasOwn(response, 'error')) throw fail(Object.hasOwn(messages, response.error) ? response.error : 'SESSION_IO');
      if (!Object.hasOwn(response, 'value') || (response.value !== null && (operation !== 'read' || typeof response.value !== 'string'))) throw fail('SESSION_IO');
      return response.value;
    } catch (error) {
      if (error instanceof AccountSessionError) throw error;
      // Child-process errors can contain stdin, stderr, paths or decrypted data.
      throw fail('SESSION_IO');
    }
  }
  function clear() { run('clear'); }
  function write(value) { run('write', validateAccountSession(value, now())); }
  function read() {
    const contents = run('read');
    if (contents === null) return null;
    let value;
    try { value = JSON.parse(contents); } catch { throw fail('INVALID_SESSION'); }
    try { return validateAccountSession(value, now()); }
    catch (error) {
      if (error.code !== 'SESSION_EXPIRED') throw error;
      clear();
      return null;
    }
  }
  return { filePath, read, write, clear };
}

module.exports = { createAccountSessionStore, validateAccountSession, AccountSessionError };
