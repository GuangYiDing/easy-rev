/**
 * Easy-Rev desktop Frida: file open/read/write observation (config, certs, tokens).
 * Authorized targets only. libc / Win32 symbols vary by OS.
 */
'use strict';

function tryHook(moduleName, exportName, callbacks) {
  try {
    const addr = Module.findExportByName(moduleName, exportName);
    if (!addr) return false;
    Interceptor.attach(addr, callbacks);
    send({ type: 'hook', module: moduleName, export: exportName, status: 'attached' });
    return true;
  } catch (e) {
    send({ type: 'hook', module: moduleName, export: exportName, status: 'error', error: String(e) });
    return false;
  }
}

function readCString(ptr) {
  try {
    if (!ptr || ptr.isNull()) return null;
    return ptr.readUtf8String() || ptr.readCString();
  } catch (_) {
    return null;
  }
}

// POSIX open / openat
tryHook(null, 'open', {
  onEnter(args) {
    this.path = readCString(args[0]);
    this.flags = args[1].toInt32();
  },
  onLeave(retval) {
    if (this.path) {
      send({ type: 'open', path: this.path, flags: this.flags, fd: retval.toInt32() });
    }
  },
});

tryHook(null, 'openat', {
  onEnter(args) {
    this.path = readCString(args[1]);
  },
  onLeave(retval) {
    if (this.path) {
      send({ type: 'openat', path: this.path, fd: retval.toInt32() });
    }
  },
});

// fopen family
tryHook(null, 'fopen', {
  onEnter(args) {
    this.path = readCString(args[0]);
    this.mode = readCString(args[1]);
  },
  onLeave(retval) {
    if (this.path) {
      send({ type: 'fopen', path: this.path, mode: this.mode, ok: !retval.isNull() });
    }
  },
});

// Windows CreateFileW (optional)
if (Process.platform === 'windows') {
  tryHook('kernel32.dll', 'CreateFileW', {
    onEnter(args) {
      try {
        this.path = args[0].readUtf16String();
      } catch (_) {
        this.path = null;
      }
    },
    onLeave(retval) {
      if (this.path) {
        send({ type: 'CreateFileW', path: this.path, handle: retval.toString() });
      }
    },
  });
}

// Interesting path filter note
send({
  type: 'script_loaded',
  name: 'file_trace',
  note: 'Filter for .pem .key .json .plist .db token cookie cert in client',
});
