/**
 * Easy-Rev desktop Frida script: SSL/TLS write/read observation (skeleton).
 * Authorized targets only. Platform-specific symbols vary — extend per binary.
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

// OpenSSL-style (common in cross-platform clients)
tryHook(null, 'SSL_write', {
  onEnter(args) {
    this.len = args[2].toInt32();
    this.buf = args[1];
  },
  onLeave(retval) {
    if (this.len > 0 && this.len < 65536) {
      try {
        const bytes = Memory.readByteArray(this.buf, Math.min(this.len, 512));
        send({ type: 'ssl_write', len: this.len, preview_b64: bytes ? undefined : null });
      } catch (_) {}
    }
  }
});

tryHook(null, 'SSL_read', {
  onEnter(args) {
    this.buf = args[1];
    this.max = args[2].toInt32();
  },
  onLeave(retval) {
    const n = retval.toInt32();
    if (n > 0 && n < 65536) {
      send({ type: 'ssl_read', len: n });
    }
  }
});

// Secure Transport (macOS) — SecItem for keychain-ish traffic side channels
if (Process.platform === 'darwin') {
  tryHook(null, 'SSLWrite', {
    onEnter(args) { this.len = args[2].toInt32(); },
    onLeave(retval) { if (this.len > 0) send({ type: 'st_ssl_write', len: this.len }); }
  });
}

send({ type: 'script_loaded', name: 'ssl_trace' });
