/**
 * Easy-Rev iOS Frida: CommonCrypto / Security framework observation.
 * Authorized apps only.
 */
'use strict';

function tryHookExport(name, callbacks) {
  try {
    const addr = Module.findExportByName(null, name);
    if (!addr) {
      send({ type: 'hook', target: name, status: 'missing' });
      return false;
    }
    Interceptor.attach(addr, callbacks);
    send({ type: 'hook', target: name, status: 'attached' });
    return true;
  } catch (e) {
    send({ type: 'hook', target: name, status: 'error', error: String(e) });
    return false;
  }
}

// CCCrypt — core symmetric crypto
tryHookExport('CCCrypt', {
  onEnter(args) {
    send({
      type: 'crypto',
      api: 'CCCrypt',
      op: args[0].toInt32(),
      alg: args[1].toInt32(),
      options: args[2].toInt32(),
      keyLength: args[4].toInt32(),
    });
  },
});

tryHookExport('CCHmac', {
  onEnter(args) {
    send({ type: 'crypto', api: 'CCHmac', algorithm: args[0].toInt32() });
  },
});

tryHookExport('CC_SHA256', {
  onEnter(args) {
    send({ type: 'crypto', api: 'CC_SHA256', len: args[1].toInt32() });
  },
});

tryHookExport('CC_MD5', {
  onEnter(args) {
    send({ type: 'crypto', api: 'CC_MD5', len: args[1].toInt32() });
  },
});

// SecKeyCreateSignature / SecKeyEncrypt when available
tryHookExport('SecKeyCreateSignature', {
  onEnter(args) {
    send({ type: 'crypto', api: 'SecKeyCreateSignature' });
  },
});

if (ObjC && ObjC.available) {
  send({ type: 'runtime', objc: true });
  try {
    if (ObjC.classes.NSData) {
      send({ type: 'hook', target: 'NSData', status: 'present' });
    }
  } catch (e) {}
}

send({ type: 'script_loaded', name: 'ios_crypto' });
