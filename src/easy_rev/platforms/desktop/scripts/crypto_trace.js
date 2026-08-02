/**
 * Easy-Rev desktop Frida script: common crypto API hooks (skeleton).
 */
'use strict';

function hookExport(name, onEnter, onLeave) {
  try {
    const addr = Module.findExportByName(null, name);
    if (!addr) return;
    Interceptor.attach(addr, { onEnter, onLeave });
    send({ type: 'hook', export: name, status: 'attached' });
  } catch (e) {
    send({ type: 'hook', export: name, status: 'error', error: String(e) });
  }
}

// OpenSSL EVP
hookExport('EVP_EncryptUpdate', function (args) {
  this.inl = args[4] ? args[4].toInt32() : 0;
}, function (retval) {
  if (this.inl > 0) send({ type: 'evp_encrypt', in_len: this.inl });
});

hookExport('HMAC', function (args) {
  send({ type: 'hmac_call' });
}, null);

// Apple CommonCrypto
if (Process.platform === 'darwin') {
  hookExport('CCCrypt', function (args) {
    send({ type: 'CCCrypt', op: args[0].toInt32() });
  }, null);
  hookExport('CCHmac', function (args) {
    send({ type: 'CCHmac', alg: args[0].toInt32() });
  }, null);
}

// Windows BCrypt (name may require module)
if (Process.platform === 'windows') {
  try {
    const m = Process.getModuleByName('bcrypt.dll');
    const addr = m.findExportByName('BCryptEncrypt');
    if (addr) {
      Interceptor.attach(addr, {
        onEnter() { send({ type: 'BCryptEncrypt' }); }
      });
      send({ type: 'hook', export: 'BCryptEncrypt', status: 'attached' });
    }
  } catch (e) {
    send({ type: 'hook', export: 'BCryptEncrypt', status: 'skip', error: String(e) });
  }
}

send({ type: 'script_loaded', name: 'crypto_trace' });
