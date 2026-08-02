/**
 * Easy-Rev mobile Frida: javax.crypto / CommonCrypto observation.
 */
'use strict';

if (Java.available) {
  Java.perform(function () {
    try {
      const Cipher = Java.use('javax.crypto.Cipher');
      Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        send({ type: 'crypto', api: 'Cipher.getInstance', transformation: String(transformation) });
        return this.getInstance(transformation);
      };
      send({ type: 'hook', target: 'javax.crypto.Cipher.getInstance', status: 'attached' });
    } catch (e) {
      send({ type: 'hook', target: 'Cipher', status: 'error', error: String(e) });
    }
    try {
      const Mac = Java.use('javax.crypto.Mac');
      Mac.getInstance.overload('java.lang.String').implementation = function (alg) {
        send({ type: 'crypto', api: 'Mac.getInstance', alg: String(alg) });
        return this.getInstance(alg);
      };
    } catch (e) {}
    try {
      const md = Java.use('java.security.MessageDigest');
      md.getInstance.overload('java.lang.String').implementation = function (alg) {
        send({ type: 'crypto', api: 'MessageDigest.getInstance', alg: String(alg) });
        return this.getInstance(alg);
      };
    } catch (e) {}
  });
}

if (ObjC && ObjC.available) {
  try {
    const CCCrypt = Module.findExportByName(null, 'CCCrypt');
    if (CCCrypt) {
      Interceptor.attach(CCCrypt, {
        onEnter(args) { send({ type: 'crypto', api: 'CCCrypt', op: args[0].toInt32() }); }
      });
      send({ type: 'hook', target: 'CCCrypt', status: 'attached' });
    }
  } catch (e) {}
}

send({ type: 'script_loaded', name: 'crypto' });
