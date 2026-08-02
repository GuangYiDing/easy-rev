/**
 * Easy-Rev mobile Frida: SSL pinning observation / common bypass hooks (template).
 * Authorized apps only. Customize for target OkHttp/TrustManager versions.
 */
'use strict';

if (Java.available) {
  Java.perform(function () {
    send({ type: 'runtime', java: true });

    // OkHttp3 CertificatePinner
    try {
      const CertificatePinner = Java.use('okhttp3.CertificatePinner');
      CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
        send({ type: 'pinning', api: 'okhttp3.CertificatePinner.check', host: String(hostname) });
        // default: still call original (observe-only). Uncomment to bypass:
        // return;
        return this.check(hostname, peerCertificates);
      };
      send({ type: 'hook', target: 'okhttp3.CertificatePinner', status: 'attached' });
    } catch (e) {
      send({ type: 'hook', target: 'okhttp3.CertificatePinner', status: 'missing' });
    }

    // TrustManager checkServerTrusted (observe)
    try {
      const X509 = Java.use('javax.net.ssl.X509TrustManager');
      // cannot hook interface directly on all runtimes; best-effort custom
      send({ type: 'hook', target: 'X509TrustManager', status: 'interface_note' });
    } catch (e) {}
  });
} else {
  send({ type: 'runtime', java: false, note: 'use iOS script set for ObjC' });
}

send({ type: 'script_loaded', name: 'ssl_pinning' });
