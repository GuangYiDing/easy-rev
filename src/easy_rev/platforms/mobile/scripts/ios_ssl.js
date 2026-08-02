/**
 * Easy-Rev iOS Frida: SSL pinning observation / common bypass hooks (ObjC).
 * Authorized apps only. TrustKit / AFNetworking / NSURLSession variants differ by app.
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

if (ObjC && ObjC.available) {
  send({ type: 'runtime', objc: true });

  // SecTrustEvaluate / SecTrustEvaluateWithError — observe trust decisions
  tryHookExport('SecTrustEvaluate', {
    onEnter(args) {
      send({ type: 'pinning', api: 'SecTrustEvaluate' });
    },
  });
  tryHookExport('SecTrustEvaluateWithError', {
    onEnter(args) {
      send({ type: 'pinning', api: 'SecTrustEvaluateWithError' });
    },
  });

  // NSURLSession challenge — observe auth challenges
  try {
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
      send({ type: 'hook', target: 'NSURLSession', status: 'present' });
    }
  } catch (e) {}

  // TrustKit if present
  try {
    if (ObjC.classes.TSKPinningValidator) {
      const TSK = ObjC.classes.TSKPinningValidator;
      Interceptor.attach(TSK['- evaluateTrust:forHostname:'].implementation, {
        onEnter(args) {
          send({ type: 'pinning', api: 'TSKPinningValidator', host: 'objc' });
        },
      });
      send({ type: 'hook', target: 'TSKPinningValidator', status: 'attached' });
    } else {
      send({ type: 'hook', target: 'TSKPinningValidator', status: 'missing' });
    }
  } catch (e) {
    send({ type: 'hook', target: 'TSKPinningValidator', status: 'error', error: String(e) });
  }

  // AFSecurityPolicy (AFNetworking)
  try {
    if (ObjC.classes.AFSecurityPolicy) {
      send({ type: 'hook', target: 'AFSecurityPolicy', status: 'present' });
    }
  } catch (e) {}
} else {
  send({ type: 'runtime', objc: false, note: 'load on iOS process with ObjC runtime' });
}

send({ type: 'script_loaded', name: 'ios_ssl' });
