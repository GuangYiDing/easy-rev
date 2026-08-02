/*
 * SimplySign Desktop — session / OAuth / PKCS server trace
 * Attach: frida -n "SimplySign Desktop" -l hooks/session_trace.js
 *
 * Goal: observe when OTP webview is shown, token refresh, session expiry,
 * and PKCS SIGN_HASH path. Customize before relying on any bypass.
 */
'use strict';

function log(msg) {
  console.log('[simplysign-session] ' + msg);
}

function hookObjC() {
  if (!ObjC.available) {
    log('ObjC unavailable');
    return;
  }

  const interesting = [
    'PanelWebViewController',
    'SCCAppDelegate',
    'SCCClientForPKIServerRequests',
    'SCCServerForPKCS11Requests',
    'NXOAuth2Account',
    'NXOAuth2AccountStore',
    'NXOAuth2Connection',
  ];

  interesting.forEach((className) => {
    try {
      const cls = ObjC.classes[className];
      if (!cls) {
        log('class missing: ' + className);
        return;
      }
      const methods = cls.$ownMethods;
      methods.forEach((m) => {
        const lower = m.toLowerCase();
        if (
          lower.indexOf('oauth') !== -1 ||
          lower.indexOf('token') !== -1 ||
          lower.indexOf('auth') !== -1 ||
          lower.indexOf('login') !== -1 ||
          lower.indexOf('logon') !== -1 ||
          lower.indexOf('refresh') !== -1 ||
          lower.indexOf('session') !== -1 ||
          lower.indexOf('connect') !== -1 ||
          lower.indexOf('sign') !== -1 ||
          lower.indexOf('expire') !== -1
        ) {
          try {
            Interceptor.attach(cls[m].implementation, {
              onEnter() {
                log(className + ' ' + m);
              },
            });
          } catch (e) {
            // some methods may be unsupported
          }
        }
      });
      log('hooked methods on ' + className);
    } catch (e) {
      log('hook error ' + className + ': ' + e);
    }
  });
}

hookObjC();
log('loaded');
