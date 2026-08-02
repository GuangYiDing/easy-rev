/**
 * Easy-Rev desktop Frida: common HTTP/TLS client entry hooks (curl / WinHTTP / CFNetwork).
 * Authorized targets only. Extend symbols per binary.
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

// libcurl
tryHook(null, 'curl_easy_setopt', {
  onEnter(args) {
    const opt = args[1].toInt32();
    // CURLOPT_URL = 10002
    if (opt === 10002) {
      send({ type: 'curl_setopt_url', url: readCString(args[2]) });
    }
  },
});

tryHook(null, 'curl_easy_perform', {
  onEnter(args) {
    send({ type: 'curl_perform' });
  },
});

// WinHTTP
if (Process.platform === 'windows') {
  tryHook('winhttp.dll', 'WinHttpConnect', {
    onEnter(args) {
      try {
        send({ type: 'WinHttpConnect', server: args[1].readUtf16String() });
      } catch (_) {}
    },
  });
  tryHook('winhttp.dll', 'WinHttpOpenRequest', {
    onEnter(args) {
      try {
        send({
          type: 'WinHttpOpenRequest',
          verb: args[1].readUtf16String(),
          path: args[2].readUtf16String(),
        });
      } catch (_) {}
    },
  });
}

// macOS CFNetwork / NSURLSession are ObjC — best-effort C entry
if (Process.platform === 'darwin') {
  tryHook(null, 'CFHTTPMessageCreateRequest', {
    onEnter(args) {
      send({ type: 'CFHTTPMessageCreateRequest' });
    },
  });
}

send({ type: 'script_loaded', name: 'http_trace' });
