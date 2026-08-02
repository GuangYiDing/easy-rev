/**
 * Easy-Rev mobile Frida: high-level HTTP client observation (OkHttp / URLSession).
 */
'use strict';

if (Java.available) {
  Java.perform(function () {
    try {
      const Builder = Java.use('okhttp3.Request$Builder');
      Builder.url.overload('java.lang.String').implementation = function (url) {
        send({ type: 'http', api: 'okhttp3.Request.Builder.url', url: String(url) });
        return this.url(url);
      };
      send({ type: 'hook', target: 'okhttp3.Request.Builder.url', status: 'attached' });
    } catch (e) {
      send({ type: 'hook', target: 'okhttp3.Request.Builder', status: 'missing' });
    }
    try {
      const HttpURLConnection = Java.use('java.net.HttpURLConnection');
      HttpURLConnection.getRequestMethod.implementation = function () {
        const m = this.getRequestMethod();
        try {
          send({ type: 'http', api: 'HttpURLConnection', method: String(m), url: String(this.getURL()) });
        } catch (_) {}
        return m;
      };
    } catch (e) {}
  });
}

if (ObjC && ObjC.available) {
  try {
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession && NSURLSession['- dataTaskWithRequest:completionHandler:']) {
      Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
        onEnter(args) {
          try {
            const req = new ObjC.Object(args[2]);
            const url = req.URL().absoluteString().toString();
            send({ type: 'http', api: 'NSURLSession', url: url });
          } catch (e) {}
        }
      });
      send({ type: 'hook', target: 'NSURLSession', status: 'attached' });
    }
  } catch (e) {
    send({ type: 'hook', target: 'NSURLSession', status: 'error', error: String(e) });
  }
}

send({ type: 'script_loaded', name: 'network' });
