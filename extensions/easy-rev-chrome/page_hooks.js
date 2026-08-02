/**
 * Injected into the page (via chrome.debugger Runtime.evaluate or scripting).
 * Mirrors easy-rev runtime_hooks + crypto_hooks for full RE parity in user Chrome.
 * Exposes: window.__easy_rev_hooks__, window.__easy_rev_install__(), window.__easy_rev_dump__()
 */
(function () {
  if (window.__easy_rev_full_installed__) {
    return { already: true };
  }
  window.__easy_rev_full_installed__ = true;

  const MAX = 250;
  const MAX_BODY = 16000;
  const MAX_C = 300;
  const h = (window.__easy_rev_hooks__ = window.__easy_rev_hooks__ || {
    installed: false,
    traces: [],
    ws: [],
    crypto: [],
    cryptoInstalled: false,
  });

  const clip = (s) => {
    if (s == null) return null;
    let t;
    try {
      t = typeof s === "string" ? s : JSON.stringify(s);
    } catch (e) {
      t = String(s);
    }
    return t.length > MAX_BODY ? t.slice(0, MAX_BODY) + "…" : t;
  };
  const stack = () => {
    try {
      return (new Error().stack || "")
        .split("\n")
        .slice(2, 12)
        .map((x) => x.trim())
        .filter(Boolean);
    } catch (e) {
      return [];
    }
  };
  const push = (entry) => {
    if (h.traces.length >= MAX) h.traces.shift();
    entry.ts = Date.now();
    entry.stack = stack();
    h.traces.push(entry);
  };
  const bufToHex = (buf) => {
    try {
      const u8 =
        buf instanceof ArrayBuffer
          ? new Uint8Array(buf)
          : buf && buf.buffer
            ? new Uint8Array(buf.buffer, buf.byteOffset || 0, buf.byteLength || buf.length)
            : null;
      if (!u8) return null;
      let out = "";
      const n = Math.min(u8.length, 256);
      for (let i = 0; i < n; i++) out += u8[i].toString(16).padStart(2, "0");
      if (u8.length > 256) out += "…";
      return out;
    } catch (e) {
      return null;
    }
  };
  const pushCrypto = (ev) => {
    if (h.crypto.length >= MAX_C) h.crypto.shift();
    ev.ts = Date.now();
    ev.stack = stack();
    h.crypto.push(ev);
  };

  // ---- fetch ----
  if (typeof window.fetch === "function" && !window.fetch.__er) {
    const origFetch = window.fetch.bind(window);
    window.fetch = async function (input, init) {
      const started = Date.now();
      let url = "",
        method = "GET",
        headers = {},
        body = null;
      try {
        url = typeof input === "string" ? input : (input && input.url) || "";
        init = init || {};
        method = (init.method || (input && input.method) || "GET").toUpperCase();
        if (init.headers) {
          if (init.headers.forEach) init.headers.forEach((v, k) => (headers[k] = v));
          else headers = Object.assign({}, init.headers);
        }
        body = init.body != null ? clip(init.body) : null;
      } catch (e) {}
      try {
        const resp = await origFetch(input, init);
        let respBody = null;
        const respHeaders = {};
        try {
          resp.headers.forEach((v, k) => (respHeaders[k] = v));
        } catch (e) {}
        try {
          const ct = (respHeaders["content-type"] || "").toLowerCase();
          if (ct.includes("json") || ct.includes("text") || ct === "") {
            respBody = clip(await resp.clone().text());
          }
        } catch (e) {}
        push({
          type: "fetch",
          url,
          method,
          request_headers: headers,
          request_body: body,
          status: resp.status,
          response_headers: respHeaders,
          response_body: respBody,
          duration_ms: Date.now() - started,
        });
        return resp;
      } catch (e) {
        push({
          type: "fetch",
          url,
          method,
          request_headers: headers,
          request_body: body,
          status: 0,
          error: String(e && e.message ? e.message : e),
          duration_ms: Date.now() - started,
        });
        throw e;
      }
    };
    window.fetch.__er = true;
  }

  // ---- XHR ----
  if (typeof XMLHttpRequest !== "undefined" && !XMLHttpRequest.prototype.__er) {
    const XO = XMLHttpRequest.prototype.open;
    const XS = XMLHttpRequest.prototype.send;
    const XH = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.open = function (method, url) {
      this.__er = { method: String(method || "GET").toUpperCase(), url: String(url || ""), headers: {}, body: null, started: 0 };
      return XO.apply(this, arguments);
    };
    XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
      try {
        if (this.__er) this.__er.headers[k] = v;
      } catch (e) {}
      return XH.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function (body) {
      const self = this;
      if (self.__er) {
        self.__er.body = clip(body);
        self.__er.started = Date.now();
        self.addEventListener("loadend", function () {
          let respBody = null;
          try {
            respBody = clip(self.responseText);
          } catch (e) {}
          push({
            type: "xhr",
            url: self.__er.url,
            method: self.__er.method,
            request_headers: self.__er.headers,
            request_body: self.__er.body,
            status: self.status,
            response_body: respBody,
            duration_ms: Date.now() - (self.__er.started || Date.now()),
          });
        });
      }
      return XS.apply(this, arguments);
    };
    XMLHttpRequest.prototype.__er = true;
  }

  // ---- WebSocket ----
  if (typeof WebSocket !== "undefined" && !WebSocket.__er) {
    const OWS = WebSocket;
    window.WebSocket = function (url, protocols) {
      const ws = protocols !== undefined ? new OWS(url, protocols) : new OWS(url);
      const rec = { url: String(url), frames: [] };
      h.ws.push(rec);
      const origSend = ws.send.bind(ws);
      ws.send = function (data) {
        if (rec.frames.length < 80) {
          rec.frames.push({ direction: "sent", payload: clip(data), ts: Date.now() });
        }
        push({
          type: "websocket_send",
          url: String(url),
          method: "WS",
          request_body: clip(data),
        });
        return origSend(data);
      };
      ws.addEventListener("message", function (ev) {
        if (rec.frames.length < 80) {
          rec.frames.push({ direction: "received", payload: clip(ev.data), ts: Date.now() });
        }
      });
      return ws;
    };
    window.WebSocket.prototype = OWS.prototype;
    try {
      Object.assign(window.WebSocket, OWS);
    } catch (e) {}
    WebSocket.__er = true;
  }

  // ---- Web Crypto ----
  try {
    const subtle = crypto && crypto.subtle;
    if (subtle && !subtle.__er) {
      const origDigest = subtle.digest.bind(subtle);
      const origSign = subtle.sign.bind(subtle);
      const origImportKey = subtle.importKey.bind(subtle);
      subtle.importKey = async function (format, keyData, algorithm, extractable, keyUsages) {
        const key = await origImportKey(format, keyData, algorithm, extractable, keyUsages);
        let key_text = null;
        try {
          const u8 = keyData instanceof ArrayBuffer ? new Uint8Array(keyData) : new Uint8Array(keyData);
          const s = new TextDecoder().decode(u8);
          if (/^[\x20-\x7e]+$/.test(s) && s.length <= 256) key_text = s;
        } catch (e) {}
        pushCrypto({
          api: "subtle.importKey",
          format: String(format),
          algorithm: clip(algorithm),
          key_hex: bufToHex(keyData),
          key_text,
        });
        try {
          key.__er_raw_hex = bufToHex(keyData);
        } catch (e) {}
        return key;
      };
      subtle.digest = async function (algorithm, data) {
        const out = await origDigest(algorithm, data);
        let data_text = null;
        try {
          data_text = clip(new TextDecoder().decode(data instanceof ArrayBuffer ? data : data));
        } catch (e) {}
        pushCrypto({
          api: "subtle.digest",
          algorithm: clip(algorithm),
          data_hex: bufToHex(data),
          data_text,
          result_hex: bufToHex(out),
        });
        return out;
      };
      subtle.sign = async function (algorithm, key, data) {
        const out = await origSign(algorithm, key, data);
        let data_text = null;
        try {
          data_text = clip(new TextDecoder().decode(data instanceof ArrayBuffer ? data : data));
        } catch (e) {}
        pushCrypto({
          api: "subtle.sign",
          algorithm: clip(algorithm),
          key_hex: (key && key.__er_raw_hex) || null,
          data_hex: bufToHex(data),
          data_text,
          result_hex: bufToHex(out),
        });
        return out;
      };
      subtle.__er = true;
    }
  } catch (e) {}

  // ---- CryptoJS ----
  const hookCryptoJS = () => {
    try {
      const C = window.CryptoJS;
      if (!C || C.__er_hooked) return;
      C.__er_hooked = true;
      const wrap = (name, label) => {
        if (!C[name] || C[name].__er) return;
        const orig = C[name];
        C[name] = function (message, key) {
          const result = orig.apply(this, arguments);
          let resStr = null;
          try {
            resStr = result && result.toString ? result.toString() : String(result);
          } catch (e) {}
          pushCrypto({
            api: "CryptoJS." + label,
            message: clip(typeof message === "string" ? message : message && message.toString && message.toString()),
            key: clip(typeof key === "string" ? key : key && key.toString && key.toString()),
            result: clip(resStr),
          });
          return result;
        };
        C[name].__er = true;
      };
      ["HmacSHA256", "HmacSHA1", "HmacSHA512", "HmacMD5", "SHA256", "SHA1", "MD5"].forEach((n) => wrap(n, n));
    } catch (e) {}
  };
  hookCryptoJS();
  let tries = 0;
  const iv = setInterval(() => {
    tries++;
    hookCryptoJS();
    if (tries > 40) clearInterval(iv);
  }, 500);

  h.installed = true;
  h.cryptoInstalled = true;

  // Discover signers
  window.__easy_rev_discover_signers__ = function () {
    const names = [];
    const re = /(sign|hmac|hash|digest|signature|encrypt|token|auth)/i;
    const pushN = (path, type) => {
      if (names.length < 60) names.push({ path, type });
    };
    const walk = (obj, prefix, depth) => {
      if (!obj || depth > 2 || names.length >= 60) return;
      let keys = [];
      try {
        keys = Object.getOwnPropertyNames(obj);
      } catch (e) {
        return;
      }
      for (const k of keys) {
        if (k.startsWith("_") || k === "window" || k === "document") continue;
        let v;
        try {
          v = obj[k];
        } catch (e) {
          continue;
        }
        const path = prefix ? prefix + "." + k : k;
        if (typeof v === "function" && re.test(k)) pushN(path, "function");
        else if (v && typeof v === "object" && re.test(k)) walk(v, path, depth + 1);
      }
    };
    try {
      walk(window, "", 0);
    } catch (e) {}
    [
      "sign",
      "signRequest",
      "signData",
      "getSign",
      "makeSign",
      "apiSign",
      "requestSign",
      "Auth.sign",
      "API.sign",
      "utils.sign",
    ].forEach((p) => {
      try {
        const parts = p.split(".");
        let cur = window;
        for (const part of parts) cur = cur && cur[part];
        if (typeof cur === "function") pushN(p, "known");
      } catch (e) {}
    });
    const seen = new Set();
    return names.filter((n) => (seen.has(n.path) ? false : (seen.add(n.path), true)));
  };

  window.__easy_rev_sign__ = async function (method, url, body, preferredPath) {
    const paths = [];
    if (preferredPath) paths.push(preferredPath);
    window.__easy_rev_discover_signers__().forEach((d) => paths.push(d.path));
    const seen = new Set();
    for (const path of paths) {
      if (!path || seen.has(path)) continue;
      seen.add(path);
      try {
        const parts = String(path).split(".");
        let cur = window;
        for (const p of parts) cur = cur && cur[p];
        if (typeof cur !== "function") continue;
        const attempts = [
          () => cur(body),
          () => cur(method, url, body),
          () => cur(url, body),
          () => cur({ method, url, body, data: body }),
        ];
        for (let i = 0; i < attempts.length; i++) {
          try {
            let result = attempts[i]();
            if (result && typeof result.then === "function") result = await result;
            let signature = null,
              headers = null;
            if (result == null) {
            } else if (typeof result === "string" || typeof result === "number") signature = String(result);
            else if (typeof result === "object") {
              headers = result.headers || result.header || null;
              signature = result.sign || result.signature || result.sig || result.token || null;
            }
            if (signature && !headers) headers = { "X-Signature": String(signature), "X-Sign": String(signature) };
            return { ok: true, path, strategy: i, signature, headers, raw: result };
          } catch (e) {}
        }
      } catch (e) {}
    }
    return { ok: false, error: "no signer callable" };
  };

  window.__easy_rev_dump__ = function () {
    return {
      installed: !!h.installed,
      cryptoInstalled: !!h.cryptoInstalled,
      traces: (h.traces || []).slice(-120),
      crypto: (h.crypto || []).slice(-150),
      ws: (h.ws || []).slice(-20),
      total_traces: (h.traces || []).length,
      total_crypto: (h.crypto || []).length,
      signers: window.__easy_rev_discover_signers__(),
    };
  };

  return { ok: true, installed: true };
})();
