"""Deep crypto API hooks — capture algorithm, key material, message, signature output."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Installed alongside network hooks. Writes to window.__easy_rev_hooks__.crypto
INSTALL_CRYPTO_HOOKS_JS = r"""() => {
  const h = window.__easy_rev_hooks__ = window.__easy_rev_hooks__ || { traces: [], ws: [] };
  if (h.cryptoInstalled) {
    return { already: true, crypto_events: (h.crypto || []).length };
  }
  h.cryptoInstalled = true;
  h.crypto = h.crypto || [];
  const MAX = 300;
  const MAX_S = 8000;

  const clip = (s) => {
    if (s == null) return null;
    const t = typeof s === 'string' ? s : (function() {
      try { return JSON.stringify(s); } catch (e) { return String(s); }
    })();
    return t.length > MAX_S ? t.slice(0, MAX_S) + '…' : t;
  };

  const bufToHex = (buf) => {
    try {
      const u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf)
        : (buf && buf.buffer) ? new Uint8Array(buf.buffer, buf.byteOffset || 0, buf.byteLength || buf.length)
        : null;
      if (!u8) return null;
      let out = '';
      const n = Math.min(u8.length, 256);
      for (let i = 0; i < n; i++) out += u8[i].toString(16).padStart(2, '0');
      if (u8.length > 256) out += '…';
      return out;
    } catch (e) { return null; }
  };

  const bufToB64 = (buf) => {
    try {
      const u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf)
        : (buf && buf.buffer) ? new Uint8Array(buf.buffer, buf.byteOffset || 0, buf.byteLength || buf.length)
        : null;
      if (!u8) return null;
      let s = '';
      const n = Math.min(u8.length, 4096);
      for (let i = 0; i < n; i++) s += String.fromCharCode(u8[i]);
      return btoa(s) + (u8.length > 4096 ? '…' : '');
    } catch (e) { return null; }
  };

  const stack = () => {
    try {
      return (new Error().stack || '').split('\n').slice(2, 14).map(x => x.trim()).filter(Boolean);
    } catch (e) { return []; }
  };

  const pushCrypto = (ev) => {
    if (h.crypto.length >= MAX) h.crypto.shift();
    ev.ts = Date.now();
    ev.stack = stack();
    h.crypto.push(ev);
  };

  // ---- Web Crypto subtle ----
  try {
    const subtle = crypto && crypto.subtle;
    if (subtle) {
      const origDigest = subtle.digest.bind(subtle);
      const origSign = subtle.sign.bind(subtle);
      const origImportKey = subtle.importKey.bind(subtle);
      const origEncrypt = subtle.encrypt ? subtle.encrypt.bind(subtle) : null;

      subtle.importKey = async function(format, keyData, algorithm, extractable, keyUsages) {
        const key = await origImportKey(format, keyData, algorithm, extractable, keyUsages);
        pushCrypto({
          api: 'subtle.importKey',
          format: String(format),
          algorithm: clip(algorithm),
          extractable: !!extractable,
          keyUsages: keyUsages,
          key_hex: bufToHex(keyData),
          key_b64: bufToB64(keyData),
          key_text: (function() {
            try {
              const u8 = keyData instanceof ArrayBuffer ? new Uint8Array(keyData) : new Uint8Array(keyData);
              const s = new TextDecoder().decode(u8);
              if (/^[\x20-\x7e]+$/.test(s) && s.length <= 256) return s;
            } catch (e) {}
            return null;
          })(),
        });
        // stash raw on key object for later (best-effort)
        try { key.__er_raw_hex = bufToHex(keyData); key.__er_alg = algorithm; } catch (e) {}
        return key;
      };

      subtle.digest = async function(algorithm, data) {
        const out = await origDigest(algorithm, data);
        pushCrypto({
          api: 'subtle.digest',
          algorithm: clip(algorithm),
          data_hex: bufToHex(data),
          data_text: (function() {
            try {
              return clip(new TextDecoder().decode(
                data instanceof ArrayBuffer ? data : data));
            } catch (e) { return null; }
          })(),
          result_hex: bufToHex(out),
          result_b64: bufToB64(out),
        });
        return out;
      };

      subtle.sign = async function(algorithm, key, data) {
        const out = await origSign(algorithm, key, data);
        pushCrypto({
          api: 'subtle.sign',
          algorithm: clip(algorithm),
          key_meta: key && (key.__er_alg || key.algorithm) ? clip(key.__er_alg || key.algorithm) : null,
          key_hex: key && key.__er_raw_hex || null,
          data_hex: bufToHex(data),
          data_text: (function() {
            try {
              return clip(new TextDecoder().decode(
                data instanceof ArrayBuffer ? data : data));
            } catch (e) { return null; }
          })(),
          result_hex: bufToHex(out),
          result_b64: bufToB64(out),
        });
        return out;
      };

      if (origEncrypt) {
        subtle.encrypt = async function(algorithm, key, data) {
          const out = await origEncrypt(algorithm, key, data);
          pushCrypto({
            api: 'subtle.encrypt',
            algorithm: clip(algorithm),
            key_hex: key && key.__er_raw_hex || null,
            data_hex: bufToHex(data),
            result_hex: bufToHex(out),
          });
          return out;
        };
      }
    }
  } catch (e) {
    pushCrypto({ api: 'subtle.hook_error', error: String(e) });
  }

  // ---- CryptoJS common entry points ----
  const hookCryptoJS = () => {
    try {
      const C = window.CryptoJS;
      if (!C || C.__er_hooked) return;
      C.__er_hooked = true;
      const wrap = (obj, name, algLabel) => {
        if (!obj || !obj[name] || obj[name].__er) return;
        const orig = obj[name];
        obj[name] = function(message, key) {
          const result = orig.apply(this, arguments);
          let resStr = null;
          try { resStr = result && result.toString ? result.toString() : String(result); } catch (e) {}
          pushCrypto({
            api: 'CryptoJS.' + algLabel,
            message: clip(typeof message === 'string' ? message : (message && message.toString && message.toString())),
            key: clip(typeof key === 'string' ? key : (key && key.toString && key.toString())),
            result: clip(resStr),
          });
          return result;
        };
        obj[name].__er = true;
      };
      wrap(C, 'HmacSHA256', 'HmacSHA256');
      wrap(C, 'HmacSHA1', 'HmacSHA1');
      wrap(C, 'HmacSHA512', 'HmacSHA512');
      wrap(C, 'HmacMD5', 'HmacMD5');
      wrap(C, 'SHA256', 'SHA256');
      wrap(C, 'SHA1', 'SHA1');
      wrap(C, 'MD5', 'MD5');
      if (C.AES && C.AES.encrypt) {
        const oenc = C.AES.encrypt;
        C.AES.encrypt = function(message, key, cfg) {
          const result = oenc.apply(this, arguments);
          pushCrypto({
            api: 'CryptoJS.AES.encrypt',
            message: clip(String(message)),
            key: clip(String(key)),
            result: clip(result && result.toString ? result.toString() : String(result)),
          });
          return result;
        };
      }
    } catch (e) {}
  };
  hookCryptoJS();
  // late-loaded CryptoJS
  let tries = 0;
  const iv = setInterval(() => {
    tries++;
    hookCryptoJS();
    if (tries > 40) clearInterval(iv);
  }, 500);

  // ---- js-sha256 / md5 style globals ----
  ['sha256', 'sha1', 'md5', 'hmac_sha256', 'hmacSha256'].forEach((name) => {
    try {
      const fn = window[name];
      if (typeof fn !== 'function' || fn.__er) return;
      const orig = fn;
      window[name] = function() {
        const result = orig.apply(this, arguments);
        pushCrypto({
          api: 'global.' + name,
          args: clip([].slice.call(arguments, 0, 3)),
          result: clip(result),
        });
        return result;
      };
      window[name].__er = true;
    } catch (e) {}
  });

  // ---- btoa of long strings (often final signature packaging) ----
  try {
    const ob = window.btoa;
    window.btoa = function(s) {
      const r = ob.apply(this, arguments);
      if (s && String(s).length >= 16) {
        pushCrypto({ api: 'btoa', input: clip(String(s)), result: clip(r) });
      }
      return r;
    };
  } catch (e) {}

  return { already: false, crypto_events: 0 };
}"""

DUMP_CRYPTO_JS = r"""(maxN) => {
  const h = window.__easy_rev_hooks__;
  if (!h) return { installed: false, events: [] };
  const n = maxN || 150;
  return {
    installed: !!h.cryptoInstalled,
    events: (h.crypto || []).slice(-n),
    total: (h.crypto || []).length,
  };
}"""


async def install_crypto_hooks(page: Any) -> dict[str, Any]:
    if not page:
        return {"ok": False, "error": "no page"}
    try:
        context = getattr(page, "context", None)
        if context is not None and hasattr(context, "add_init_script"):
            try:
                await context.add_init_script(
                    f"(() => {{ ({INSTALL_CRYPTO_HOOKS_JS})(); }})();"
                )
            except Exception:  # noqa: BLE001
                pass
        result = await page.evaluate(INSTALL_CRYPTO_HOOKS_JS)
        return {"ok": True, "result": result}
    except Exception as e:  # noqa: BLE001
        logger.warning("crypto hooks failed: %s", e)
        return {"ok": False, "error": str(e)}


async def dump_crypto_events(page: Any, *, max_events: int = 150) -> dict[str, Any]:
    if not page:
        return {"installed": False, "events": []}
    try:
        data = await page.evaluate(DUMP_CRYPTO_JS, max_events)
        return data if isinstance(data, dict) else {"installed": False, "events": []}
    except Exception as e:  # noqa: BLE001
        return {"installed": False, "events": [], "error": str(e)}
