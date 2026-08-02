"""Browser-side signing oracle: discover + invoke page sign functions for strong signatures."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Discover callable globals / nested methods that look like signers
DISCOVER_SIGNERS_JS = r"""() => {
  const names = [];
  const push = (path, type) => {
    if (names.length < 80) names.push({ path, type });
  };
  const re = /(sign|hmac|hash|digest|signature|encrypt|token|auth)/i;
  const walk = (obj, prefix, depth) => {
    if (!obj || depth > 3 || names.length >= 80) return;
    let keys = [];
    try { keys = Object.getOwnPropertyNames(obj); } catch (e) { return; }
    for (const k of keys) {
      if (k.startsWith('_') && k !== '__easy_rev_hooks__') continue;
      if (k === 'window' || k === 'self' || k === 'document' || k === 'frames') continue;
      let v;
      try { v = obj[k]; } catch (e) { continue; }
      const path = prefix ? prefix + '.' + k : k;
      if (typeof v === 'function' && re.test(k)) {
        push(path, 'function');
      } else if (v && typeof v === 'object' && re.test(k) && depth < 2) {
        walk(v, path, depth + 1);
      }
    }
  };
  try { walk(window, '', 0); } catch (e) {}
  // common frameworks
  for (const p of [
    'sign', 'signRequest', 'signData', 'getSign', 'makeSign', 'createSign',
    'cryptoSign', 'hmacSign', 'apiSign', 'requestSign',
    'Auth.sign', 'API.sign', 'utils.sign', 'util.sign', 'helper.sign',
    '__APP__.sign', 'app.sign',
  ]) {
    try {
      const parts = p.split('.');
      let cur = window;
      for (const part of parts) cur = cur && cur[part];
      if (typeof cur === 'function') push(p, 'known');
    } catch (e) {}
  }
  // from hook stacks
  const h = window.__easy_rev_hooks__;
  if (h && h.crypto) {
    for (const ev of h.crypto.slice(-30)) {
      for (const line of (ev.stack || [])) {
        const m = line.match(/at\s+(\w+)\s+/);
        if (m && re.test(m[1])) push(m[1], 'stack');
      }
    }
  }
  // unique
  const seen = new Set();
  const out = [];
  for (const n of names) {
    if (seen.has(n.path)) continue;
    seen.add(n.path);
    out.push(n);
  }
  return out;
}"""

# Invoke a path like "API.sign" or "signRequest" with flexible args
INVOKE_SIGNER_JS = r"""(args) => {
  const path = args.path;
  const payload = args.payload;
  const method = args.method || 'POST';
  const url = args.url || '';
  const parts = String(path).split('.');
  let cur = window;
  for (const p of parts) {
    if (cur == null) return { ok: false, error: 'path broken at ' + p };
    cur = cur[p];
  }
  if (typeof cur !== 'function') return { ok: false, error: 'not a function: ' + path };

  const tryCalls = [];
  // strategies: (payload), (method,url,payload), (url,payload), ({method,url,body})
  tryCalls.push(() => cur(payload));
  tryCalls.push(() => cur(method, url, payload));
  tryCalls.push(() => cur(url, payload));
  tryCalls.push(() => cur({ method, url, body: payload, data: payload }));
  tryCalls.push(() => cur(JSON.stringify(payload)));
  tryCalls.push(() => cur(method, payload));

  const errors = [];
  for (let i = 0; i < tryCalls.length; i++) {
    try {
      const result = tryCalls[i]();
      // handle Promise
      return { ok: true, sync: true, strategy: i, result: result };
    } catch (e) {
      errors.push(String(e && e.message ? e.message : e));
    }
  }
  return { ok: false, error: errors.slice(0, 5).join(' | ') };
}"""

# Async invoke (returns promise resolution via playwright)
INVOKE_SIGNER_ASYNC_JS = r"""async (args) => {
  const path = args.path;
  const payload = args.payload;
  const method = args.method || 'POST';
  const url = args.url || '';
  const parts = String(path).split('.');
  let cur = window;
  for (const p of parts) {
    if (cur == null) return { ok: false, error: 'path broken' };
    cur = cur[p];
  }
  if (typeof cur !== 'function') return { ok: false, error: 'not a function' };
  const strategies = [
    () => cur(payload),
    () => cur(method, url, payload),
    () => cur(url, payload),
    () => cur({ method, url, body: payload, data: payload }),
    () => cur(JSON.stringify(payload || {})),
  ];
  const errors = [];
  for (let i = 0; i < strategies.length; i++) {
    try {
      let result = strategies[i]();
      if (result && typeof result.then === 'function') result = await result;
      // normalize
      let headers = null;
      let body = null;
      let signature = null;
      if (result == null) {
        signature = null;
      } else if (typeof result === 'string' || typeof result === 'number') {
        signature = String(result);
      } else if (typeof result === 'object') {
        headers = result.headers || result.header || null;
        body = result.body || result.data || result.payload || null;
        signature = result.sign || result.signature || result.sig || result.token || null;
        if (!signature && !headers && !body) {
          try { signature = JSON.stringify(result); } catch (e) { signature = String(result); }
        }
      }
      return {
        ok: true,
        strategy: i,
        signature,
        headers,
        body,
        raw_type: typeof result,
      };
    } catch (e) {
      errors.push(String(e && e.message ? e.message : e));
    }
  }
  return { ok: false, error: errors.join(' | ') };
}"""

# Install a stable oracle entry point used by http.sign_via_browser
INSTALL_ORACLE_BRIDGE_JS = r"""(preferredPaths) => {
  const paths = preferredPaths || [];
  window.__easy_rev_sign__ = async function(method, url, body) {
    const payload = body;
    const tryPaths = paths.concat([
      'signRequest', 'sign', 'getSign', 'makeSign', 'apiSign', 'requestSign',
      'Auth.sign', 'API.sign', 'utils.sign',
    ]);
    const seen = new Set();
    for (const path of tryPaths) {
      if (!path || seen.has(path)) continue;
      seen.add(path);
      try {
        const parts = String(path).split('.');
        let cur = window;
        for (const p of parts) cur = cur && cur[p];
        if (typeof cur !== 'function') continue;
        const attempts = [
          () => cur(payload),
          () => cur(method, url, payload),
          () => cur(url, payload),
          () => cur({ method, url, body: payload, data: payload }),
        ];
        for (let i = 0; i < attempts.length; i++) {
          try {
            let result = attempts[i]();
            if (result && typeof result.then === 'function') result = await result;
            return { ok: true, path, strategy: i, result };
          } catch (e) {}
        }
      } catch (e) {}
    }
    // Fallback: use last crypto event pattern — cannot invent sig
    return { ok: false, error: 'no signer callable; ensure page sign functions loaded' };
  };
  return true;
}"""


async def discover_signers(page: Any) -> list[dict[str, str]]:
    if not page:
        return []
    try:
        data = await page.evaluate(DISCOVER_SIGNERS_JS)
        return data if isinstance(data, list) else []
    except Exception as e:  # noqa: BLE001
        logger.warning("discover_signers: %s", e)
        return []


async def install_sign_oracle(page: Any, preferred_paths: list[str] | None = None) -> bool:
    if not page:
        return False
    try:
        await page.evaluate(INSTALL_ORACLE_BRIDGE_JS, preferred_paths or [])
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning("install_sign_oracle: %s", e)
        return False


async def oracle_sign(
    page: Any,
    *,
    method: str = "POST",
    url: str = "",
    body: Any = None,
    signer_path: str | None = None,
) -> dict[str, Any]:
    """Sign using browser JS — the commercial path for strong/obfuscated signatures."""
    if not page:
        return {"ok": False, "error": "no page"}

    # Ensure bridge
    paths = [signer_path] if signer_path else []
    if not paths:
        discovered = await discover_signers(page)
        paths = [d["path"] for d in discovered if d.get("path")]
    await install_sign_oracle(page, paths)

    try:
        if signer_path:
            result = await page.evaluate(
                INVOKE_SIGNER_ASYNC_JS,
                {
                    "path": signer_path,
                    "payload": body,
                    "method": method,
                    "url": url,
                },
            )
            if isinstance(result, dict) and result.get("ok"):
                return _normalize_oracle_result(result, signer_path)
        # bridge
        result = await page.evaluate(
            """async ([method, url, body]) => {
              if (!window.__easy_rev_sign__) return { ok: false, error: 'oracle not installed' };
              return await window.__easy_rev_sign__(method, url, body);
            }""",
            [method, url, body],
        )
        if isinstance(result, dict):
            if result.get("ok"):
                return _normalize_oracle_result(
                    {
                        "ok": True,
                        "signature": _extract_sig(result.get("result")),
                        "headers": _extract_headers(result.get("result")),
                        "body": _extract_body(result.get("result")),
                        "raw": result.get("result"),
                        "path": result.get("path"),
                        "strategy": result.get("strategy"),
                    },
                    result.get("path"),
                )
            return result
        return {"ok": False, "error": "unexpected oracle result", "raw": result}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def _extract_sig(result: Any) -> str | None:
    if result is None:
        return None
    if isinstance(result, (str, int, float)):
        return str(result)
    if isinstance(result, dict):
        for k in ("sign", "signature", "sig", "token", "hmac", "hash"):
            if k in result and result[k] is not None:
                return str(result[k])
    return None


def _extract_headers(result: Any) -> dict[str, str] | None:
    if not isinstance(result, dict):
        return None
    h = result.get("headers") or result.get("header")
    if isinstance(h, dict):
        return {str(k): str(v) for k, v in h.items()}
    return None


def _extract_body(result: Any) -> Any:
    if not isinstance(result, dict):
        return None
    return result.get("body") or result.get("data") or result.get("payload")


def _normalize_oracle_result(result: dict[str, Any], path: str | None) -> dict[str, Any]:
    out = {
        "ok": True,
        "signer_path": path or result.get("path"),
        "strategy": result.get("strategy"),
        "signature": result.get("signature") or _extract_sig(result.get("raw") or result.get("result")),
        "headers": result.get("headers") or _extract_headers(result.get("raw") or result.get("result")),
        "body": result.get("body") if "body" in result else _extract_body(result.get("raw") or result.get("result")),
        "raw": result.get("raw") or result.get("result"),
    }
    # If only signature string, invent common header placement
    if out["signature"] and not out["headers"]:
        out["headers"] = {
            "X-Signature": str(out["signature"]),
            "X-Sign": str(out["signature"]),
        }
        out["suggested_header"] = "X-Signature"
    return out


async def oracle_sign_batch(
    page: Any,
    items: list[dict[str, Any]],
    *,
    signer_path: str | None = None,
    default_method: str = "POST",
    default_url: str = "",
    stop_on_error: bool = False,
) -> dict[str, Any]:
    """Sign many payloads with one live page (commercial bulk oracle).

    Each item: {method?, url?, json?|body?, signer_path?, id?}
    """
    if not page:
        return {"ok": False, "error": "no page", "results": []}
    # Install oracle once with preferred path
    paths = [signer_path] if signer_path else []
    if not paths:
        discovered = await discover_signers(page)
        paths = [d["path"] for d in discovered if d.get("path")]
    await install_sign_oracle(page, paths)

    results: list[dict[str, Any]] = []
    ok_n = 0
    for i, item in enumerate(items or []):
        if not isinstance(item, dict):
            results.append({"index": i, "ok": False, "error": "item must be object"})
            if stop_on_error:
                break
            continue
        method = str(item.get("method") or default_method)
        url = str(item.get("url") or default_url)
        body = item.get("json") if item.get("json") is not None else item.get("body")
        path = item.get("signer_path") or signer_path
        res = await oracle_sign(
            page, method=method, url=url, body=body, signer_path=str(path) if path else None
        )
        entry = {
            "index": i,
            "id": item.get("id"),
            "ok": bool(res.get("ok")),
            "method": method,
            "url": url,
            "signer_path": res.get("signer_path") or path,
            "headers": res.get("headers"),
            "signature": res.get("signature"),
            "body": res.get("body"),
            "error": res.get("error"),
        }
        if entry["ok"]:
            ok_n += 1
        results.append(entry)
        if stop_on_error and not entry["ok"]:
            break

    return {
        "ok": ok_n == len(results) and len(results) > 0,
        "total": len(results),
        "success": ok_n,
        "failed": len(results) - ok_n,
        "signer_path": signer_path or (paths[0] if paths else None),
        "results": results,
    }


async def auto_probe_signers(
    page: Any,
    *,
    sample_body: dict[str, Any] | None = None,
    method: str = "POST",
    url: str = "https://example.com/api",
    max_try: int = 12,
) -> dict[str, Any]:
    """Try discovered signers with a sample payload; return working ones."""
    discovered = await discover_signers(page)
    sample_body = sample_body or {"email": "probe@example.test", "password": "Probe1!aaaa"}
    working: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for item in discovered[:max_try]:
        path = item.get("path")
        if not path:
            continue
        res = await oracle_sign(
            page, method=method, url=url, body=sample_body, signer_path=str(path)
        )
        if res.get("ok") and (res.get("signature") or res.get("headers") or res.get("body")):
            working.append({"path": path, "type": item.get("type"), "result": res})
        else:
            failed.append({"path": path, "error": res.get("error")})
    return {
        "discovered": discovered,
        "working": working,
        "failed": failed[:20],
        "best": working[0] if working else None,
    }
