"""Inject runtime hooks to capture fetch/XHR/WebSocket with call stacks (signing traces)."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Self-contained IIFE installed via page.add_init_script or evaluate.
# Stores traces on window.__easy_rev_hooks__
INSTALL_HOOKS_JS = r"""() => {
  if (window.__easy_rev_hooks__ && window.__easy_rev_hooks__.installed) {
    return { already: true, count: (window.__easy_rev_hooks__.traces || []).length };
  }
  const MAX = 200;
  const MAX_BODY = 16000;
  const state = {
    installed: true,
    traces: [],
    ws: [],
  };
  window.__easy_rev_hooks__ = state;

  const clip = (s) => {
    if (s == null) return null;
    const t = typeof s === 'string' ? s : (function() {
      try { return JSON.stringify(s); } catch (e) { return String(s); }
    })();
    return t.length > MAX_BODY ? t.slice(0, MAX_BODY) + '…' : t;
  };

  const stack = () => {
    try {
      const e = new Error();
      return (e.stack || '').split('\n').slice(2, 12).map(x => x.trim()).filter(Boolean);
    } catch (err) {
      return [];
    }
  };

  const push = (entry) => {
    if (state.traces.length >= MAX) state.traces.shift();
    entry.ts = Date.now();
    entry.stack = stack();
    state.traces.push(entry);
  };

  // ---- fetch ----
  if (typeof window.fetch === 'function') {
    const origFetch = window.fetch.bind(window);
    window.fetch = async function(input, init) {
      const started = Date.now();
      let url = '';
      let method = 'GET';
      let headers = {};
      let body = null;
      try {
        if (typeof input === 'string') url = input;
        else if (input && input.url) url = input.url;
        init = init || {};
        method = (init.method || (input && input.method) || 'GET').toUpperCase();
        if (init.headers) {
          if (init.headers.forEach) init.headers.forEach((v, k) => { headers[k] = v; });
          else headers = Object.assign({}, init.headers);
        }
        body = init.body != null ? clip(init.body) : null;
      } catch (e) {}

      let status = 0;
      let respBody = null;
      let respHeaders = {};
      let err = null;
      try {
        const resp = await origFetch(input, init);
        status = resp.status;
        try {
          resp.headers.forEach((v, k) => { respHeaders[k] = v; });
        } catch (e) {}
        try {
          const clone = resp.clone();
          const ct = (respHeaders['content-type'] || respHeaders['Content-Type'] || '').toLowerCase();
          if (ct.includes('json') || ct.includes('text') || ct.includes('javascript') || ct === '') {
            respBody = clip(await clone.text());
          } else {
            respBody = `<binary content-type=${ct}>`;
          }
        } catch (e) {
          respBody = null;
        }
        push({
          type: 'fetch',
          url, method, request_headers: headers, request_body: body,
          status, response_headers: respHeaders, response_body: respBody,
          duration_ms: Date.now() - started, error: null,
        });
        return resp;
      } catch (e) {
        err = String(e && e.message ? e.message : e);
        push({
          type: 'fetch',
          url, method, request_headers: headers, request_body: body,
          status: 0, response_headers: {}, response_body: null,
          duration_ms: Date.now() - started, error: err,
        });
        throw e;
      }
    };
  }

  // ---- XHR ----
  if (typeof XMLHttpRequest !== 'undefined') {
    const XO = XMLHttpRequest.prototype.open;
    const XS = XMLHttpRequest.prototype.send;
    const XH = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.open = function(method, url) {
      this.__er = {
        method: String(method || 'GET').toUpperCase(),
        url: String(url || ''), headers: {}, body: null, started: 0 };
      return XO.apply(this, arguments);
    };
    XMLHttpRequest.prototype.setRequestHeader = function(k, v) {
      try { if (this.__er) this.__er.headers[k] = v; } catch (e) {}
      return XH.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(body) {
      const self = this;
      if (self.__er) {
        self.__er.body = clip(body);
        self.__er.started = Date.now();
        self.addEventListener('loadend', function() {
          let respBody = null;
          try { respBody = clip(self.responseText); } catch (e) {}
          push({
            type: 'xhr',
            url: self.__er.url,
            method: self.__er.method,
            request_headers: self.__er.headers,
            request_body: self.__er.body,
            status: self.status,
            response_headers: {},
            response_body: respBody,
            duration_ms: Date.now() - (self.__er.started || Date.now()),
            error: null,
          });
        });
      }
      return XS.apply(this, arguments);
    };
  }

  // ---- WebSocket ----
  if (typeof WebSocket !== 'undefined') {
    const OWS = WebSocket;
    window.WebSocket = function(url, protocols) {
      const ws = protocols !== undefined ? new OWS(url, protocols) : new OWS(url);
      const rec = { url: String(url), frames: [] };
      state.ws.push(rec);
      const origSend = ws.send.bind(ws);
      ws.send = function(data) {
        if (rec.frames.length < 100) {
          rec.frames.push({ direction: 'sent', payload: clip(data), ts: Date.now() });
        }
        // also as trace for signing-ish traffic
        push({
          type: 'websocket_send',
          url: String(url),
          method: 'WS',
          request_headers: {},
          request_body: clip(data),
          status: null,
          response_headers: {},
          response_body: null,
          duration_ms: 0,
          error: null,
        });
        return origSend(data);
      };
      ws.addEventListener('message', function(ev) {
        if (rec.frames.length < 100) {
          rec.frames.push({ direction: 'received', payload: clip(ev.data), ts: Date.now() });
        }
      });
      return ws;
    };
    window.WebSocket.prototype = OWS.prototype;
    try {
      Object.assign(window.WebSocket, OWS);
    } catch (e) {}
  }

  return { already: false, count: 0 };
}"""

DUMP_HOOKS_JS = r"""(maxTraces) => {
  const h = window.__easy_rev_hooks__;
  if (!h) return { installed: false, traces: [], ws: [] };
  const n = maxTraces || 100;
  return {
    installed: !!h.installed,
    traces: (h.traces || []).slice(-n),
    ws: (h.ws || []).slice(-20),
    total: (h.traces || []).length,
  };
}"""

CLEAR_HOOKS_JS = r"""() => {
  const h = window.__easy_rev_hooks__;
  if (!h) return false;
  h.traces = [];
  h.ws = [];
  return true;
}"""


async def install_runtime_hooks(page: Any) -> dict[str, Any]:
    """Install network + crypto hooks on an existing page.

    Prefer install_init_script before first navigation when possible.
    """
    if not page:
        return {"ok": False, "error": "no page"}
    try:
        # try add_init_script for future navigations
        context = getattr(page, "context", None)
        if context is not None and hasattr(context, "add_init_script"):
            try:
                await context.add_init_script(f"(() => {{ ({INSTALL_HOOKS_JS})(); }})();")
            except Exception:  # noqa: BLE001
                pass
        result = await page.evaluate(INSTALL_HOOKS_JS)
        crypto_res = None
        try:
            from easy_rev.platforms.web.re.crypto_hooks import install_crypto_hooks

            crypto_res = await install_crypto_hooks(page)
        except Exception as e:  # noqa: BLE001
            crypto_res = {"ok": False, "error": str(e)}
        return {"ok": True, "result": result, "crypto": crypto_res}
    except Exception as e:  # noqa: BLE001
        logger.warning("install_runtime_hooks failed: %s", e)
        return {"ok": False, "error": str(e)}


async def dump_runtime_hooks(page: Any, *, max_traces: int = 100) -> dict[str, Any]:
    if not page:
        return {"installed": False, "traces": [], "ws": []}
    try:
        data = await page.evaluate(DUMP_HOOKS_JS, max_traces)
        return data if isinstance(data, dict) else {"installed": False, "traces": [], "ws": []}
    except Exception as e:  # noqa: BLE001
        return {"installed": False, "traces": [], "ws": [], "error": str(e)}


async def clear_runtime_hooks(page: Any) -> bool:
    if not page:
        return False
    try:
        return bool(await page.evaluate(CLEAR_HOOKS_JS))
    except Exception:  # noqa: BLE001
        return False


def analyze_signing_traces(traces: list[dict[str, Any]]) -> dict[str, Any]:
    """Heuristic: find headers/body fields that look like signatures across traces."""
    sig_header_hits: dict[str, int] = {}
    sig_body_keys: dict[str, int] = {}
    stack_files: dict[str, int] = {}
    interesting: list[dict[str, Any]] = []

    sig_header_names = (
        "authorization",
        "x-signature",
        "x-sign",
        "x-sig",
        "x-hmac",
        "x-api-sign",
        "sign",
        "signature",
        "x-csrf-token",
        "x-xsrf-token",
        "x-request-id",
        "x-timestamp",
        "x-nonce",
    )

    for t in traces:
        headers = t.get("request_headers") or {}
        for k, v in headers.items():
            kl = str(k).lower()
            if any(s in kl for s in sig_header_names) or (
                isinstance(v, str) and len(v) >= 16 and kl not in {"cookie", "user-agent", "accept"}
            ):
                if any(s in kl for s in ("sign", "sig", "hmac", "auth", "token", "nonce", "timestamp")):
                    sig_header_hits[kl] = sig_header_hits.get(kl, 0) + 1

        body = t.get("request_body") or ""
        if body and body.strip()[:1] in "{[":
            try:
                import json

                data = json.loads(body)
                if isinstance(data, dict):
                    for bk in data:
                        bkl = str(bk).lower()
                        if any(x in bkl for x in ("sign", "sig", "hmac", "token", "nonce", "timestamp", "hash")):
                            sig_body_keys[bkl] = sig_body_keys.get(bkl, 0) + 1
            except Exception:  # noqa: BLE001
                pass

        for line in t.get("stack") or []:
            # extract filename-ish
            if ".js" in line:
                # rough: foo.js:12:34
                import re

                m = re.search(r"([\w./-]+\.js)", line)
                if m:
                    stack_files[m.group(1)] = stack_files.get(m.group(1), 0) + 1

        method = str(t.get("method") or "").upper()
        url = str(t.get("url") or "")
        if method in {"POST", "PUT", "PATCH"} or any(
            x in url.lower() for x in ("register", "signup", "auth", "login", "api")
        ):
            interesting.append(
                {
                    "type": t.get("type"),
                    "method": method,
                    "url": url[:300],
                    "status": t.get("status"),
                    "has_body": bool(t.get("request_body")),
                    "stack_top": (t.get("stack") or [])[:4],
                    "sig_headers": [
                        k
                        for k in (t.get("request_headers") or {})
                        if any(
                            s in str(k).lower()
                            for s in ("sign", "sig", "hmac", "auth", "token", "nonce", "timestamp")
                        )
                    ],
                }
            )

    recommendations: list[str] = []
    if sig_header_hits:
        recommendations.append(
            "Dynamic traces show signed headers: "
            + ", ".join(sorted(sig_header_hits.keys())[:8])
            + ". Capture one full request and reimplement sign in hooks.py or keep hybrid browser."
        )
    if sig_body_keys:
        recommendations.append(
            "Signed body fields: " + ", ".join(sorted(sig_body_keys.keys())[:8])
        )
    if stack_files:
        top = sorted(stack_files.items(), key=lambda x: -x[1])[:5]
        recommendations.append(
            "Likely JS files in call stack: " + ", ".join(f"{a}({b})" for a, b in top)
        )
    if not recommendations:
        recommendations.append(
            "No strong runtime signature headers detected; pure http.request pack may work."
        )

    return {
        "sig_headers": sig_header_hits,
        "sig_body_keys": sig_body_keys,
        "stack_files": dict(sorted(stack_files.items(), key=lambda x: -x[1])[:15]),
        "interesting_calls": interesting[-40:],
        "recommendations": recommendations,
        "trace_count": len(traces),
    }
