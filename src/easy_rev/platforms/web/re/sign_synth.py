"""Synthesize real Python sign_request implementations from crypto hook events."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any


def analyze_crypto_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Classify recoverable algorithms and extract key material."""
    hmac_events = []
    digest_events = []
    import_keys = []
    aes_events = []
    other = []

    for ev in events or []:
        api = str(ev.get("api") or "")
        if "HmacSHA256" in api or (
            api == "subtle.sign" and "HMAC" in json.dumps(ev.get("algorithm") or "").upper()
        ):
            hmac_events.append(ev)
        elif "HmacSHA1" in api or "HmacSHA512" in api or "HmacMD5" in api:
            hmac_events.append(ev)
        elif "digest" in api.lower() or api in {"CryptoJS.SHA256", "CryptoJS.MD5", "CryptoJS.SHA1"}:
            digest_events.append(ev)
        elif "importKey" in api:
            import_keys.append(ev)
        elif "AES" in api or "encrypt" in api.lower():
            aes_events.append(ev)
        else:
            other.append(ev)

    # Recover HMAC-SHA256 with string key
    recoverable: list[dict[str, Any]] = []
    for ev in hmac_events:
        key = ev.get("key") or ev.get("key_text") or ev.get("key_hex")
        msg = ev.get("message") or ev.get("data_text")
        result = ev.get("result") or ev.get("result_hex") or ev.get("result_b64")
        alg = "sha256"
        api = str(ev.get("api") or "")
        if "SHA1" in api:
            alg = "sha1"
        elif "SHA512" in api:
            alg = "sha512"
        elif "MD5" in api:
            alg = "md5"
        if key and msg is not None:
            # verify if we can reproduce
            verified = False
            py_result = None
            try:
                key_b = _key_bytes(key)
                msg_b = str(msg).encode()
                dig = {
                    "sha256": hashlib.sha256,
                    "sha1": hashlib.sha1,
                    "sha512": hashlib.sha512,
                    "md5": hashlib.md5,
                }[alg]
                py_result = hmac.new(key_b, msg_b, dig).hexdigest()
                if result and str(result).lower().replace(" ", "") in {
                    py_result,
                    py_result[: len(str(result))],
                }:
                    verified = True
                # CryptoJS often returns hex by default
                if result and py_result == str(result).lower():
                    verified = True
            except Exception:  # noqa: BLE001
                pass
            recoverable.append(
                {
                    "kind": "hmac",
                    "alg": alg,
                    "key": key if isinstance(key, str) else str(key),
                    "message_sample": str(msg)[:200],
                    "result_sample": str(result)[:200] if result else None,
                    "verified": verified,
                    "python_result": py_result,
                    "api": api,
                }
            )

    for ev in import_keys:
        if ev.get("key_text") or ev.get("key_hex"):
            recoverable.append(
                {
                    "kind": "imported_key",
                    "key_text": ev.get("key_text"),
                    "key_hex": ev.get("key_hex"),
                    "algorithm": ev.get("algorithm"),
                    "api": ev.get("api"),
                }
            )

    # Infer message template from data_text patterns
    templates = _infer_message_templates(hmac_events + digest_events)

    confidence = "none"
    if any(r.get("verified") for r in recoverable if r.get("kind") == "hmac"):
        confidence = "high"
    elif any(r.get("kind") == "hmac" and r.get("key") for r in recoverable):
        confidence = "medium"
    elif recoverable:
        confidence = "low"
    elif aes_events:
        confidence = "oracle_only"  # need browser oracle

    return {
        "hmac_events": len(hmac_events),
        "digest_events": len(digest_events),
        "import_keys": len(import_keys),
        "aes_events": len(aes_events),
        "other_events": len(other),
        "recoverable": recoverable[:20],
        "message_templates": templates[:10],
        "confidence": confidence,
        "recommendation": _rec(confidence, recoverable, aes_events),
    }


def _key_bytes(key: Any) -> bytes:
    if isinstance(key, bytes):
        return key
    s = str(key)
    # hex?
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0 and len(s) >= 16:
        try:
            return bytes.fromhex(s)
        except Exception:  # noqa: BLE001
            pass
    return s.encode()


def _infer_message_templates(events: list[dict[str, Any]]) -> list[str]:
    samples = []
    for ev in events:
        t = ev.get("message") or ev.get("data_text")
        if t and isinstance(t, str) and len(t) < 500:
            samples.append(t)
    templates = []
    for s in samples[:20]:
        # replace long hex/base64-ish with placeholders
        t = re.sub(r"[0-9a-fA-F]{16,}", "{HEX}", s)
        t = re.sub(r"\d{10,13}", "{TS}", t)
        t = re.sub(
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "{EMAIL}",
            t,
        )
        if t not in templates:
            templates.append(t)
    return templates


def _rec(confidence: str, recoverable: list[dict[str, Any]], aes: list[dict[str, Any]]) -> str:
    if confidence == "high":
        return "HMAC key verified — auto-generate pure Python sign_request hooks"
    if confidence == "medium":
        return "HMAC key seen but not verified — generate hooks + validate with re.session.sign"
    if confidence == "oracle_only" or aes:
        return "Encryption/obfuscation detected — use http.sign_via_browser oracle (hybrid)"
    if confidence == "low":
        return "Partial crypto signals — prefer browser oracle + scaffold_hooks"
    return "No crypto events — pure http.request may work; else ensure hooks installed before interact"


def synthesize_sign_request_python(analysis: dict[str, Any]) -> str | None:
    """Return a concrete sign_request() Python source if high/medium confidence HMAC."""
    rec = [r for r in (analysis.get("recoverable") or []) if r.get("kind") == "hmac" and r.get("key")]
    if not rec:
        return None
    # prefer verified
    rec.sort(key=lambda r: (not r.get("verified"), r.get("alg") != "sha256"))
    best = rec[0]
    key = best["key"]
    alg = best.get("alg") or "sha256"
    templates = analysis.get("message_templates") or []
    tmpl = templates[0] if templates else "{method}\\n{path}\\n{body}\\n{ts}"

    # Build as plain string to avoid nested f-string hell
    lines = [
        "def sign_request(method: str, url: str, body, secret: str | None = None) -> dict[str, str]:",
        f'    """Auto-synthesized from runtime crypto hooks (alg={alg})."""',
        "    import hashlib",
        "    import hmac",
        "    import json",
        "    import time",
        "    from urllib.parse import urlparse",
        f"    _default_key = {key!r}",
        "    raw_key = secret if secret is not None else _default_key",
        "    key_b = raw_key.encode() if isinstance(raw_key, str) else raw_key",
        "    path = urlparse(url).path",
        "    ts = str(int(time.time() * 1000))",
        "    if isinstance(body, dict):",
        '        payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False)',
        "    else:",
        "        payload = \"\" if body is None else str(body)",
        "    msg = f\"{method.upper()}\\n{path}\\n{payload}\\n{ts}\".encode()",
        f"    dig = {{'sha256': hashlib.sha256, 'sha1': hashlib.sha1, "
        f"'sha512': hashlib.sha512, 'md5': hashlib.md5}}.get({alg!r}, hashlib.sha256)",
        "    sig = hmac.new(key_b, msg, dig).hexdigest()",
        "    return {\"X-Timestamp\": ts, \"X-Signature\": sig, \"X-Sign\": sig}",
        f"    # observed template approx: {tmpl!r}",
    ]
    return "\n".join(lines) + "\n"


def synthesize_hooks_module(
    analysis: dict[str, Any],
    *,
    signer_path: str | None = None,
    use_oracle_fallback: bool = True,
) -> str:
    """Full hooks.py source: pure HMAC if possible, else browser-oracle instructions."""
    pure = synthesize_sign_request_python(analysis)
    conf = analysis.get("confidence") or "none"
    rec = analysis.get("recommendation") or ""

    if pure and conf in {"high", "medium"}:
        return f'''\
"""Auto-synthesized signing hooks (confidence={conf}).

{rec}
"""
from __future__ import annotations

from typing import Any

{pure}

async def before_http_request(ctx: Any, params: dict[str, Any]) -> dict[str, Any] | None:
    secret = (ctx.vars or {{}}).get("api_sign_secret")
    body = params.get("json") if params.get("json") is not None else params.get("body")
    extra = sign_request(
        str(params.get("method") or "POST"),
        str(params.get("url") or ""),
        body,
        secret=str(secret) if secret else None,
    )
    headers = dict(params.get("headers") or {{}})
    headers.update(extra)
    params["headers"] = headers
    return params


async def is_success(ctx: Any) -> bool | None:
    st = (ctx.meta or {{}}).get("last_http_status")
    if st is not None and int(st) in (200, 201):
        return True
    return None
'''

    # Oracle-oriented hooks (documentation + thin wrapper using meta from sign_via_browser)
    return f'''\
"""Signing hooks — browser oracle mode (confidence={conf}).

{rec}

Strong/obfuscated signatures: use flow steps:
  - http.sign_via_browser  (or http.request with sign_via_browser: true)
Preferred signer path: {signer_path!r}
"""
from __future__ import annotations

from typing import Any


async def before_http_request(ctx: Any, params: dict[str, Any]) -> dict[str, Any] | None:
    # If a prior http.sign_via_browser stored headers in extract/meta, merge them.
    signed = (ctx.extract or {{}}).get("signed_headers") or (ctx.meta or {{}}).get("signed_headers")
    if isinstance(signed, dict) and signed:
        headers = dict(params.get("headers") or {{}})
        headers.update({{str(k): str(v) for k, v in signed.items()}})
        params["headers"] = headers
        # one-shot consume
        if "signed_headers" in (ctx.extract or {{}}):
            ctx.extract.pop("signed_headers", None)
        return params
    return None


async def is_success(ctx: Any) -> bool | None:
    st = (ctx.meta or {{}}).get("last_http_status")
    if st is not None and int(st) in (200, 201):
        return True
    return None
'''
