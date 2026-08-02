"""Heuristic JS reverse-engineering: signing, crypto, tokens, endpoints."""

from __future__ import annotations

import re
from typing import Any

# Signature / crypto related patterns
CRYPTO_PATTERNS: list[tuple[str, str]] = [
    ("crypto_subtle", r"crypto\.subtle\.(digest|sign|encrypt|importKey|generateKey)"),
    ("webcrypto", r"window\.crypto|globalThis\.crypto"),
    ("hmac", r"\bHMAC\b|createHmac|hmac\s*\(|HmacSHA|hmacsha"),
    ("sha", r"\bSHA-?256\b|\bSHA-?1\b|\bSHA-?512\b|sha256\s*\(|CryptoJS\.SHA"),
    ("md5", r"\bmd5\s*\(|CryptoJS\.MD5|MD5\s*\("),
    ("aes", r"\bAES\b|CryptoJS\.AES|aes-(cbc|gcm|ecb)"),
    ("rsa", r"\bRSA\b|JSEncrypt|node-forge|forge\.pki"),
    ("btoa_sign", r"btoa\s*\(|atob\s*\("),
    ("text_encoder", r"TextEncoder|TextDecoder"),
    ("jwt_like", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("sign_fn", r"function\s+(\w*sign\w*)\s*\(|(\w*sign\w*)\s*[:=]\s*(async\s*)?function|(\w*sign\w*)\s*[:=]\s*\("),
    ("hash_fn", r"function\s+(\w*hash\w*)\s*\(|(\w*hash\w*)\s*[:=]\s*function"),
    ("encrypt_fn", r"function\s+(\w*encrypt\w*)\s*\(|(\w*encrypt\w*)\s*[:=]"),
    ("nonce", r"\bnonce\b|x-nonce|X-Nonce|requestId|request_id"),
    ("timestamp_sign", r"timestamp.*sign|sign.*timestamp|x-timestamp|X-Timestamp"),
    ("app_secret", r"app[_-]?secret|client[_-]?secret|api[_-]?secret|appKey|app_key"),
    ("csrf", r"csrf[_-]?token|xsrf|_csrf|X-CSRF|X-XSRF"),
    ("authorization", r"Authorization\s*[:=]|Bearer\s+[A-Za-z0-9._-]+"),
    ("graphql", r"\bquery\s+\w+|mutation\s+\w+|graphql"),
    ("protobuf", r"protobuf|proto3|\.serializeBinary"),
    ("wasm", r"WebAssembly\.|\.wasm\b"),
    ("obfuscated", r"_0x[a-f0-9]{4,}|\\x[0-9a-f]{2}"),
]

ENDPOINT_PATTERNS = [
    r"""['"`](https?://[^'"`\s]+/api/[^'"`\s]+)['"`]""",
    r"""['"`](/api/[^'"`\s]+)['"`]""",
    r"""['"`](/v\d+/[^'"`\s]+)['"`]""",
    r"""['"`](/graphql[^'"`\s]*)['"`]""",
    r"""['"`](/auth/[^'"`\s]+)['"`]""",
    r"""['"`](/register[^'"`\s]*)['"`]""",
    r"""['"`](/signup[^'"`\s]*)['"`]""",
]

FN_EXTRACT_RE = re.compile(
    r"(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{|"
    r"(\w+)\s*[:=]\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{|"
    r"(\w+)\s*[:=]\s*(?:async\s*)?function\s*\([^)]*\)\s*\{",
    re.M,
)


def analyze_js_text(
    text: str,
    *,
    source: str = "inline",
    max_hits_per_kind: int = 12,
    context: int = 100,
) -> dict[str, Any]:
    """Return structured RE hints from one JS blob."""
    findings: list[dict[str, Any]] = []
    kinds_count: dict[str, int] = {}

    for kind, pat in CRYPTO_PATTERNS:
        try:
            cre = re.compile(pat, re.I | re.M)
        except re.error:
            continue
        count = 0
        for m in cre.finditer(text):
            if count >= max_hits_per_kind:
                break
            start = max(0, m.start() - context)
            end = min(len(text), m.end() + context)
            findings.append(
                {
                    "kind": kind,
                    "match": m.group(0)[:200],
                    "context": text[start:end].replace("\n", " ")[:500],
                    "offset": m.start(),
                    "source": source,
                }
            )
            count += 1
        if count:
            kinds_count[kind] = count

    endpoints: list[str] = []
    seen_ep: set[str] = set()
    for pat in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, text, re.I):
            ep = m.group(1) if m.lastindex else m.group(0)
            ep = ep.strip("'\"`")
            if ep not in seen_ep:
                seen_ep.add(ep)
                endpoints.append(ep[:300])
            if len(endpoints) >= 40:
                break

    # Candidate function names near crypto keywords
    sign_fns: list[str] = []
    for m in re.finditer(
        r"(?:function\s+|const\s+|let\s+|var\s+)(\w*(?:sign|hash|hmac|encrypt|digest|token)\w*)\s*[=:(]",
        text,
        re.I,
    ):
        name = m.group(1)
        if name and name not in sign_fns:
            sign_fns.append(name)
        if len(sign_fns) >= 25:
            break

    # Snippet extraction for top sign-like functions
    function_snippets: list[dict[str, Any]] = []
    for name in sign_fns[:8]:
        snip = _extract_function_snippet(text, name, max_chars=800)
        if snip:
            function_snippets.append({"name": name, "snippet": snip, "source": source})

    risk = _risk_level(kinds_count)
    recommendations = _recommendations(kinds_count, endpoints, sign_fns)

    return {
        "source": source,
        "length": len(text),
        "crypto_kinds": kinds_count,
        "findings": findings[:80],
        "endpoints": endpoints,
        "sign_function_candidates": sign_fns,
        "function_snippets": function_snippets,
        "risk": risk,
        "recommendations": recommendations,
    }


def _extract_function_snippet(text: str, name: str, *, max_chars: int = 800) -> str | None:
    # Try function name() { ... } with brace matching (best-effort, not full parse)
    patterns = [
        rf"function\s+{re.escape(name)}\s*\([^)]*\)\s*\{{",
        rf"(?:const|let|var)\s+{re.escape(name)}\s*=\s*(?:async\s*)?function\s*\([^)]*\)\s*\{{",
        rf"(?:const|let|var)\s+{re.escape(name)}\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{{",
        rf"{re.escape(name)}\s*[:=]\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{{",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if not m:
            continue
        start = m.start()
        i = m.end() - 1  # at '{'
        depth = 0
        end = start
        for j in range(i, min(len(text), i + max_chars * 2)):
            ch = text[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        snippet = text[start:end] if end > start else text[start : start + max_chars]
        return snippet[:max_chars]
    # fallback: window around first name mention
    m = re.search(re.escape(name), text)
    if not m:
        return None
    a = max(0, m.start() - 40)
    b = min(len(text), m.end() + max_chars)
    return text[a:b]


def _risk_level(kinds: dict[str, int]) -> str:
    hard = {"crypto_subtle", "hmac", "aes", "rsa", "wasm", "protobuf", "obfuscated"}
    score = sum(kinds.get(k, 0) for k in hard)
    if kinds.get("obfuscated", 0) >= 3 or kinds.get("wasm", 0):
        return "high"
    if score >= 3 or kinds.get("hmac") or kinds.get("crypto_subtle"):
        return "medium"
    if kinds:
        return "low"
    return "none"


def _recommendations(
    kinds: dict[str, int],
    endpoints: list[str],
    sign_fns: list[str],
) -> list[str]:
    tips: list[str] = []
    if kinds.get("hmac") or kinds.get("crypto_subtle") or kinds.get("sha"):
        tips.append(
            "Detected client-side signing/hash. Capture a real request with site.capture or "
            "re.session, then either replay headers/body verbatim or reimplement sign logic "
            "in hooks.py (requires trust)."
        )
    if kinds.get("aes") or kinds.get("rsa"):
        tips.append(
            "Payload may be encrypted. Prefer browser hybrid flow, or extract key material "
            "from JS/network before pure http.request packs."
        )
    if kinds.get("wasm"):
        tips.append("WASM present — algorithm may be native; use browser path or reverse the wasm.")
    if kinds.get("obfuscated"):
        tips.append("Obfuscated JS — use runtime capture (network) over static deobfuscation first.")
    if kinds.get("graphql"):
        tips.append("GraphQL detected — capture full query/mutation body for http.request.")
    if kinds.get("csrf"):
        tips.append("CSRF tokens present — add a preliminary GET http.request to harvest token/cookie.")
    if sign_fns:
        tips.append(f"Inspect candidate functions: {', '.join(sign_fns[:6])}")
    if endpoints:
        tips.append(f"Static endpoints sample: {', '.join(endpoints[:5])}")
    if not tips:
        tips.append("No strong crypto signals; pure protocol http.request pack may be enough.")
    return tips


def merge_analyses(parts: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge multiple analyze_js_text results."""
    kinds: dict[str, int] = {}
    findings: list[dict[str, Any]] = []
    endpoints: list[str] = []
    seen_ep: set[str] = set()
    sign_fns: list[str] = []
    snippets: list[dict[str, Any]] = []
    recs: list[str] = []
    sources: list[str] = []

    for p in parts:
        sources.append(str(p.get("source") or ""))
        for k, v in (p.get("crypto_kinds") or {}).items():
            kinds[k] = kinds.get(k, 0) + int(v)
        findings.extend(p.get("findings") or [])
        for ep in p.get("endpoints") or []:
            if ep not in seen_ep:
                seen_ep.add(ep)
                endpoints.append(ep)
        for fn in p.get("sign_function_candidates") or []:
            if fn not in sign_fns:
                sign_fns.append(fn)
        snippets.extend(p.get("function_snippets") or [])
        recs.extend(p.get("recommendations") or [])

    # unique recommendations preserve order
    seen_r: set[str] = set()
    uniq_recs: list[str] = []
    for r in recs:
        if r not in seen_r:
            seen_r.add(r)
            uniq_recs.append(r)

    risk = _risk_level(kinds)
    return {
        "sources": [s for s in sources if s],
        "crypto_kinds": kinds,
        "findings": findings[:120],
        "endpoints": endpoints[:50],
        "sign_function_candidates": sign_fns[:30],
        "function_snippets": snippets[:12],
        "risk": risk,
        "recommendations": uniq_recs[:15],
        "bundle_count": len(parts),
    }
