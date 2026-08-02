"""Full RE analysis of Chrome-extension captures (parity with Camoufox site.capture)."""

from __future__ import annotations

from typing import Any

from easy_rev.platforms.web.re.dependency_graph import smart_suggest_http_steps
from easy_rev.platforms.web.re.runtime_hooks import analyze_signing_traces
from easy_rev.platforms.web.re.sign_synth import analyze_crypto_events, synthesize_hooks_module


def enrich_extension_capture(doc: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """Merge page hook dumps + run auto_sign offline analysis into capture doc."""
    dump = payload.get("page_hooks") or payload.get("hooks_dump") or {}
    traces = list(dump.get("traces") or payload.get("hook_traces") or [])
    crypto_events = list(dump.get("crypto") or payload.get("crypto_events") or [])
    signers = list(dump.get("signers") or payload.get("signers") or [])
    oracle_try = payload.get("oracle_try") or {}

    signing = analyze_signing_traces(traces) if traces else (doc.get("signing") or {})
    crypto_analysis = (
        analyze_crypto_events(crypto_events) if crypto_events else {"confidence": "none"}
    )

    best = None
    working: list[str] = []
    if oracle_try.get("ok") and oracle_try.get("path"):
        best = oracle_try.get("path")
        working.append(str(best))
    for s in signers:
        path = s.get("path") if isinstance(s, dict) else s
        if path and path not in working:
            # mark discovered; working only if oracle succeeded on that path
            pass
    if not best and working:
        best = working[0]
    if not best and signers:
        first = signers[0]
        best = first.get("path") if isinstance(first, dict) else first

    mode = "manual"
    conf = crypto_analysis.get("confidence") or "none"
    if conf in {"high", "medium"}:
        mode = "pure_python"
    if best or conf == "oracle_only":
        mode = "browser_oracle" if conf not in {"high", "medium"} else "pure_python_with_oracle_fallback"
    if conf == "high" and best:
        mode = "pure_python_with_oracle_fallback"
    if conf == "high" and not best:
        mode = "pure_python"

    hooks_src = synthesize_hooks_module(crypto_analysis, signer_path=best)
    need_sign = bool(
        best
        or mode in {"browser_oracle", "pure_python_with_oracle_fallback"}
        or conf == "oracle_only"
        or signing.get("sig_headers")
    )

    apis = doc.get("apis") or []
    smart = smart_suggest_http_steps(
        apis,
        max_steps=10,
        use_browser_cookies=True,
        min_score=3,
        sign_via_browser=need_sign,
        signer_path=str(best) if best else None,
    )

    doc["signing"] = signing
    doc["runtime_hooks"] = {
        "installed": dump.get("installed") or bool(traces),
        "total": dump.get("total_traces") or len(traces),
        "traces": traces[-40:],
        "ws": dump.get("ws") or [],
    }
    doc["crypto_events_sample"] = crypto_events[-30:]
    doc["auto_sign"] = {
        "mode": mode,
        "best_signer": best,
        "crypto_analysis": {
            "confidence": conf,
            "hmac_events": crypto_analysis.get("hmac_events"),
            "digest_events": crypto_analysis.get("digest_events"),
            "recoverable": (crypto_analysis.get("recoverable") or [])[:8],
            "message_templates": crypto_analysis.get("message_templates"),
            "recommendation": crypto_analysis.get("recommendation"),
        },
        "crypto_confidence": conf,
        "signers_working": working or ([best] if best else []),
        "signers_discovered": [
            (s.get("path") if isinstance(s, dict) else s) for s in signers[:30]
        ],
        "oracle_try": {
            "ok": oracle_try.get("ok"),
            "path": oracle_try.get("path"),
            "error": oracle_try.get("error"),
        },
        "crypto_event_count": dump.get("total_crypto") or len(crypto_events),
        "hooks_source_len": len(hooks_src) if hooks_src else 0,
    }
    # keep hooks source only if small / requested
    if payload.get("include_hooks_source"):
        doc["auto_sign"]["hooks_source"] = hooks_src

    doc["dependency_graph"] = smart.get("graph")
    doc["suggested_http_steps"] = smart.get("steps") or doc.get("suggested_http_steps")
    doc["websockets"] = {
        "urls": list({w.get("url") for w in (dump.get("ws") or []) if isinstance(w, dict)}),
        "frame_count": sum(len(w.get("frames") or []) for w in (dump.get("ws") or []) if isinstance(w, dict)),
        "frames": [
            f
            for w in (dump.get("ws") or [])
            if isinstance(w, dict)
            for f in (w.get("frames") or [])[:5]
        ][:40],
    }
    notes = list(doc.get("notes") or [])
    notes.append(f"extension_full mode={mode} best_signer={best} crypto={conf}")
    if need_sign:
        notes.append("POST steps use sign_via_browser (hybrid pack recommended)")
    doc["notes"] = notes
    doc["capability"] = {
        "network_cdp": True,
        "fetch_xhr_hooks": bool(traces) or dump.get("installed"),
        "crypto_hooks": bool(crypto_events) or dump.get("cryptoInstalled"),
        "auto_sign": True,
        "dependency_graph": True,
        "sign_oracle_probe": bool(oracle_try),
        "parity_with_camoufox": "near" if (traces or crypto_events) else "network_only",
    }
    return doc
