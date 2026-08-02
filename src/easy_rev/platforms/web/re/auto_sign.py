"""End-to-end auto-sign pipeline: crypto hooks + oracle + synthesis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from easy_rev.platforms.web.re.crypto_hooks import dump_crypto_events, install_crypto_hooks
from easy_rev.platforms.web.re.runtime_hooks import (
    analyze_signing_traces,
    dump_runtime_hooks,
    install_runtime_hooks,
)
from easy_rev.platforms.web.re.sign_oracle import (
    auto_probe_signers,
    install_sign_oracle,
    oracle_sign,
)
from easy_rev.platforms.web.re.sign_synth import analyze_crypto_events, synthesize_hooks_module


async def prepare_page_for_auto_sign(page: Any) -> dict[str, Any]:
    """Install network + crypto hooks + oracle bridge."""
    net = await install_runtime_hooks(page)
    crypto = await install_crypto_hooks(page)
    oracle = await install_sign_oracle(page)
    return {"network_hooks": net, "crypto_hooks": crypto, "oracle": oracle}


async def run_auto_sign_analysis(page: Any, *, sample_url: str = "") -> dict[str, Any]:
    """Dump hooks + crypto + discover working signers."""
    hooks = await dump_runtime_hooks(page, max_traces=100)
    crypto = await dump_crypto_events(page, max_events=150)
    crypto_analysis = analyze_crypto_events(list(crypto.get("events") or []))
    signing = analyze_signing_traces(list(hooks.get("traces") or []))
    probe = await auto_probe_signers(
        page,
        url=sample_url or "https://local/api/register",
        method="POST",
    )
    best_path = None
    if probe.get("best"):
        best_path = probe["best"].get("path")
    hooks_src = synthesize_hooks_module(
        crypto_analysis,
        signer_path=best_path,
        use_oracle_fallback=True,
    )
    mode = "pure_python"
    if crypto_analysis.get("confidence") not in {"high", "medium"}:
        mode = "browser_oracle" if probe.get("working") else "manual"
    if probe.get("working") and crypto_analysis.get("confidence") == "high":
        mode = "pure_python_with_oracle_fallback"

    return {
        "mode": mode,
        "crypto_analysis": crypto_analysis,
        "signing_traces": {
            "sig_headers": signing.get("sig_headers"),
            "sig_body_keys": signing.get("sig_body_keys"),
            "recommendations": signing.get("recommendations"),
            "interesting_calls": (signing.get("interesting_calls") or [])[:10],
        },
        "signers": probe,
        "best_signer": best_path,
        "hooks_source": hooks_src,
        "crypto_event_count": crypto.get("total") or len(crypto.get("events") or []),
        "network_trace_count": hooks.get("total") or len(hooks.get("traces") or []),
    }


async def auto_sign_payload(
    page: Any,
    *,
    method: str,
    url: str,
    body: Any,
    signer_path: str | None = None,
) -> dict[str, Any]:
    """Produce headers/body for one request using the best available strategy."""
    # Prefer working oracle
    res = await oracle_sign(
        page, method=method, url=url, body=body, signer_path=signer_path
    )
    if res.get("ok"):
        return {
            "ok": True,
            "strategy": "browser_oracle",
            "signer_path": res.get("signer_path"),
            "headers": res.get("headers") or {},
            "body": res.get("body"),
            "signature": res.get("signature"),
        }
    # Try pure synthesis from crypto dump
    crypto = await dump_crypto_events(page)
    analysis = analyze_crypto_events(list(crypto.get("events") or []))
    from easy_rev.platforms.web.re.sign_synth import synthesize_sign_request_python

    src = synthesize_sign_request_python(analysis)
    if src and analysis.get("confidence") in {"high", "medium"}:
        # exec synthesized function in isolation
        ns: dict[str, Any] = {}
        exec(src, ns, ns)  # noqa: S102 — local synthesis only
        fn = ns.get("sign_request")
        if callable(fn):
            headers = fn(method, url, body)
            return {
                "ok": True,
                "strategy": "synthesized_hmac",
                "headers": headers,
                "confidence": analysis.get("confidence"),
            }
    return {
        "ok": False,
        "error": res.get("error") or "auto_sign failed",
        "crypto_confidence": analysis.get("confidence"),
        "hint": "Interact with the page (submit form) so crypto hooks capture keys, or name signer_path",
    }


async def oracle_batch_http(
    page: Any,
    items: list[dict[str, Any]],
    *,
    signer_path: str | None = None,
    proxy: str | None = None,
    impersonate: str | None = None,
    timeout_s: float = 30.0,
    import_cookies: bool = True,
) -> dict[str, Any]:
    """Sign each item via browser then fire httpx/curl_cffi request (same page).

    Item: {method, url, json|body, headers?, id?}
    """
    from easy_rev.platforms.web.re.browser_bridge import import_browser_into_http
    from easy_rev.platforms.web.re.http_client import HttpClient
    from easy_rev.platforms.web.re.sign_oracle import oracle_sign_batch

    signed = await oracle_sign_batch(
        page, items, signer_path=signer_path, stop_on_error=False
    )
    client = HttpClient(proxy=proxy, timeout_s=timeout_s, impersonate=impersonate)
    out_rows: list[dict[str, Any]] = []
    try:
        if import_cookies and page:
            await import_browser_into_http(page, client)
        for item, sig in zip(items or [], signed.get("results") or [], strict=False):
            if not sig.get("ok"):
                out_rows.append(
                    {
                        "id": item.get("id") if isinstance(item, dict) else None,
                        "ok": False,
                        "phase": "sign",
                        "error": sig.get("error"),
                    }
                )
                continue
            method = str(item.get("method") or "POST")
            url = str(item.get("url") or "")
            headers = {**(item.get("headers") or {}), **(sig.get("headers") or {})}
            body = item.get("json") if item.get("json") is not None else item.get("body")
            if sig.get("body") is not None and item.get("use_signed_body"):
                body = sig["body"]
            resp = await client.request(
                method,
                url,
                headers={str(k): str(v) for k, v in headers.items()},
                json_body=body if isinstance(body, (dict, list)) else None,
                body=None if isinstance(body, (dict, list)) else body,
            )
            out_rows.append(
                {
                    "id": item.get("id"),
                    "ok": resp.ok,
                    "phase": "http",
                    "status": resp.status,
                    "url": resp.url,
                    "signature": sig.get("signature"),
                    "signer_path": sig.get("signer_path"),
                    "body_preview": (resp.text or "")[:400],
                    "error": resp.error,
                }
            )
    finally:
        await client.close()

    success = sum(1 for r in out_rows if r.get("ok"))
    return {
        "ok": success == len(out_rows) and len(out_rows) > 0,
        "total": len(out_rows),
        "success": success,
        "failed": len(out_rows) - success,
        "signer_path": signed.get("signer_path") or signer_path,
        "sign_batch": signed,
        "results": out_rows,
    }


def write_auto_hooks(
    pack_path: str | Path,
    analysis: dict[str, Any],
    *,
    force: bool = False,
) -> dict[str, Any]:
    pack_path = Path(pack_path)
    hooks_file = pack_path / "hooks.py"
    if hooks_file.exists() and not force:
        return {"ok": False, "error": "hooks.py exists", "path": str(hooks_file)}
    source = analysis.get("hooks_source")
    if not source:
        source = synthesize_hooks_module(
            analysis.get("crypto_analysis") or {},
            signer_path=analysis.get("best_signer"),
        )
    pack_path.mkdir(parents=True, exist_ok=True)
    hooks_file.write_text(source, encoding="utf-8")

    pack_yaml = pack_path / "pack.yaml"
    if pack_yaml.exists():
        import yaml

        man = yaml.safe_load(pack_yaml.read_text(encoding="utf-8")) or {}
        entry = man.get("entry") or {}
        entry["hooks"] = "hooks.py"
        if entry.get("kind") == "declarative":
            entry["kind"] = "hybrid"
        man["entry"] = entry
        mode = analysis.get("mode") or "unknown"
        warns = list(man.get("warnings") or [])
        w = f"auto_sign hooks mode={mode} — verify before production bulk"
        if w not in warns:
            warns.append(w)
        man["warnings"] = warns
        if mode.startswith("browser") or mode.endswith("oracle"):
            man.setdefault("requires", {})["engine"] = "camoufox"
        pack_yaml.write_text(yaml.safe_dump(man, allow_unicode=True, sort_keys=False), encoding="utf-8")

    return {
        "ok": True,
        "path": str(hooks_file.resolve()),
        "mode": analysis.get("mode"),
        "trust_required": True,
    }
