"""One-shot reverse-engineering explore: capture + analyze + optional pack draft."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _browser_available() -> tuple[bool, list[str]]:
    """Return (any_browser_path, missing_dep_names)."""
    missing: list[str] = []
    has = False
    try:
        import camoufox  # noqa: F401

        has = True
    except Exception:  # noqa: BLE001
        missing.append("camoufox")
    try:
        from playwright.async_api import async_playwright  # noqa: F401

        has = True
    except Exception:  # noqa: BLE001
        missing.append("playwright")
    return has, missing


async def run_re_explore(args: dict[str, Any]) -> dict[str, Any]:
    """Aggregate site.capture + smart graph + optional pack.from_capture.

    Without browser/CDP, degrade cleanly (status=degraded/offline) instead of crashing.
    """
    from easy_rev.core.result import install_hints
    from easy_rev.platforms.web.re.capture_flow import run_site_capture
    from easy_rev.platforms.web.re.draft_protocol import write_protocol_pack

    url = args.get("url")
    if not url:
        raise ValueError("url required")

    cdp_url = args.get("cdp_url") or args.get("cdp")
    force_offline = bool(args.get("offline_only") or args.get("offline"))
    browser_ok, missing = _browser_available()
    need_degrade = force_offline or (not browser_ok and not cdp_url)

    if need_degrade:
        capture_path = args.get("capture_path")
        if capture_path:
            # Avoid circular import with ai.handlers — call offline helpers directly
            import json as _json

            from easy_rev.platforms.web.re.dependency_graph import smart_suggest_http_steps
            from easy_rev.platforms.web.re.draft_protocol import write_protocol_pack as _wpp

            cap_data = _json.loads(Path(capture_path).read_text(encoding="utf-8"))
            apis = [a for a in (cap_data.get("apis") or []) if isinstance(a, dict)]
            graph = smart_suggest_http_steps(apis, min_score=int(args.get("min_api_score") or 1))
            offline: dict[str, Any] = {
                "ok": True,
                "url": url,
                "api_count": len(apis),
                "top_apis": apis[:12],
                "graph": graph if isinstance(graph, dict) else {"steps": graph},
                "status": "offline",
                "degraded": True,
                "attached": False,
                "dry_run": False,
                "confidence": "medium" if apis else "low",
                "recommendation": "offline_protocol",
                "hint": "; ".join(install_hints(missing)) if missing else None,
                "missing_deps": missing,
            }
            offline["next_steps"] = _next_steps(offline)
            if args.get("write_pack") or args.get("pack_id"):
                pack_id = args.get("pack_id") or "offline-explore"
                dest = Path(args.get("pack_dest") or args.get("dest") or f"./packs/{pack_id}")
                pack_out = _wpp(
                    pack_path=dest,
                    pack_id=pack_id,
                    capture_path=Path(capture_path),
                    hybrid=bool(args.get("hybrid", False)),
                )
                offline["pack"] = pack_out if isinstance(pack_out, dict) else {"result": pack_out}
                offline["pack_path"] = str(dest)
            return offline

        host = urlparse(url).netloc or url
        degraded_out = {
            "ok": True,
            "status": "degraded",
            "degraded": True,
            "dry_run": True,
            "attached": False,
            "confidence": "low",
            "url": url,
            "recommendation": "install_browser_or_pass_capture",
            "risk": "unknown",
            "api_count": 0,
            "top_apis": [],
            "missing_deps": missing,
            "hint": (
                "No Camoufox/Playwright and no cdp_url. "
                + ("; ".join(install_hints(missing)) + ". " if missing else "")
                + "Pass capture_path= for offline_chain, or cdp_url= / re bridge for Chrome."
            ),
            "notes": [
                f"Target host: {host}",
                "Use easy-rev re bridge + Chrome extension for logged-in RE without Camoufox.",
                "Use pack.from_capture / web.offline_chain when you already have capture JSON.",
            ],
        }
        degraded_out["next_steps"] = _next_steps(degraded_out)
        return degraded_out

    capture_args = {
        "url": url,
        "engine": args.get("engine") or "auto",
        "headless": bool(args.get("headless", True)),
        "wait_ms": int(args.get("wait_ms") or 2000),
        "accept_consent": bool(args.get("accept_consent", True)),
        "multi_step": bool(args.get("multi_step", True)),
        "max_steps": int(args.get("max_steps") or 5),
        "actions": args.get("actions") or [],
        "auto_fill": bool(args.get("auto_fill", True)),
        "submit": bool(args.get("submit", True)),
        "capture_bodies": True,
        "include_scripts": True,
        "download_scripts": bool(args.get("download_scripts", True)),
        "runtime_hooks": bool(args.get("runtime_hooks", True)),
        "analyze_js": bool(args.get("analyze_js", True)),
        "screenshot": bool(args.get("screenshot", False)),
        "min_api_score": int(args.get("min_api_score") or 4),
        "suggest_browser_bridge": bool(args.get("hybrid", False)),
        "cdp_url": cdp_url,
        "tab_url": args.get("tab_url") or args.get("cdp_target_url"),
        "tab_index": args.get("tab_index"),
        "navigate": args.get("navigate"),
    }
    # CDP instant RE: don't force navigate away from logged-in page
    if capture_args.get("cdp_url") and args.get("navigate") is None:
        capture_args["navigate"] = False
        # keep url for matching / pack signup_url; capture uses current tab
    try:
        capture = await run_site_capture(capture_args)
    except Exception as e:  # noqa: BLE001
        fail_out = {
            "ok": True,
            "status": "degraded",
            "degraded": True,
            "attached": False,
            "dry_run": False,
            "confidence": "low",
            "url": url,
            "error": str(e),
            "recommendation": "browser_flow_or_extension",
            "risk": "unknown",
            "api_count": 0,
            "top_apis": [],
            "missing_deps": missing,
            "hint": "; ".join(install_hints(missing)) if missing else "check browser engine / CDP",
            "notes": ["site.capture failed; try re bridge or offline capture_path"],
        }
        fail_out["next_steps"] = _next_steps(fail_out)
        return fail_out

    # Compact view for AI context
    apis = capture.get("apis") or []
    signing = capture.get("signing") or {}
    js_analysis = capture.get("js_analysis") or {}
    graph = capture.get("dependency_graph") or {}

    auto_sign = capture.get("auto_sign") or {}
    risk = js_analysis.get("risk") or "unknown"
    if signing.get("sig_headers") or signing.get("sig_body_keys"):
        risk = "medium" if risk in {"none", "low", "unknown"} else risk
    ca = (auto_sign.get("crypto_analysis") or {}).get("confidence")
    if ca in {"high", "medium"}:
        risk = "medium" if risk == "none" else risk
    if ca == "oracle_only" or auto_sign.get("mode") == "browser_oracle":
        risk = "high"

    recommendation = "protocol"
    if risk in {"medium", "high"} or auto_sign.get("best_signer"):
        recommendation = "hybrid"
    if auto_sign.get("mode") == "pure_python" and ca == "high":
        recommendation = "protocol"  # synthesized HMAC can run without browser
    if not apis:
        recommendation = "browser_flow"

    out: dict[str, Any] = {
        "ok": True,
        "status": "attached",
        "degraded": False,
        "url": capture.get("url") or url,
        "capture_path": capture.get("capture_path"),
        "har_path": capture.get("har_path"),
        "recommendation": recommendation,
        "risk": risk,
        "api_count": len(apis),
        "top_apis": [
            {
                "method": a.get("method"),
                "url": a.get("url"),
                "score": a.get("score"),
                "summary": a.get("summary") or a.get("api_summary"),
                "tags": a.get("why") or a.get("tags"),
            }
            for a in apis[:12]
        ],
        "dependency_graph": graph,
        "suggested_http_steps": capture.get("suggested_http_steps") or [],
        "signing": {
            "sig_headers": signing.get("sig_headers"),
            "sig_body_keys": signing.get("sig_body_keys"),
            "stack_files": signing.get("stack_files"),
            "recommendations": signing.get("recommendations"),
            "interesting_calls": (signing.get("interesting_calls") or [])[:15],
        },
        "auto_sign": {
            "mode": auto_sign.get("mode"),
            "best_signer": auto_sign.get("best_signer"),
            "crypto_confidence": (auto_sign.get("crypto_analysis") or {}).get("confidence"),
            "signers_working": auto_sign.get("signers_working"),
            "crypto_event_count": auto_sign.get("crypto_event_count"),
        },
        "js_analysis": {
            "risk": js_analysis.get("risk"),
            "crypto_kinds": js_analysis.get("crypto_kinds"),
            "sign_function_candidates": js_analysis.get("sign_function_candidates"),
            "endpoints": (js_analysis.get("endpoints") or [])[:20],
            "recommendations": js_analysis.get("recommendations"),
        },
        "websockets": capture.get("websockets"),
        "notes": capture.get("notes"),
        "verbosity": args.get("verbosity") or "summary",
    }

    if args.get("verbosity") == "full":
        out["full_capture"] = capture

    # Optional pack generation
    if args.get("write_pack") or args.get("pack_id") or args.get("pack_path"):
        pack_id = args.get("pack_id")
        if not pack_id:
            host = urlparse(str(url)).netloc or "site"
            pack_id = host.replace(".", "-").lower()
            pack_id = "".join(c if c.isalnum() or c in "-_." else "-" for c in pack_id)
        dest = Path(args["pack_path"]) if args.get("pack_path") else Path("packs") / pack_id
        hybrid = bool(args.get("hybrid", recommendation == "hybrid"))
        # Oracle modes must be hybrid camoufox
        if auto_sign.get("mode") in {
            "browser_oracle",
            "pure_python_with_oracle_fallback",
        } or auto_sign.get("best_signer"):
            hybrid = True
        pack_out = write_protocol_pack(
            pack_path=dest,
            pack_id=pack_id,
            name=args.get("name") or pack_id,
            signup_url=str(url),
            capture_path=capture.get("capture_path"),
            apis=apis,
            max_apis=int(args.get("max_apis") or 10),
            min_score=int(args.get("min_api_score") or 4),
            hybrid=hybrid,
            impersonate=args.get("impersonate") or "chrome120",
            auto_sign=auto_sign,
            signer_path=auto_sign.get("best_signer"),
            sign_via_browser=(
                True
                if auto_sign.get("best_signer")
                or auto_sign.get("mode")
                in {"browser_oracle", "pure_python_with_oracle_fallback"}
                else None
            ),
        )
        out["pack"] = pack_out

    # Optional commercial follow-ups: prefer auto_sign synthesized hooks
    if (args.get("scaffold_hooks") or args.get("auto_sign_hooks")) and out.get("pack"):
        try:
            if capture.get("auto_sign") and capture["auto_sign"].get("mode"):
                from easy_rev.platforms.web.re.auto_sign import (
                    run_auto_sign_analysis,  # noqa: F401
                    write_auto_hooks,
                )

                # rebuild full analysis if hooks_source missing from compact capture
                analysis = capture.get("auto_sign") or {}
                if not analysis.get("hooks_source"):
                    from easy_rev.platforms.web.re.sign_synth import synthesize_hooks_module

                    analysis = {
                        **analysis,
                        "hooks_source": synthesize_hooks_module(
                            analysis.get("crypto_analysis") or {},
                            signer_path=analysis.get("best_signer"),
                        ),
                    }
                out["hooks"] = write_auto_hooks(
                    out["pack"]["pack_path"],
                    analysis,
                    force=bool(args.get("force_hooks")),
                )
            else:
                from easy_rev.platforms.web.re.hooks_scaffold import scaffold_hooks_for_pack

                out["hooks"] = scaffold_hooks_for_pack(
                    out["pack"]["pack_path"],
                    capture_path=capture.get("capture_path"),
                    force=bool(args.get("force_hooks")),
                )
        except Exception as e:  # noqa: BLE001
            out["hooks_error"] = str(e)

    out["next_steps"] = _next_steps(out)
    # Agent-facing confidence (adapter also derives; keep for direct callers)
    if "confidence" not in out:
        st = out.get("status")
        if st == "attached" and (out.get("api_count") or 0) > 0:
            out["confidence"] = "high"
        elif st == "attached":
            out["confidence"] = "medium"
        elif st in {"offline", "degraded", "dry_run"}:
            out["confidence"] = "low"
        elif st == "error":
            out["confidence"] = "none"
        else:
            out["confidence"] = "medium"
    if "attached" not in out:
        out["attached"] = out.get("status") == "attached"
    if "dry_run" not in out:
        out["dry_run"] = out.get("status") == "dry_run" or bool(out.get("dry_run"))

    out["commercial"] = {
        "har_path": capture.get("har_path"),
        "probe_hint": "re.probe_fields with capture_path to minimize JSON body",
        "diff_hint": "re.diff a=prev.json b=new.json after flow changes",
        "tls": "pip install 'easy-rev[tls]' then impersonate=chrome120",
    }
    return out


def _next_steps(out: dict[str, Any]) -> list[str]:
    """Suggest agent follow-ups from explore outcome."""
    tips: list[str] = []
    rec = out.get("recommendation")
    status = out.get("status")
    if status in {"degraded", "dry_run"}:
        for dep in out.get("missing_deps") or []:
            tips.append(f"Install missing dependency: {dep}")
        tips.append(
            "Pass cdp_url= for Chrome attach, or capture_path= for offline protocol chain"
        )
        tips.append("Or: easy-rev re bridge + Chrome extension for logged-in RE")
    if status == "offline":
        tips.append("Review graph/steps then pack.from_capture or write_pack for protocol pack")
        tips.append("Validate with pack.validate + pack.run --dry-run")
    if out.get("capture_path"):
        tips.append("re.probe_fields {capture_path} → shrink json to required keys")
    auto_sign = out.get("auto_sign") or {}
    if rec == "hybrid" or auto_sign.get("mode") in {
        "browser_oracle",
        "pure_python_with_oracle_fallback",
    }:
        tips.append("re.scaffold_hooks {pack_path, capture_path} then implement sign_request")
    if rec == "protocol" and out.get("capture_path"):
        tips.append("Try pure protocol replay via pack flow / http client with captured APIs")
    if rec == "browser_flow":
        tips.append("Few APIs found — use multi_step actions / CDP on logged-in tab")
    if not out.get("pack") and not out.get("pack_path") and out.get("capture_path"):
        tips.append("Call re.explore with write_pack=true or pack.from_capture on capture_path")
    seen: set[str] = set()
    uniq: list[str] = []
    for tip in tips:
        if tip not in seen:
            seen.add(tip)
            uniq.append(tip)
    return uniq
