"""Web platform adapter: Camoufox / CDP / Chrome extension bridge."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from easy_rev.core.platform import Platform, PlatformFamily, TargetSpec
from easy_rev.core.types import ArtifactKind, CaptureArtifact, ProbeResult
from easy_rev.platforms.base import PlatformAdapter


class WebAdapter(PlatformAdapter):
    family = PlatformFamily.WEB
    platforms = (Platform.WEB,)

    async def doctor(self) -> dict[str, Any]:
        from easy_rev.core.deps import preflight

        out: dict[str, Any] = {
            "platform": "web",
            "camoufox_installed": False,
            "curl_cffi_installed": False,
            "playwright_available": False,
            "httpx_available": False,
        }
        try:
            import camoufox  # noqa: F401

            out["camoufox_installed"] = True
            out["camoufox_version"] = getattr(camoufox, "__version__", "unknown")
        except Exception as e:  # noqa: BLE001
            out["camoufox_error"] = str(e)
        try:
            import curl_cffi  # noqa: F401

            out["curl_cffi_installed"] = True
        except Exception:  # noqa: BLE001
            pass
        try:
            from playwright.async_api import async_playwright  # noqa: F401

            out["playwright_available"] = True
        except Exception:  # noqa: BLE001
            pass
        try:
            import httpx  # noqa: F401

            out["httpx_available"] = True
        except Exception:  # noqa: BLE001
            pass
        pf = preflight("web")
        web_pf = (pf.get("platforms") or {}).get("web") or {}
        out["ready"] = web_pf.get("ready")
        out["score"] = web_pf.get("score")
        out["missing"] = web_pf.get("missing")
        out["capabilities"] = {
            "browser": bool(out["camoufox_installed"] or out["playwright_available"]),
            "tls_fingerprint": bool(out["curl_cffi_installed"]),
            "offline_protocol": bool(out["httpx_available"]),
            "extension_bridge": True,  # pure Python
        }
        out["install_hints"] = pf.get("install_hints") or []
        return out

    async def explore(self, target: TargetSpec, **kwargs: Any) -> ProbeResult:
        from easy_rev.platforms.web.re.explore import run_re_explore

        url = target.url or kwargs.get("url")
        if not url:
            return ProbeResult(
                ok=False,
                platform="web",
                target=target.label(),
                status="error",
                confidence="none",
                error="url required for web explore",
                blocking_issues=["missing:url"],
            ).ensure_status_fields()
        args = {**kwargs, "url": url}
        started = datetime.now(UTC)
        try:
            raw = await run_re_explore(args)
        except Exception as e:  # noqa: BLE001
            return ProbeResult(
                ok=False,
                platform="web",
                target=url,
                status="error",
                confidence="none",
                error=str(e),
                blocking_issues=[f"explore_exception:{e}"],
                started_at=started,
                finished_at=datetime.now(UTC),
            ).ensure_status_fields()
        arts: list[CaptureArtifact] = []
        if raw.get("capture_path"):
            arts.append(
                CaptureArtifact(
                    kind=ArtifactKind.CAPTURE,
                    path=str(raw["capture_path"]),
                    summary="network + hooks capture",
                )
            )
        if raw.get("har_path"):
            arts.append(
                CaptureArtifact(kind=ArtifactKind.HAR, path=str(raw["har_path"]))
            )
        pack_path = raw.get("pack_path")
        if not pack_path and isinstance(raw.get("pack"), dict):
            pack_path = raw["pack"].get("path") or raw["pack"].get("pack_path")
        if pack_path:
            arts.append(
                CaptureArtifact(kind=ArtifactKind.PACK, path=str(pack_path))
            )

        status = str(raw.get("status") or ("attached" if raw.get("ok", True) else "error"))
        blocking: list[str] = []
        for dep in raw.get("missing_deps") or []:
            blocking.append(f"missing:{dep}")
        if raw.get("error") and status in {"degraded", "error"}:
            blocking.append(f"capture:{raw.get('error')}")
        next_steps = list(raw.get("next_steps") or [])
        confidence = raw.get("confidence")
        if confidence is None:
            if status == "attached" and (raw.get("api_count") or 0) > 0:
                confidence = "high"
            elif status == "attached":
                confidence = "medium"
            elif status in {"offline", "degraded", "dry_run"}:
                confidence = "low"
            elif status == "error":
                confidence = "none"
            else:
                confidence = "medium"

        return ProbeResult(
            ok=bool(raw.get("ok", True)) and status != "error",
            platform="web",
            target=str(raw.get("url") or url),
            status=status,
            attached=bool(raw.get("attached", status == "attached")),
            dry_run=bool(raw.get("dry_run", status == "dry_run")),
            degraded=bool(raw.get("degraded", status in {"dry_run", "offline", "degraded"})),
            confidence=str(confidence),
            hint=raw.get("hint"),
            next_steps=next_steps,
            blocking_issues=blocking,
            recommendation=raw.get("recommendation"),
            risk=raw.get("risk"),
            artifacts=arts,
            findings={
                "api_count": raw.get("api_count"),
                "top_apis": raw.get("top_apis"),
                "auto_sign": raw.get("auto_sign"),
                "signing": raw.get("signing"),
                "dependency_graph": raw.get("dependency_graph"),
                "js_analysis": raw.get("js_analysis"),
                "suggested_http_steps": raw.get("suggested_http_steps"),
                "notes": raw.get("notes"),
                "pack": raw.get("pack"),
            },
            message=raw.get("message"),
            error=raw.get("error"),
            capture_path=str(raw["capture_path"]) if raw.get("capture_path") else None,
            har_path=str(raw["har_path"]) if raw.get("har_path") else None,
            pack_path=str(pack_path) if pack_path else None,
            started_at=started,
            finished_at=datetime.now(UTC),
        ).ensure_status_fields()

    async def capture(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        from easy_rev.platforms.web.re.capture_flow import run_site_capture

        url = target.url or kwargs.get("url")
        if not url:
            return {
                "ok": False,
                "status": "error",
                "attached": False,
                "confidence": "none",
                "error": "url required",
            }
        args = {**kwargs, "url": url}
        try:
            result = await run_site_capture(args)
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False,
                "status": "error",
                "attached": False,
                "confidence": "none",
                "error": str(e),
                "url": url,
            }
        if not isinstance(result, dict):
            return {"ok": True, "status": "attached", "result": result, "url": url}
        # Preserve explicit failure; default success path is attached browser capture
        if "ok" not in result:
            result["ok"] = not bool(result.get("error"))
        result.setdefault("status", "attached" if result.get("ok") else "error")
        result.setdefault("attached", result.get("status") == "attached")
        result.setdefault(
            "confidence",
            "high" if result.get("ok") and (result.get("apis") or result.get("capture_path")) else (
                "none" if not result.get("ok") else "medium"
            ),
        )
        return result

    async def analyze(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        from easy_rev.platforms.web.re.js_analyze import analyze_js_text

        text = kwargs.get("text") or ""
        url = target.url or kwargs.get("url")
        if not text and url:
            # lightweight: analyze from explore snippet path

            return {"ok": True, "message": "use re.explore or pass text=", "url": url}
        if text:
            return {"ok": True, **analyze_js_text(text)}
        return {"ok": False, "error": "text or url required"}

    async def session_start(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        from easy_rev.platforms.web.re.session_client import session_start

        url = target.url or kwargs.get("url")
        args = {**kwargs}
        if url:
            args.setdefault("url", url)
        return await session_start(args)
