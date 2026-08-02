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
        out: dict[str, Any] = {
            "platform": "web",
            "camoufox_installed": False,
            "curl_cffi_installed": False,
            "playwright_available": False,
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
        return out

    async def explore(self, target: TargetSpec, **kwargs: Any) -> ProbeResult:
        from easy_rev.platforms.web.re.explore import run_re_explore

        url = target.url or kwargs.get("url")
        if not url:
            return ProbeResult(
                ok=False,
                platform="web",
                target=target.label(),
                error="url required for web explore",
            )
        args = {**kwargs, "url": url}
        started = datetime.now(UTC)
        try:
            raw = await run_re_explore(args)
        except Exception as e:  # noqa: BLE001
            return ProbeResult(
                ok=False,
                platform="web",
                target=url,
                error=str(e),
                started_at=started,
                finished_at=datetime.now(UTC),
            )
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
        if raw.get("pack_path"):
            arts.append(
                CaptureArtifact(kind=ArtifactKind.PACK, path=str(raw["pack_path"]))
            )
        return ProbeResult(
            ok=True,
            platform="web",
            target=url,
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
            },
            started_at=started,
            finished_at=datetime.now(UTC),
        )

    async def capture(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        from easy_rev.platforms.web.re.capture_flow import run_site_capture

        url = target.url or kwargs.get("url")
        if not url:
            return {"ok": False, "error": "url required"}
        args = {**kwargs, "url": url}
        result = await run_site_capture(args)
        result["ok"] = True
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
