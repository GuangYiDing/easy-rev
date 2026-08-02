"""Diagnose protocol / hybrid reverse-engineering failures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from easy_rev.core.paths import artifacts_dir
from easy_rev.storage.db import Storage


def diagnose_http_message(message: str | None, meta: dict[str, Any] | None) -> list[str]:
    tips: list[str] = []
    msg = (message or "").lower()
    meta = meta or {}
    status = meta.get("last_http_status")
    if status in {401, 403}:
        tips.append("401/403: import browser cookies (http.from_browser) or refresh CSRF/session")
        tips.append("Consider TLS fingerprint: vars.http_impersonate=chrome120 + curl_cffi")
    if status == 429:
        tips.append("429 rate limit: lower concurrency, rotate proxy, increase min_interval_s")
    if status in {400, 422}:
        tips.append("400/422 validation: compare request JSON to capture apis[] post_data field names")
        tips.append("Check extract wiring — prior csrf/token may be missing")
    if "ssl" in msg or "certificate" in msg:
        tips.append("TLS/certificate error: check proxy MITM or set verify appropriately")
    if "cookie" in msg or status in {401, 403}:
        tips.append("Hybrid: put captcha/login in browser then http.from_browser before register API")
    if "timeout" in msg:
        tips.append("Increase http.request timeout_s; check proxy dead")
    if meta.get("http_from_browser", {}).get("skipped"):
        tips.append("http.from_browser skipped (no page) — run with camoufox hybrid engine")
    if not tips:
        tips.append("Re-run site.capture/re.explore and compare failed body to capture response")
        tips.append("Use re.diagnose on job_id or inspect extract save_as payloads in artifacts")
    return tips


async def diagnose_protocol_job(job_id: str, *, storage: Storage | None = None) -> dict[str, Any]:
    """Diagnose a prior RE job/capture folder by job_id (artifacts + optional DB)."""
    storage = storage or Storage()
    job = storage.get_job(job_id)
    art_root = artifacts_dir() / job_id

    findings: list[dict[str, Any]] = []
    http_artifacts: list[str] = []
    tips: list[str] = []
    if art_root.exists():
        for p in sorted(art_root.rglob("*.json")):
            http_artifacts.append(str(p))
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(data, dict) and (
                "status" in data and ("text" in data or "json" in data)
            ):
                findings.append(
                    {
                        "path": str(p),
                        "status": data.get("status"),
                        "url": data.get("url"),
                        "error": data.get("error"),
                        "body_preview": str(data.get("text") or data.get("json") or "")[:400],
                    }
                )
                tips.extend(
                    diagnose_http_message(
                        str(data.get("error") or data.get("message") or ""),
                        data if isinstance(data, dict) else {},
                    )
                )

    seen: set[str] = set()
    uniq = []
    for t in tips:
        if t not in seen:
            seen.add(t)
            uniq.append(t)

    return {
        "job_id": job_id,
        "job": job,
        "http_artifacts": http_artifacts[:40],
        "http_findings": findings[:15],
        "suggestions": uniq[:12]
        or ["No protocol-specific signals; re-run explore/capture and inspect artifacts"],
    }


def diagnose_capture_path(path: str | Path) -> dict[str, Any]:
    """Offline diagnose a capture file for protocol readiness."""
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    apis = data.get("apis") or []
    signing = data.get("signing") or {}
    js = data.get("js_analysis") or {}
    graph = data.get("dependency_graph") or {}
    tips: list[str] = []
    if not apis:
        tips.append("No API candidates — use browser declarative flow or re-capture with submit=true")
    if signing.get("sig_headers") or js.get("risk") in {"medium", "high"}:
        tips.append("Signing/crypto risk — prefer hybrid + http.from_browser or hooks.py")
    if graph.get("count", 0) >= 2:
        tips.append("Dependency graph has multiple nodes — ensure extract wiring preserved in flow")
    roles = graph.get("roles") or []
    if "register" not in roles and apis:
        tips.append("No node role=register — manually pick signup API from top_apis")
    if not tips:
        tips.append("Capture looks protocol-friendly — pack.from_capture then engine=http dry-run")
    return {
        "path": str(p),
        "api_count": len(apis),
        "graph": graph,
        "signing_summary": {
            "headers": signing.get("sig_headers"),
            "body_keys": signing.get("sig_body_keys"),
            "recs": signing.get("recommendations"),
        },
        "js_risk": js.get("risk"),
        "suggestions": tips,
    }
