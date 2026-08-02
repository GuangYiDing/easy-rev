"""Doctor / preflight / fix dry-run contracts."""

from __future__ import annotations

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.core.deps import DEP_CATALOG, catalog_public, detect_dep, fix_deps, preflight


def test_catalog_nonempty():
    cat = catalog_public()
    assert len(cat) >= 10
    ids = {c["id"] for c in cat}
    assert "frida" in ids or "camoufox" in ids
    assert "httpx" in ids


def test_preflight_all_structure():
    pf = preflight("all")
    assert pf["ok"] is True
    assert "platforms" in pf
    assert "web" in pf["platforms"]
    assert "fixable" in pf
    assert "install_hints" in pf
    assert "next_steps" in pf
    web = pf["platforms"]["web"]
    assert "score" in web
    assert "checks" in web
    assert isinstance(web["checks"], list)
    # each check has present flag
    assert all("present" in c or c.get("skipped") for c in web["checks"])


def test_preflight_path_browser():
    pf = preflight("web", path="browser")
    checks = (pf["platforms"].get("web") or {}).get("checks") or []
    ids = {c["id"] for c in checks}
    # browser path should surface camoufox/playwright
    assert "camoufox" in ids or "playwright" in ids


def test_detect_httpx_present():
    spec = next(s for s in DEP_CATALOG if s.id == "httpx")
    d = detect_dep(spec)
    assert d["present"] is True


def test_fix_deps_dry_run():
    r = fix_deps(["camoufox", "frida"], dry_run=True)
    assert r["ok"] is True
    assert r["results"]
    for item in r["results"]:
        assert item.get("dry_run") is True or item.get("skipped")
        if item.get("dry_run"):
            assert item.get("commands")


@pytest.mark.asyncio
async def test_ai_doctor_preflight_fix_catalog():
    doc = await call_tool("doctor", {"platform": "all"})
    assert doc["ok"] is True
    assert "fixable" in doc
    assert "missing_required" in doc or "missing" in doc
    assert "next_steps" in doc
    assert "ai_hint" in doc
    # platforms have scores
    for key in ("web", "macos", "android"):
        if key in (doc.get("platforms") or {}):
            assert "score" in doc["platforms"][key] or "ready" in doc["platforms"][key]

    pf = await call_tool("doctor.preflight", {"platform": "web"})
    assert pf["ok"] is True
    assert "web" in (pf.get("platforms") or {})

    cat = await call_tool("doctor.catalog", {"platform": "web"})
    assert cat["ok"] is True
    assert cat.get("count", 0) >= 3

    fix = await call_tool("doctor.fix", {"ids": ["curl_cffi"], "dry_run": True})
    assert fix["ok"] is True
    assert fix.get("results") is not None


@pytest.mark.asyncio
async def test_explore_includes_preflight():
    r = await call_tool("explore", {"platform": "web", "url": "https://example.com", "offline": True})
    # degraded explore still returns preflight block
    assert "preflight" in r
    assert "missing" in r["preflight"] or "ready" in r["preflight"]
