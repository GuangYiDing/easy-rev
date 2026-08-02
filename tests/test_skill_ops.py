"""Skill router, scope gate, evidence chain, field journal."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from easy_rev.ai.handlers import call_tool
from easy_rev.pack.runner import run_pack
from easy_rev.pack.template import init_pack
from easy_rev.skill.case import case_guard, case_init
from easy_rev.skill.routing import master_route


def test_master_route_web():
    r = master_route("逆向这个网页的 JS 签名 https://example.com")
    assert r["ok"] is True
    assert r["route_id"] == "R-WEB"
    assert r["platform"] == "web"
    assert "web.explore" in r["tools"]


def test_master_route_android():
    r = master_route("分析 APK SSL pinning")
    assert r["route_id"] == "R-ANDROID"
    assert r["platform"] == "android"


def test_master_route_forced_platform():
    r = master_route("generic task", platform="macos")
    assert r["platform"] == "macos"
    assert r["primary"] == "desktop-reverse"


@pytest.mark.asyncio
async def test_route_tool():
    r = await call_tool("route", {"hint": "macOS .app Mach-O Frida"})
    assert r["ok"] is True
    assert r["platform"] == "macos"


def test_case_init_and_guard(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # journal writes under cwd/skills
    out = case_init(
        hint="web protocol pack for example.com",
        case_name="demo-case",
        platform="web",
        auth_granted=False,
        network_profile="offline",
        target="https://example.com",
        with_pack=True,
    )
    assert out["ok"] is True
    root = Path(out["path"])
    assert (root / "scope.yaml").is_file()
    assert (root / "evidence").is_dir()
    assert (root / "findings.md").is_file()
    assert (root / "pack.yaml").is_file()

    g = case_guard(root)
    assert g["ready"] is False
    assert g["exit_code"] == 2

    # grant auth
    scope = yaml.safe_load((root / "scope.yaml").read_text(encoding="utf-8"))
    scope["auth"]["status"] = "granted"
    scope["auth"]["basis"] = "own_system"
    scope["network_profile"]["mode"] = "authorized_target_only"
    scope["in_scope"]["assets"] = ["https://example.com"]
    scope["signoff"]["ready_for_act"] = True
    (root / "scope.yaml").write_text(yaml.safe_dump(scope, allow_unicode=True), encoding="utf-8")
    g2 = case_guard(root)
    assert g2["ready"] is True
    assert g2["exit_code"] == 0


@pytest.mark.asyncio
async def test_evidence_finding_path_and_journal(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    dest = tmp_path / "packs" / "ev"
    init_pack(dest, pack_id="ev", platform="web", with_ops=True)

    e = await call_tool(
        "evidence.append",
        {
            "path": str(dest),
            "title": "sample request",
            "repro_command": "curl -I https://example.com",
            "raw_excerpt": "HTTP/1.1 200",
        },
    )
    assert e["ok"] is True
    assert (dest / "evidence" / f"{e['id']}.md").is_file()

    f = await call_tool(
        "finding.append",
        {
            "path": str(dest),
            "title": "no auth header required on health",
            "evidence_ids": [e["id"]],
            "confidence": "high",
            "status": "validated",
        },
    )
    assert f["ok"] is True
    text = (dest / "findings.md").read_text(encoding="utf-8")
    assert f["id"] in text

    p = await call_tool(
        "path.append",
        {
            "path": str(dest),
            "title": "health check callflow",
            "steps": [{"action": "GET /health", "evidence": e["id"], "finding": f["id"]}],
        },
    )
    assert p["ok"] is True

    j = await call_tool(
        "journal.write",
        {
            "title": "health endpoint open",
            "summary": "health returns 200 without token",
            "platform": "web",
            "tags": ["web", "health"],
            "commands": ["curl -I https://example.com"],
            "root": str(tmp_path / "skills" / "field-journal"),
        },
    )
    assert j["ok"] is True
    s = await call_tool(
        "journal.search",
        {"query": "health", "root": str(tmp_path / "skills" / "field-journal")},
    )
    assert s["ok"] is True
    assert s["count"] >= 1


@pytest.mark.asyncio
async def test_pack_run_execute_blocked_without_scope(tmp_path: Path):
    dest = tmp_path / "blocked"
    init_pack(dest, pack_id="blocked", platform="web", with_ops=True)
    # pending auth by default
    result = await run_pack(dest, dry_run=False, max_steps=1)
    assert result["ok"] is False
    assert result.get("status") == "blocked" or "scope" in str(result.get("error", "")).lower()

    # dry_run still ok
    dry = await run_pack(dest, dry_run=True, max_steps=2)
    assert dry["ok"] is True


@pytest.mark.asyncio
async def test_pack_init_includes_ops(tmp_path: Path):
    dest = tmp_path / "withops"
    r = await call_tool("pack.init", {"pack_id": "withops", "dest": str(dest), "platform": "web"})
    assert r["ok"] is True
    assert (dest / "scope.yaml").is_file()
    assert (dest / "evidence").is_dir()


@pytest.mark.asyncio
async def test_skill_list():
    r = await call_tool("skill.list", {})
    assert r["ok"] is True
    # may be 0 if cwd has no skills; just ensure shape
    assert "skills" in r
    assert "count" in r
