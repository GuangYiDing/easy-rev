"""Pack init three platforms + explore error contracts via shipped call_tool."""

from __future__ import annotations

from pathlib import Path

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.pack.template import init_pack


@pytest.mark.parametrize(
    "platform,extra_hook",
    [
        ("web", "hooks.py"),
        ("macos", "hooks/ssl_pinning.js"),
        ("android", "hooks/network.js"),
    ],
)
def test_pack_init_three_platforms(tmp_path: Path, platform: str, extra_hook: str):
    dest = tmp_path / f"p-{platform}"
    init_pack(dest, pack_id=f"p-{platform}", platform=platform, with_hooks=True)
    assert (dest / "pack.yaml").is_file()
    assert (dest / "playbook.yaml").is_file()
    assert (dest / extra_hook).is_file()
    yaml_text = (dest / "pack.yaml").read_text(encoding="utf-8")
    assert "easy-rev.pack" in yaml_text or "platform:" in yaml_text


@pytest.mark.asyncio
async def test_doctor_has_version_and_platforms():
    r = await call_tool("doctor", {"platform": "all"})
    assert r["ok"] is True
    assert r.get("version")
    plats = r.get("platforms") or {}
    assert "web" in plats
    assert "macos" in plats or "windows" in plats
    assert "android" in plats


@pytest.mark.asyncio
async def test_explore_error_contracts():
    web = await call_tool("explore", {"platform": "web"})
    assert web["ok"] is False
    assert web.get("error")

    desk = await call_tool("explore", {"platform": "windows"})
    assert desk["ok"] is False
    assert desk.get("error")

    mob = await call_tool("explore", {"platform": "ios"})
    assert mob["ok"] is False
    assert mob.get("error")


@pytest.mark.asyncio
async def test_pack_list_after_init(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_pack(tmp_path / "packs" / "listed", pack_id="listed", platform="web")
    r = await call_tool("pack.list", {})
    assert r["ok"] is True
    ids = [p["id"] for p in r.get("packs") or []]
    assert "listed" in ids
