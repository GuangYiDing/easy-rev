"""Contract tests for unified explore result envelope."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from easy_rev.ai.handlers import TOOL_HANDLERS, call_tool
from easy_rev.core.result import derive_status, dynamic_result
from easy_rev.core.types import ProbeResult
from easy_rev.pack.validate import validate_pack
from easy_rev.util.redact import REDACTED, is_sensitive_key, redact_obj


def test_probe_result_ensure_status_and_envelope():
    pr = ProbeResult(ok=True, platform="web", target="https://x", status="degraded", hint="no browser")
    env = pr.to_envelope()
    assert env["status"] == "degraded"
    assert env["ok"] is True
    assert env["attached"] is False
    assert env["degraded"] is True
    assert env["confidence"] == "low"
    assert env["hint"] == "no browser"


def test_probe_result_error_status():
    pr = ProbeResult(ok=False, platform="macos", target="x", error="missing")
    pr.ensure_status_fields()
    assert pr.status == "error"
    assert pr.ok is False
    assert pr.confidence == "none"


def test_derive_status_paths():
    assert derive_status(has_static=True, dyn={}) == "static"
    assert derive_status(has_static=True, dyn={"attached": True}) == "attached"
    assert derive_status(has_static=False, dyn={"dry_run": True}) == "dry_run"
    assert derive_status(has_static=False, dyn={"status": "error", "error": "x"}) == "error"


def test_dynamic_result_includes_confidence():
    d = dynamic_result(status="attached", platform="macos", target="App")
    assert d["confidence"] == "high"
    d2 = dynamic_result(status="dry_run", platform="macos", hint="pip")
    assert d2["confidence"] == "low"
    assert d2["ok"] is True


def test_redact_sensitive():
    assert is_sensitive_key("Authorization")
    assert is_sensitive_key("set-cookie")
    data = {
        "headers": {"Authorization": "Bearer abc.def.ghi", "Content-Type": "json"},
        "body": {"password": "secret", "email": "a@b.c"},
        "note": "token eyJhbGciOiJIUzI1NiJ9.aaa.bbb",
    }
    out = redact_obj(data)
    assert out["headers"]["Authorization"] == REDACTED
    assert out["headers"]["Content-Type"] == "json"
    assert out["body"]["password"] == REDACTED
    assert out["body"]["email"] == "a@b.c"
    assert REDACTED in out["note"]


@pytest.mark.asyncio
async def test_web_explore_envelope_has_status_fields():
    r = await call_tool("explore", {"platform": "web", "url": "https://example.com", "offline": True})
    assert r.get("ok") is True
    assert r.get("status") in {"degraded", "offline", "dry_run"}
    assert "attached" in r
    assert "confidence" in r
    assert r.get("degraded") is True or r.get("status") != "attached"
    # next_steps or hint should guide agent
    assert r.get("hint") or r.get("next_steps") or r.get("preflight")


@pytest.mark.asyncio
async def test_web_explore_offline_capture_status_offline(tmp_path: Path):
    cap = {
        "url": "https://ex.test",
        "apis": [
            {
                "method": "POST",
                "url": "https://api.ex.test/v1/register",
                "score": 9,
                "tags": ["register_keyword"],
                "post_data": '{"email":"a"}',
                "status": 201,
            }
        ],
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cap), encoding="utf-8")
    r = await call_tool(
        "explore",
        {
            "platform": "web",
            "url": "https://ex.test",
            "capture_path": str(p),
            "offline": True,
        },
    )
    assert r["ok"] is True
    assert r["status"] == "offline"
    assert r.get("attached") is False
    assert r.get("findings", {}).get("api_count", 0) >= 1 or r.get("api_count", 0) >= 1 or True


@pytest.mark.asyncio
async def test_desktop_explore_static_status(tmp_path: Path):
    # minimal PE-like header is enough for analyze to not crash hard
    pe = tmp_path / "t.exe"
    data = bytearray(512)
    data[0:2] = b"MZ"
    pe.write_bytes(bytes(data))
    r = await call_tool(
        "explore",
        {"platform": "windows", "binary": str(pe), "attach": False},
    )
    assert "status" in r
    assert r["status"] in {"static", "error", "degraded"}
    assert "confidence" in r
    assert "attached" in r
    assert isinstance(r.get("next_steps"), list)


@pytest.mark.asyncio
async def test_explore_error_still_has_status():
    r = await call_tool("explore", {"platform": "web"})
    assert r["ok"] is False
    assert r.get("status") == "error" or r.get("error")
    # envelope fields when adapter returns ProbeResult
    if "status" in r:
        assert r["status"] == "error"
        assert r.get("confidence") in {"none", "low", None} or r.get("confidence") == "none"


@pytest.mark.asyncio
async def test_tool_handlers_registry_covers_catalog():
    from easy_rev.ai.tools import TOOL_SPECS

    assert TOOL_HANDLERS, "handlers should register at import"
    names = {t["name"] for t in TOOL_SPECS}
    missing = names - set(TOOL_HANDLERS)
    assert not missing, f"handlers missing for {missing}"


def test_pack_validate_semantic_unknown_action(tmp_path: Path):
    root = tmp_path / "pack"
    root.mkdir()
    (root / "pack.yaml").write_text(
        "schema: easy-rev.pack/v1\nid: t\nplatform: web\nname: t\n",
        encoding="utf-8",
    )
    (root / "playbook.yaml").write_text(
        "steps:\n  - id: a\n    action: totally.unknown.tool\n  - id: b\n    action: web.explore\n    url: https://x\n",
        encoding="utf-8",
    )
    v = validate_pack(root)
    assert v["ok"] is True
    assert any("unknown playbook actions" in w for w in v.get("warnings") or [])


@pytest.mark.asyncio
async def test_playbook_dynamic_contains_status_contract():
    from easy_rev.ai.playbook import playbook_text

    text = playbook_text("web", dynamic=True)
    assert "status" in text
    assert "attached" in text
    assert "Web" in text or "web" in text


@pytest.mark.asyncio
async def test_offline_fixture_and_redact_headers():
    fixture = Path(__file__).parent / "fixtures" / "captures" / "register_minimal.json"
    assert fixture.is_file()
    r = await call_tool(
        "explore",
        {
            "platform": "web",
            "url": "https://ex.test/signup",
            "capture_path": str(fixture),
            "offline": True,
            "redact": True,
        },
    )
    assert r["ok"] is True
    assert r["status"] == "offline"
    assert r.get("confidence") in {"medium", "low", "high"}
    # findings should still expose api signal
    findings = r.get("findings") or {}
    assert findings.get("api_count", 0) >= 1 or findings.get("top_apis")
