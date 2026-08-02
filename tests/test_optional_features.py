"""Frida live sessions, pack run, AXML tree, MCP entry, message schema."""

from __future__ import annotations

from pathlib import Path

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.pack.runner import run_pack
from easy_rev.pack.template import init_pack
from easy_rev.platforms.common.frida_live import (
    drain_messages,
    eval_js,
    list_sessions,
    normalize_frida_message,
    start_session,
    stop_session,
)
from easy_rev.platforms.mobile.common.static import parse_axml_strings, parse_axml_tree


def test_normalize_frida_message_schema():
    m = normalize_frida_message(
        {"type": "send", "payload": {"type": "ssl_write", "module": "libssl", "len": 10}}
    )
    assert m["schema"] == "easy-rev.frida.message/v1"
    assert m["type"] == "send"
    assert m["event"] == "ssl_write"
    assert m["module"] == "libssl"

    err = normalize_frida_message({"type": "error", "description": "boom", "stack": "s"})
    assert err["error"]["description"] == "boom"


def test_frida_session_dry_run_lifecycle():
    # Without requiring real frida attach success — dry_run or error both ok for contract
    r = start_session(kind="desktop", platform="macos", target="nonexistent_easy_rev_xyz")
    assert r.get("status") in {"dry_run", "error", "attached"}
    assert "session" in r or r.get("session_id")
    sid = (r.get("session") or {}).get("session_id")
    if not sid:
        # error path may still register
        sessions = list_sessions()
        if sessions:
            sid = sessions[-1]["session_id"]
    if sid:
        d = drain_messages(sid, since=0, limit=10)
        assert d.get("ok") is True
        assert "messages" in d
        if d["messages"]:
            assert d["messages"][0].get("schema") == "easy-rev.frida.message/v1"
        e = eval_js(sid, "send({type:'ping'})")
        assert e.get("ok") is True or e.get("status") in {"dry_run", "attached", "error"}
        stop = stop_session(sid)
        assert stop.get("ok") is True


@pytest.mark.asyncio
async def test_ai_frida_session_tools():
    r = await call_tool(
        "frida.session.start",
        {"kind": "mobile", "platform": "android", "target": "com.example.none"},
    )
    assert "ok" in r
    assert r.get("status") in {"dry_run", "error", "attached"}
    lst = await call_tool("frida.session.list", {})
    assert lst.get("ok") is True
    assert "sessions" in lst
    # stop all
    for s in lst.get("sessions") or []:
        await call_tool("frida.session.stop", {"session_id": s["session_id"]})


def test_parse_axml_tree_text_manifest():
    raw = b'package="com.tree.app" android.permission.INTERNET MainActivity'
    tree = parse_axml_tree(raw)
    assert tree.get("package") == "com.tree.app" or any(
        "com.tree" in s for s in (tree.get("strings") or [])
    )
    s = parse_axml_strings(raw)
    assert s.get("strings")
    assert "nodes" in s


@pytest.mark.asyncio
async def test_pack_run_dry_run(tmp_path: Path):
    dest = tmp_path / "runpack"
    init_pack(dest, pack_id="runpack", platform="web", with_hooks=True)
    out = await run_pack(dest, dry_run=True)
    assert out.get("ok") is True
    assert out.get("dry_run") is True
    assert out.get("step_count", 0) >= 1
    assert any(s.get("mode") == "dry_run" or s.get("mode") == "executed_local" for s in out["steps"])
    assert Path(out["report_path"]).is_file() if out.get("report_path") else True

    ai = await call_tool("pack.run", {"path": str(dest), "dry_run": True})
    assert ai.get("ok") is True
    assert ai.get("steps")


@pytest.mark.asyncio
async def test_pack_run_protocol_flow(tmp_path: Path):
    dest = tmp_path / "flowpack"
    dest.mkdir()
    (dest / "pack.yaml").write_text(
        """
schema: easy-rev.pack/v1
id: flowpack
name: flowpack
platform: web
""",
        encoding="utf-8",
    )
    (dest / "flow.yaml").write_text(
        """
steps:
  - id: req1
    action: http.request
    method: GET
    url: https://example.com/
  - id: doc
    action: doctor
""",
        encoding="utf-8",
    )
    out = await run_pack(dest, dry_run=True)
    assert out.get("ok") is True
    assert out.get("source") == "flow.yaml"
    actions = [s.get("action") for s in out["steps"]]
    assert "http.request" in actions or "doctor" in actions


def test_mcp_module_importable():
    import easy_rev.mcp_server as m

    tools = m._tools_for_mcp()
    assert len(tools) >= 20
    names = {t["name"] for t in tools}
    assert "doctor" in names
    assert "pack.run" in names
    assert "frida.session.start" in names
    # main should exit cleanly when mcp missing
    try:
        import mcp  # noqa: F401
    except Exception:
        with pytest.raises(SystemExit):
            m.main()


@pytest.mark.asyncio
async def test_tools_catalog_includes_new():
    from easy_rev.ai.tools import tools_catalog

    names = {t["name"] for t in tools_catalog()}
    for n in (
        "pack.run",
        "frida.session.start",
        "frida.session.drain",
        "frida.session.eval",
        "web.diagnose",
        "pack.validate",
    ):
        assert n in names
