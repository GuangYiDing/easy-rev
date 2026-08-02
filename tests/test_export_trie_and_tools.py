"""Export trie + new AI tools (diagnose/har/pack.validate)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.core.platform import Platform
from easy_rev.pack.template import init_pack
from easy_rev.pack.validate import validate_pack
from easy_rev.platforms.desktop.common.static import (
    analyze_binary,
    parse_export_trie,
    parse_macho_header,
)


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def test_parse_export_trie_synthetic():
    # node0 -> edge "hello" -> terminal node
    term = _uleb(0) + _uleb(0x42)
    node1 = _uleb(len(term)) + term + bytes([0])
    node0 = _uleb(0) + bytes([1]) + b"hello\x00"
    # child offset = len(node0) + 1 (1-byte uleb)
    child = len(node0) + 1
    blob = node0 + bytes([child]) + node1
    names = parse_export_trie(blob)
    assert "hello" in names


def test_parse_macho_export_trie_on_ls():
    ls = Path("/bin/ls")
    if not ls.is_file():
        pytest.skip("no /bin/ls")
    m = parse_macho_header(ls.read_bytes())
    # modern macOS /bin/ls has LC_DYLD_EXPORTS_TRIE
    assert m.get("export_source") in {"exports_trie", "dyld_info", "symtab"}
    exports = m.get("exports") or []
    assert "__mh_execute_header" in exports
    assert "_printf" not in exports
    trie = m.get("exports_trie") or []
    if m.get("export_source") in {"exports_trie", "dyld_info"}:
        assert trie
        assert "__mh_execute_header" in trie
        meta = m.get("export_trie_meta") or {}
        assert meta.get("count", 0) >= 1
        assert meta.get("size", 0) > 0


@pytest.mark.asyncio
async def test_analyze_binary_export_source_on_ls():
    ls = Path("/bin/ls")
    if not ls.is_file():
        pytest.skip("no /bin/ls")
    r = await analyze_binary(ls, platform=Platform.MACOS)
    assert r["ok"]
    assert r.get("export_source") in {"exports_trie", "dyld_info", "symtab"}
    assert "__mh_execute_header" in (r.get("exports") or [])
    assert "_printf" not in (r.get("exports") or [])


def test_validate_pack_ok_and_missing(tmp_path: Path):
    dest = tmp_path / "good"
    init_pack(dest, pack_id="good", platform="web", with_hooks=True)
    v = validate_pack(dest)
    assert v["ok"] is True
    assert not v["errors"]

    bad = tmp_path / "bad"
    bad.mkdir()
    v2 = validate_pack(bad)
    assert v2["ok"] is False
    assert any("pack.yaml" in e for e in v2["errors"])


@pytest.mark.asyncio
async def test_ai_pack_validate_and_diagnose_har(tmp_path: Path):
    dest = tmp_path / "p"
    init_pack(dest, pack_id="p", platform="android", with_hooks=True)
    v = await call_tool("pack.validate", {"path": str(dest)})
    assert v["ok"] is True

    cap = {
        "url": "https://ex.test/s",
        "apis": [
            {
                "method": "POST",
                "url": "https://api.ex.test/v1/register",
                "score": 12,
                "tags": ["register_keyword"],
                "post_data": '{"email":"a"}',
                "status": 201,
                "request_headers": {"content-type": "application/json"},
            }
        ],
        "signing": {"sig_headers": ["x-signature"]},
        "js_analysis": {"risk": "medium"},
    }
    cpath = tmp_path / "c.json"
    cpath.write_text(json.dumps(cap), encoding="utf-8")

    d = await call_tool("web.diagnose", {"capture_path": str(cpath)})
    assert d["ok"] is True
    assert d.get("api_count") == 1
    assert d.get("suggestions")

    har_path = tmp_path / "out.har"
    h = await call_tool(
        "web.har_export",
        {"capture_path": str(cpath), "dest": str(har_path), "title": "t"},
    )
    assert h["ok"] is True
    assert har_path.is_file()
    doc = json.loads(har_path.read_text(encoding="utf-8"))
    assert doc["log"]["entries"]
    assert doc["log"]["version"] == "1.2"

    tips = await call_tool("web.diagnose", {"message": "ssl certificate failed", "status": 403})
    assert tips["ok"] is True
    assert tips.get("suggestions")


@pytest.mark.asyncio
async def test_ai_session_list_smoke():
    # Should not crash even without active sessions / web extras
    r = await call_tool("web.session.list", {})
    assert "ok" in r
