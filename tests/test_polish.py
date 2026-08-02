"""Polish pass: status semantics, web degrade, dex/axml helpers, doctor hints."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.core.platform import Platform
from easy_rev.core.result import dynamic_result, install_hints
from easy_rev.platforms.desktop.common.frida_session import dry_run_result as desktop_dry
from easy_rev.platforms.mobile.common.frida_session import dry_run_result as mobile_dry
from easy_rev.platforms.mobile.common.static import (
    parse_axml_strings,
    parse_dex_string_ids,
    scan_apk_bytes,
)
from easy_rev.platforms.web.re.explore import run_re_explore


def test_dynamic_result_status_semantics():
    d = dynamic_result(status="dry_run", platform="macos", target="p", error="no frida", hint="pip")
    assert d["ok"] is True
    assert d["dry_run"] is True
    assert d["attached"] is False
    assert d["status"] == "dry_run"
    assert d["degraded"] is True

    e = dynamic_result(status="error", platform="android", error="no device")
    assert e["ok"] is False
    assert e["status"] == "error"
    assert e["attached"] is False

    a = dynamic_result(status="attached", platform="macos", pid=1)
    assert a["ok"] is True and a["attached"] is True and a["dry_run"] is False


def test_desktop_mobile_dry_run_has_status():
    d = desktop_dry("App", platform=Platform.MACOS, reason="x", hint="y")
    assert d["status"] == "dry_run" and d["ok"] is True and not d["attached"]
    m = mobile_dry("com.x", platform=Platform.ANDROID, reason="x", hint="y")
    assert m["status"] == "dry_run" and m["degraded"] is True


def test_install_hints():
    hints = install_hints(["frida", "camoufox", "unknown_dep"])
    assert any("frida" in h for h in hints)
    assert any("camoufox" in h for h in hints)
    assert any("unknown_dep" in h for h in hints)


def test_parse_dex_string_ids_raw_scan_and_header():
    # non-header synthetic
    raw = b"javax.crypto.Cipher\x00OkHttpClient\x00/api/v1/login\x00"
    out = parse_dex_string_ids(raw)
    assert out["string_count"] >= 1
    assert out.get("source") in {"raw_scan", "string_ids"}

    # minimal fake dex header with one string_id
    data = bytearray(256)
    data[0:4] = b"dex\n"
    data[4:8] = b"035\x00"
    # string_ids_size=1 at 0x38, string_ids_off=0x70
    struct.pack_into("<I", data, 0x38, 1)
    struct.pack_into("<I", data, 0x3C, 0x70)
    struct.pack_into("<I", data, 0x70, 0x80)  # string data offset
    # at 0x80: uleb128 len=5 + "hello"
    data[0x80] = 5
    data[0x81:0x86] = b"hello"
    data[0x86] = 0
    parsed = parse_dex_string_ids(bytes(data))
    assert parsed.get("source") == "string_ids"
    assert any("hello" in s for s in parsed.get("strings") or [])


def test_parse_axml_fallback_package_island():
    blob = b"\x00\x00package=\"com.example.app\" android.permission.INTERNET\x00"
    out = parse_axml_strings(blob)
    assert out.get("strings")
    assert any("com.example" in s or "INTERNET" in s for s in out["strings"])


def test_scan_apk_includes_dex_meta():
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b'package="com.polish.app" android.permission.INTERNET')
        # minimal dex-like
        dex = bytearray(128)
        dex[0:4] = b"dex\n"
        dex[4:8] = b"035\x00"
        struct.pack_into("<I", dex, 0x38, 0)
        struct.pack_into("<I", dex, 0x3C, 0)
        dex[64:100] = b"javax.crypto.Cipher\x00"
        zf.writestr("classes.dex", bytes(dex))
    report = scan_apk_bytes(buf.getvalue())
    assert report["package"] == "com.polish.app"
    assert report.get("dex_meta") is not None or report.get("dex_string_classes") is not None


@pytest.mark.asyncio
async def test_web_explore_degrades_without_browser():
    out = await run_re_explore({"url": "https://example.com/signup", "offline": True})
    assert out.get("ok") is True
    assert out.get("degraded") is True or out.get("status") in {"degraded", "offline"}
    assert out.get("hint") or out.get("notes")


@pytest.mark.asyncio
async def test_web_explore_offline_with_capture(tmp_path: Path):
    cap = {
        "url": "https://ex.test/s",
        "apis": [
            {
                "method": "POST",
                "url": "https://api.ex.test/v1/register",
                "score": 10,
                "tags": ["register_keyword"],
                "post_data": '{"email":"a"}',
                "status": 201,
            }
        ],
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cap), encoding="utf-8")
    out = await run_re_explore(
        {
            "url": "https://ex.test/s",
            "capture_path": str(p),
            "offline": True,
            "write_pack": True,
            "pack_id": "polish-off",
            "dest": str(tmp_path / "pack"),
        }
    )
    assert out.get("ok") is True
    assert out.get("status") == "offline"
    assert out.get("api_count", 0) >= 1
    assert (tmp_path / "pack" / "pack.yaml").is_file() or out.get("pack_path")


@pytest.mark.asyncio
async def test_doctor_install_hints():
    r = await call_tool("doctor", {})
    assert r["ok"] is True
    assert "install_hints" in r
    assert "status_legend" in r
    assert isinstance(r.get("missing"), list)
