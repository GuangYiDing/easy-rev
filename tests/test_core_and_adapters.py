"""Core models + platform adapters (no real devices required)."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.core.platform import Platform, PlatformFamily
from easy_rev.pack.template import init_pack
from easy_rev.platforms.base import get_adapter
from easy_rev.platforms.desktop.common.static import analyze_binary
from easy_rev.platforms.mobile.common.static import analyze_package


def test_platform_family():
    assert Platform.WEB.family is PlatformFamily.WEB
    assert Platform.WINDOWS.family is PlatformFamily.DESKTOP
    assert Platform.MACOS.family is PlatformFamily.DESKTOP
    assert Platform.ANDROID.family is PlatformFamily.MOBILE
    assert Platform.IOS.family is PlatformFamily.MOBILE


def test_get_adapter():
    assert get_adapter("web").family is PlatformFamily.WEB
    assert get_adapter(Platform.MACOS).family is PlatformFamily.DESKTOP
    assert get_adapter(Platform.ANDROID).family is PlatformFamily.MOBILE


@pytest.mark.asyncio
async def test_doctor_all():
    result = await call_tool("doctor", {"platform": "all"})
    assert result["ok"] is True
    assert "web" in result["platforms"]
    assert "macos" in result["platforms"] or "windows" in result["platforms"]
    assert "android" in result["platforms"]


def test_pack_init_web(tmp_path: Path):
    dest = tmp_path / "p-web"
    init_pack(dest, pack_id="p-web", platform="web", with_hooks=True)
    assert (dest / "pack.yaml").exists()
    assert (dest / "playbook.yaml").exists()
    assert (dest / "hooks.py").exists()


def test_pack_init_android(tmp_path: Path):
    dest = tmp_path / "p-and"
    init_pack(dest, pack_id="p-and", platform="android", with_hooks=True)
    assert (dest / "hooks" / "ssl_pinning.js").exists()
    assert (dest / "hooks" / "network.js").exists()


@pytest.mark.asyncio
async def test_desktop_static_fake_pe(tmp_path: Path):
    # Minimal MZ + PE header stub
    pe = bytearray(0x200)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    # COFF: machine, num sections=1, ...
    struct.pack_into("<H", pe, 0x84 + 2, 1)  # NumberOfSections
    struct.pack_into("<H", pe, 0x84 + 16, 0)  # SizeOfOptionalHeader
    # section name
    pe[0x84 + 20 : 0x84 + 28] = b".text\x00\x00\x00"
    pe.extend(b"https://api.example.com/v1/login\x00IsDebuggerPresent\x00AES-HMAC")
    path = tmp_path / "fake.exe"
    path.write_bytes(pe)

    report = await analyze_binary(path, platform=Platform.WINDOWS)
    assert report.get("magic", {}).get("format") == "pe"
    assert report.get("artifact_paths")
    assert any("example.com" in s for s in report.get("interesting_strings") or [])


@pytest.mark.asyncio
async def test_mobile_static_fake_apk(tmp_path: Path):
    apk = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        # pseudo-manifest with readable strings
        manifest = b'package="com.example.demo" android:name="android.permission.INTERNET"'
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"dex\nhttps://api.example.com/x\nCertificatePinner\n")
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x00\x01")

    report = await analyze_package(apk, platform=Platform.ANDROID)
    assert report.get("kind") == "apk"
    assert report.get("package") == "com.example.demo"
    assert report.get("artifact_paths")


@pytest.mark.asyncio
async def test_ai_pack_list():
    result = await call_tool("pack.list", {})
    assert result["ok"] is True
    assert "packs" in result


@pytest.mark.asyncio
async def test_explore_desktop_missing_target():
    result = await call_tool("explore", {"platform": "macos"})
    assert result["ok"] is False
    assert result.get("error")


@pytest.mark.asyncio
async def test_web_analyze_js_text():
    result = await call_tool(
        "web.analyze_js",
        {"text": "function signRequest(body){ return CryptoJS.HmacSHA256(body, secret); }"},
    )
    assert result["ok"] is True
    assert "risk" in result or "crypto_kinds" in result or "sign_function_candidates" in result
