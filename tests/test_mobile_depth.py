"""Mobile commercial-depth APK/IPA static + Frida dry_run."""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.core.platform import Platform
from easy_rev.platforms.mobile.common.frida_session import capture_app, dry_run_result
from easy_rev.platforms.mobile.common.static import (
    analyze_native_so,
    analyze_package,
    classify_dex_strings,
    scan_apk_bytes,
    scan_ipa_bytes,
)
from easy_rev.platforms.mobile.scripts import list_scripts, load_script


def _minimal_elf64_so() -> bytes:
    data = bytearray(512)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<H", data, 16, 3)  # ET_DYN
    struct.pack_into("<H", data, 18, 183)  # aarch64
    data[200:240] = b"libssl.so.1.1\x00SSL_write\x00Java_com_x_n\x00"
    data[250:290] = b"https://native.example.com/v1\x00"
    return bytes(data)


def _minimal_macho_arm64() -> bytes:
    """Tiny thin arm64 Mach-O with one LC_LOAD_DYLIB (libSystem)."""
    # mach_header_64: magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved
    magic = 0xFEEDFACF
    cputype = 0x0100000C  # ARM64
    filetype = 2  # MH_EXECUTE
    ncmds = 1
    # dylib command size: 24 header + path padded
    path = b"/usr/lib/libSystem.B.dylib\x00"
    # name.offset = 24
    name_off = 24
    pad = (8 - (len(path) % 8)) % 8
    path_p = path + b"\x00" * pad
    cmdsize = 24 + len(path_p)
    sizeofcmds = cmdsize
    hdr = struct.pack("<IIIIIIII", magic, cputype, 0, filetype, ncmds, sizeofcmds, 0, 0)
    # LC_LOAD_DYLIB=0xC, timestamp/current/compat versions
    lc = struct.pack("<II", 0x0C, cmdsize) + struct.pack("<IIII", name_off, 0, 0, 0) + path_p
    # segment for realism — optional second LC would need ncmds=2; keep simple
    return hdr + lc


def _make_apk_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        manifest = (
            b'package="com.example.demoapp" '
            b'android.permission.INTERNET '
            b'android.permission.READ_PHONE_STATE '
            b"MainActivity CertificatePinner"
        )
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr(
            "classes.dex",
            b"dex\nhttps://api.example.com/v1/auth\n"
            b"javax.crypto.Cipher\nOkHttpClient\nCertificatePinner\n"
            b"Bearer token_sample\n/api/v2/login\nSharedPreferences\n",
        )
        zf.writestr("classes2.dex", b"dex2 multi-dex obfuscation signal")
        zf.writestr("lib/arm64-v8a/libnative.so", _minimal_elf64_so())
        zf.writestr(
            "res/xml/network_security_config.xml",
            b'<network-security-config><pin-set><pin digest="SHA-256">abc</pin></pin-set>',
        )
        zf.writestr("META-INF/CERT.RSA", b"fake-cert")
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        zf.writestr("assets/config.json", b'{"api":"https://cdn.example.com/x"}')
    return buf.getvalue()


def _make_ipa_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.iosdemo</string>
<key>MinimumOSVersion</key><string>15.0</string>
<key>NSPinnedDomains</key><dict><key>api.example.com</key><dict/></dict>
</dict></plist>
"""
        zf.writestr("Payload/Demo.app/Info.plist", plist.encode())
        zf.writestr(
            "Payload/Demo.app/Frameworks/Foo.framework/Foo",
            _minimal_macho_arm64() + b"\x00https://api.example.com/mobile\x00CCCrypt\x00TrustKit\x00",
        )
        zf.writestr("Payload/Demo.app/Demo", _minimal_macho_arm64())
    return buf.getvalue()


def test_scan_apk_bytes_package_urls_pinning():
    report = scan_apk_bytes(_make_apk_bytes())
    assert report["kind"] == "apk"
    assert report["package"] == "com.example.demoapp"
    assert any("INTERNET" in p for p in report.get("permissions") or [])
    assert report.get("urls")
    assert any("example.com" in u for u in report["urls"])
    assert report.get("ssl_pinning_hints")
    assert report.get("obfuscated") is True  # multi-dex
    assert report.get("has_network_security_config") is True
    assert report.get("signing", {}).get("v1_meta_inf") is True
    assert report.get("native_libs")
    # deep: native ELF + DEX string classification
    assert report.get("native_analysis")
    na = report["native_analysis"][0]
    assert na.get("is_elf") is True
    assert na.get("elf", {}).get("class") == "ELF64" or na.get("elf", {}).get("needed") is not None
    assert report.get("dex_string_classes")
    assert any(
        k in (report.get("dex_string_classes") or {})
        for k in ("crypto", "network", "pinning", "api_path", "token")
    )


def test_classify_dex_strings_buckets():
    text = (
        "javax.crypto.Cipher\nOkHttpClient\nCertificatePinner\n"
        "/api/v1/register\nBearer abc\nSharedPreferences\n"
    )
    out = classify_dex_strings(text)
    assert out["counts"].get("crypto")
    assert out["counts"].get("network") or out["counts"].get("pinning")
    assert out["hot"]


def test_analyze_native_so_shipped():
    so = analyze_native_so(_minimal_elf64_so(), name="lib/arm64/libx.so")
    assert so["is_elf"] is True
    assert so["elf"]["class"] == "ELF64"
    assert so.get("urls") or so["elf"].get("needed") or so["elf"].get("exports_hint")


def test_scan_ipa_bytes_bundle_id():
    report = scan_ipa_bytes(_make_ipa_bytes())
    assert report["kind"] == "ipa"
    assert report["package"] == "com.example.iosdemo"
    assert report.get("minimum_os_version") == "15.0"
    assert report.get("ssl_pinning_hints")
    assert report.get("urls") or report.get("frameworks")
    # deep: Payload binaries / framework macho analysis
    assert report.get("binary_analysis") or report.get("binaries")
    if report.get("binary_analysis"):
        ba = report["binary_analysis"][0]
        assert ba.get("format") in {"macho", "macho_fat"}
        assert ba.get("dylibs") is not None


@pytest.mark.asyncio
async def test_analyze_package_apk_artifacts(tmp_path: Path):
    apk = tmp_path / "demo.apk"
    apk.write_bytes(_make_apk_bytes())
    report = await analyze_package(apk, platform=Platform.ANDROID)
    assert report["ok"] is True
    assert report["package"] == "com.example.demoapp"
    assert report["summary"]["package"] == "com.example.demoapp"
    assert report["artifact_paths"]
    assert Path(report["artifact_paths"][0]).is_file()
    # androguard optional — base path must work either way
    assert "androguard" in report


@pytest.mark.asyncio
async def test_analyze_package_ipa(tmp_path: Path):
    ipa = tmp_path / "demo.ipa"
    ipa.write_bytes(_make_ipa_bytes())
    report = await analyze_package(ipa, platform=Platform.IOS)
    assert report["ok"] is True
    assert report["package"] == "com.example.iosdemo"
    assert Path(report["artifact_paths"][0]).is_file()


@pytest.mark.asyncio
async def test_mobile_frida_dry_run_or_device_error():
    result = await capture_app(
        "com.example.nonexistent_easy_rev",
        platform=Platform.ANDROID,
        duration_s=0.5,
        spawn=True,
    )
    assert "ok" in result or "attached" in result
    if result.get("dry_run"):
        assert result.get("hint")
        assert result["attached"] is False
    else:
        # frida present but no device/app
        assert result.get("error") or result.get("attached") is False
        assert result.get("hint") or result.get("error")


def test_mobile_dry_run_shape():
    r = dry_run_result(
        "com.x",
        platform=Platform.ANDROID,
        reason="frida not installed: x",
        hint="pip install 'easy-rev[frida]'",
    )
    assert r["dry_run"] and r["ok"] and not r["attached"]
    assert r.get("status") == "dry_run"
    assert r.get("degraded") is True


def test_bundled_mobile_scripts():
    names = list_scripts()
    assert "ssl_pinning.js" in names
    assert "crypto.js" in names
    assert "network.js" in names
    # iOS / ObjC templates
    assert "ios_ssl.js" in names
    assert "ios_crypto.js" in names
    assert "CertificatePinner" in load_script("ssl_pinning.js") or "pinning" in load_script(
        "ssl_pinning.js"
    )
    ios = load_script("ios_ssl")
    assert "SecTrust" in ios or "ObjC" in ios
    assert len(ios) > 80


@pytest.mark.asyncio
async def test_ai_mobile_scripts_and_explore_missing():
    s = await call_tool("mobile.scripts", {})
    assert s["ok"] is True
    assert len(s.get("scripts") or []) >= 5
    r = await call_tool("explore", {"platform": "android"})
    assert r["ok"] is False
    assert r.get("error")
