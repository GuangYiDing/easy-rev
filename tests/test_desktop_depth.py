"""Desktop commercial-depth static + Frida dry_run (shipped functions)."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.core.platform import Platform
from easy_rev.platforms.desktop.common.frida_session import capture_process, dry_run_result
from easy_rev.platforms.desktop.common.static import (
    analyze_binary,
    extract_strings,
    parse_elf,
    parse_macho_header,
    parse_pe,
)
from easy_rev.platforms.desktop.scripts import list_scripts, load_script


def _minimal_pe_with_imports() -> bytes:
    """Build a tiny PE32 with .text section + import directory pointing at kernel32."""
    # DOS header
    pe = bytearray(0x400)
    pe[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", pe, 0x3C, e_lfanew)
    # PE sig
    pe[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    coff = e_lfanew + 4
    # Machine i386, 1 section, SizeOfOptionalHeader=0xE0 (PE32)
    struct.pack_into("<H", pe, coff, 0x14C)  # machine
    struct.pack_into("<H", pe, coff + 2, 1)  # NumberOfSections
    size_opt = 0xE0
    struct.pack_into("<H", pe, coff + 16, size_opt)
    struct.pack_into("<H", pe, coff + 18, 0x0102)  # characteristics EXEC+32BIT
    opt = coff + 20
    struct.pack_into("<H", pe, opt, 0x10B)  # PE32 magic
    # Subsystem Windows CUI at opt+68
    struct.pack_into("<H", pe, opt + 68, 3)
    # NumberOfRvaAndSizes
    struct.pack_into("<I", pe, opt + 92, 16)
    # Import directory at data dir index 1 → opt+96+8
    import_rva = 0x2000
    struct.pack_into("<I", pe, opt + 96 + 8, import_rva)
    struct.pack_into("<I", pe, opt + 96 + 12, 0x100)

    # Section .text at sec_off
    sec = opt + size_opt
    pe[sec : sec + 8] = b".text\x00\x00\x00"
    vsize, vrva, raw_size, raw_ptr = 0x200, 0x1000, 0x200, 0x200
    struct.pack_into("<IIII", pe, sec + 8, vsize, vrva, raw_size, raw_ptr)
    struct.pack_into("<I", pe, sec + 36, 0x60000020)  # CODE|EXEC|READ

    # Put import-ish strings + anti-debug + crypto + URL in section raw
    payload = (
        b"IsDebuggerPresent\x00"
        b"https://api.example.com/v1/login\x00"
        b"BCryptEncrypt\x00AES-HMAC\x00"
        b"kernel32.dll\x00"
        b"UPX0\x00"
    )
    pe[raw_ptr : raw_ptr + len(payload)] = payload
    # high entropy-ish filler
    pe[raw_ptr + len(payload) : raw_ptr + 0x100] = bytes(range(256))[: 0x100 - len(payload)]
    return bytes(pe)


def test_extract_strings_ascii_and_utf16():
    raw = b"hello_world_token\x00" + "secret_key_value".encode("utf-16le")
    ss = extract_strings(raw, min_len=6)
    assert any("hello_world" in s for s in ss)
    assert any("secret_key" in s for s in ss)


def test_parse_pe_sections_and_format():
    data = _minimal_pe_with_imports()
    pe = parse_pe(data)
    assert pe.get("error") in (None, "not_mz") or pe.get("format") == "pe"
    assert pe["format"] == "pe"
    assert pe["sections"]
    assert pe["sections"][0]["name"] == ".text"
    assert "entropy" in pe["sections"][0]


@pytest.mark.asyncio
async def test_analyze_binary_pe_report(tmp_path: Path):
    path = tmp_path / "sample.exe"
    path.write_bytes(_minimal_pe_with_imports())
    report = await analyze_binary(path, platform=Platform.WINDOWS)
    assert report["ok"] is True
    assert report["magic"]["format"] == "pe"
    assert report["summary"]["format"] == "pe"
    assert report["artifact_paths"]
    for p in report["artifact_paths"]:
        assert Path(p).is_file()
    # commercial signals from embedded strings
    assert report["anti_debug"] is True or any(
        "IsDebugger" in s for s in report.get("interesting_strings") or []
    )
    assert report.get("urls") or any(
        "example.com" in s for s in report.get("interesting_strings") or []
    )
    assert report.get("crypto_hints") or report.get("packing_suspected") is not None


@pytest.mark.asyncio
async def test_analyze_macho_host_ls():
    """Host-observable macOS path: /bin/ls via otool libs when available."""
    ls = Path("/bin/ls")
    if not ls.is_file():
        pytest.skip("no /bin/ls")
    report = await analyze_binary(ls, platform=Platform.MACOS)
    assert report["ok"] is True
    assert report["magic"]["format"] in {"macho", "macho_fat"}
    # either pure parse dylibs or otool
    libs = report.get("imports_or_libs") or []
    macho = report.get("macho") or {}
    assert libs or macho.get("dylibs") is not None or macho.get("format")
    assert Path(report["artifact_paths"][0]).is_file()


def test_parse_macho_header_on_ls():
    ls = Path("/bin/ls")
    if not ls.is_file():
        pytest.skip("no /bin/ls")
    data = ls.read_bytes()
    m = parse_macho_header(data)
    assert m.get("format") in {"macho", "macho_fat"}
    assert m.get("error") is None or m.get("nfat_arch")


def test_parse_macho_pure_dylibs_nonempty_on_ls():
    """64-bit mach_header size + LC_LOAD_DYLIB must yield real dylibs without otool."""
    ls = Path("/bin/ls")
    if not ls.is_file():
        pytest.skip("no /bin/ls")
    m = parse_macho_header(ls.read_bytes())
    dylibs = m.get("slice_dylibs") or m.get("dylibs") or []
    assert m.get("ncmds", 0) > 0
    assert m.get("hdr_size") in {28, 32} or m.get("format") == "macho_fat"
    # Pure parser path — must not be empty on a real linked binary
    assert dylibs, f"expected dylibs from pure parse, got empty (macho={m})"
    blob = "\n".join(dylibs)
    assert any(
        x in blob
        for x in ("libSystem", "libutil", "libncurses", "/usr/lib/")
    ), dylibs
    # must not mis-parse LC_SEGMENT_64 (0x19) as dylib path garbage
    assert not any(s.startswith("__") for s in dylibs)


@pytest.mark.asyncio
async def test_frida_dry_run_without_install():
    """When frida missing, capture returns dry_run contract (or real attach if present)."""
    result = await capture_process(
        "nonexistent_process_easy_rev_xyz",
        platform=Platform.MACOS,
        duration_s=0.5,
    )
    assert "ok" in result or "attached" in result
    if result.get("dry_run"):
        assert result.get("hint")
        assert result.get("attached") is False
    else:
        # frida installed but process missing → explicit error
        assert result.get("error") or result.get("attached") is False


def test_dry_run_result_shape():
    r = dry_run_result(
        "foo",
        platform=Platform.WINDOWS,
        reason="frida not installed: x",
        hint="pip install 'easy-rev[frida]'",
    )
    assert r["dry_run"] is True
    assert r["ok"] is True
    assert r["attached"] is False
    assert r.get("status") == "dry_run"
    assert r.get("degraded") is True
    assert "hint" in r


def test_bundled_desktop_scripts():
    names = list_scripts()
    assert "ssl_trace.js" in names
    assert "crypto_trace.js" in names
    # deepest tier: module / file / http beyond ssl+crypto
    assert "module_enum.js" in names
    assert "file_trace.js" in names
    assert "http_trace.js" in names
    src = load_script("ssl_trace.js")
    assert "SSL" in src or "ssl" in src
    mod = load_script("module_enum.js")
    assert "enumerateModules" in mod
    assert len(mod) > 80
    ft = load_script("file_trace")
    assert "open" in ft or "fopen" in ft


def test_parse_elf_minimal():
    # Minimal ELF64 LE header + empty section table
    data = bytearray(256)
    data[0:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # LE
    data[6] = 1  # version
    # e_type=ET_DYN(3), e_machine=EM_AARCH64(183) at offset 16
    struct.pack_into("<H", data, 16, 3)
    struct.pack_into("<H", data, 18, 183)
    # e_shoff at 40, e_shentsize/shnum/shstrndx at 58
    struct.pack_into("<Q", data, 40, 0)
    struct.pack_into("<H", data, 58, 64)
    struct.pack_into("<H", data, 60, 0)
    struct.pack_into("<H", data, 62, 0)
    # plant a needed lib string
    data[100:120] = b"libssl.so.1.1\x00"
    data[130:160] = b"SSL_write\x00Java_com_x\x00"
    elf = parse_elf(bytes(data))
    assert elf["format"] == "elf"
    assert elf.get("error") in (None, "short_ehdr") or elf.get("class") == "ELF64"
    assert elf.get("class") == "ELF64"
    assert "libssl" in "\n".join(elf.get("needed") or [])
    assert elf.get("exports_hint")


def _minimal_pe_with_exports() -> bytes:
    """PE32 with a real export directory naming MyExportFn / AnotherExport.

    Section .text: VA=0x1000, PointerToRawData=0x200.
    file_off = raw_ptr + (rva - va); rva = va + (file_off - raw_ptr).
    """
    pe = bytearray(0x800)
    pe[0:2] = b"MZ"
    e_lfanew = 0x80
    pe[0x3C:0x40] = struct.pack("<I", e_lfanew)
    pe[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    coff = e_lfanew + 4
    # Machine, NumberOfSections, ... SizeOfOptionalHeader, Characteristics
    pe[coff : coff + 20] = struct.pack(
        "<HHIIIHH",
        0x14C,  # i386
        1,  # sections
        0,
        0,
        0,
        0xE0,  # SizeOfOptionalHeader
        0x2102,  # EXEC+DLL+32BIT
    )
    opt = coff + 20
    # PE32 optional header (minimal fields we care about)
    pe[opt : opt + 2] = struct.pack("<H", 0x10B)
    pe[opt + 68 : opt + 70] = struct.pack("<H", 3)  # subsystem
    pe[opt + 92 : opt + 96] = struct.pack("<I", 16)  # NumberOfRvaAndSizes

    vrva, raw_ptr = 0x1000, 0x400  # put section raw data higher to avoid header overlap

    def rva(foff: int) -> int:
        return vrva + (foff - raw_ptr)

    # Export directory at file raw_ptr+0x80
    exp_off = raw_ptr + 0x80  # 0x480
    pe[opt + 96 : opt + 104] = struct.pack("<II", rva(exp_off), 0x100)

    sec = opt + 0xE0
    pe[sec : sec + 8] = b".text\x00\x00\x00"
    pe[sec + 8 : sec + 24] = struct.pack("<IIII", 0x400, vrva, 0x400, raw_ptr)
    pe[sec + 36 : sec + 40] = struct.pack("<I", 0x60000020)

    # Names and tables inside section raw region
    dll_off = raw_ptr + 0x100
    n1_off = raw_ptr + 0x110
    n2_off = raw_ptr + 0x120
    pe[dll_off : dll_off + 11] = b"sample.dll\x00"
    pe[n1_off : n1_off + 11] = b"MyExportFn\x00"
    pe[n2_off : n2_off + 14] = b"AnotherExport\x00"

    aof_off = raw_ptr + 0x140
    aon_off = raw_ptr + 0x150
    aoo_off = raw_ptr + 0x160
    pe[aof_off : aof_off + 8] = struct.pack("<II", 0x1100, 0x1110)
    pe[aon_off : aon_off + 8] = struct.pack("<II", rva(n1_off), rva(n2_off))
    pe[aoo_off : aoo_off + 4] = struct.pack("<HH", 0, 1)

    # IMAGE_EXPORT_DIRECTORY — pack as contiguous bytes (avoid pack_into edge cases)
    exp_blob = struct.pack(
        "<IIHHIIIIIII",
        0,
        0,
        0,
        0,
        rva(dll_off),
        1,
        2,
        2,
        rva(aof_off),
        rva(aon_off),
        rva(aoo_off),
    )
    assert len(exp_blob) == 40
    pe[exp_off : exp_off + 40] = exp_blob
    # Must match slice length exactly — mismatched bytearray slice assignment resizes
    # and shifts all subsequent offsets (breaking export RVA mapping).
    marker = b"IsDebuggerPresent\x00AES\x00"
    pe[raw_ptr : raw_ptr + len(marker)] = marker
    return bytes(pe)


def test_parse_macho_true_exports_not_imports_on_ls():
    """N_SECT|N_EXT = exports; N_UNDF|N_EXT = imports — must not mix."""
    ls = Path("/bin/ls")
    if not ls.is_file():
        pytest.skip("no /bin/ls")
    m = parse_macho_header(ls.read_bytes())
    exports = m.get("exports") or []
    undefined = m.get("undefined") or m.get("imports") or []
    assert exports, "expected at least one true export"
    # Typical MH_EXECUTE exports only the mach header symbol
    blob = "\n".join(exports)
    assert "__mh_execute_header" in blob or any(
        not s.startswith("_") or s == "__mh_execute_header" for s in exports
    )
    assert "__mh_execute_header" in exports or any("mh_execute" in s for s in exports)
    # Common libc imports must NOT appear as exports
    for imp in ("_printf", "_malloc", "_exit", "___error"):
        assert imp not in exports, f"{imp} is an import (N_UNDF), not export"
    assert undefined, "expected undefined external imports"
    assert any(x in undefined for x in ("_printf", "_malloc", "_exit", "___error", "_abort"))
    # true export set is small vs former bug (~90 imports labeled exports)
    assert len(exports) < 20
    assert len(undefined) > len(exports)


def test_parse_pe_named_exports():
    pe = parse_pe(_minimal_pe_with_exports())
    assert pe.get("format") == "pe"
    exports = pe.get("exports") or []
    assert "MyExportFn" in exports
    assert "AnotherExport" in exports


@pytest.mark.asyncio
async def test_analyze_binary_deep_fields_pe_and_ls(tmp_path: Path):
    pe_path = tmp_path / "deep.exe"
    pe_path.write_bytes(_minimal_pe_with_exports())
    pe_rep = await analyze_binary(pe_path, platform=Platform.WINDOWS)
    assert pe_rep["ok"]
    assert pe_rep["sections"]
    assert pe_rep["summary"].get("section_or_segment_count", 0) >= 1
    assert pe_rep.get("findings") is not None
    assert pe_rep["summary"].get("finding_count", 0) >= 1 or pe_rep.get("crypto_hints")
    # named PE exports from real export directory
    assert "MyExportFn" in (pe_rep.get("exports") or [])
    assert pe_rep["summary"].get("export_count", 0) >= 2

    ls = Path("/bin/ls")
    if ls.is_file():
        mrep = await analyze_binary(ls, platform=Platform.MACOS)
        assert mrep["ok"]
        macho = mrep.get("macho") or {}
        segs = macho.get("segments") or mrep.get("segments") or []
        assert segs, "expected Mach-O segments on /bin/ls"
        assert any(s.get("name", "").startswith("__") for s in segs)
        exports = mrep.get("exports") or macho.get("exports") or []
        assert "__mh_execute_header" in exports
        assert "_printf" not in exports
        assert "_malloc" not in exports
        assert mrep.get("export_count", len(exports)) < 20
        und = mrep.get("undefined_symbols") or macho.get("undefined") or []
        assert und and ("_printf" in und or "_malloc" in und or "_exit" in und)


@pytest.mark.asyncio
async def test_ai_desktop_scripts_list_and_analyze_missing():
    r = await call_tool("desktop.scripts", {})
    assert r["ok"] is True
    assert len(r.get("scripts") or []) >= 5
    r2 = await call_tool("analyze", {"platform": "macos", "binary": "/no/such/binary"})
    assert r2["ok"] is False
    assert r2.get("error")
