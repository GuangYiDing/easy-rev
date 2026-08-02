"""Commercial-depth static analysis for PE / Mach-O / ELF binaries."""

from __future__ import annotations

import json
import math
import re
import shutil
import struct
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from easy_rev.core.paths import artifacts_dir
from easy_rev.core.platform import Platform

_PACKER_HINTS = re.compile(
    r"(UPX|VMProtect|Themida|Enigma|ASPack|PECompact|PELock|Obsidium|"
    r"\.vmp\d|WinLicense|Armadillo|Safengine|packer|ntdll\.unmap)",
    re.I,
)
_ANTI_DEBUG = re.compile(
    r"(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|"
    r"OutputDebugString|FindWindow.*Olly|NtSetInformationThread|"
    r"ptrace|P_TRACED|task_get_exception_ports|sysctl.*KERN_PROC|"
    r"anti.?debug|IsDebugger|CloseHandle.*0x)",
    re.I,
)
_CRYPTO_HINTS = re.compile(
    r"(AES|RSA|HMAC|SHA256|SHA-256|SHA1|SHA-1|CryptoAPI|BCrypt|"
    r"CryptEncrypt|CryptDecrypt|CommonCrypto|CCCrypt|CC_SHA|"
    r"libsodium|openssl|mbedtls|EVP_|SecKey|CNG|NCrypt)",
    re.I,
)
_NET_HINTS = re.compile(
    r"(WinHttp|WinINet|InternetOpen|URLDownload|WSAStartup|socket|"
    r"NSURLSession|CFNetwork|libcurl|curl_easy|HttpSendRequest|"
    r"https?://|wss?://)",
    re.I,
)
_INTERESTING_SUBSTR = (
    "http://",
    "https://",
    "api.",
    "token",
    "secret",
    "password",
    "license",
    "sign",
    "aes",
    "rsa",
    ".dll",
    ".dylib",
    "bundle",
    "Bearer",
    "oauth",
    "jwt",
    "certificate",
    "pinning",
)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 4)


def _file_magic(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"size": path.stat().st_size, "format": "unknown"}
    head = path.read_bytes()[:8]
    if head[:2] == b"MZ":
        out["format"] = "pe"
    elif head[:4] in {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"}:
        out["format"] = "macho"
    elif head[:4] == b"\xca\xfe\xba\xbe":
        out["format"] = "macho_fat"
    elif head[:4] == b"\x7fELF":
        out["format"] = "elf"
    if shutil.which("file"):
        try:
            r = subprocess.run(
                ["file", "-b", str(path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            out["file_cmd"] = (r.stdout or "").strip()
        except Exception:  # noqa: BLE001
            pass
    return out


def extract_strings(
    data: bytes,
    *,
    min_len: int = 6,
    limit: int = 8000,
) -> list[str]:
    """Extract ASCII + UTF-16LE strings from raw bytes (pure, testable)."""
    found: list[str] = []
    pat = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    found.extend(m.group().decode("ascii", errors="ignore") for m in pat.finditer(data))
    pat16 = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    for m in pat16.finditer(data):
        try:
            found.append(m.group().decode("utf-16le", errors="ignore"))
        except Exception:  # noqa: BLE001
            continue
    seen: set[str] = set()
    uniq: list[str] = []
    for s in found:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
        if len(uniq) >= limit:
            break
    return uniq


def parse_pe(data: bytes) -> dict[str, Any]:
    """Parse PE headers, sections (with entropy), and import DLLs without pefile."""
    result: dict[str, Any] = {
        "format": "pe",
        "sections": [],
        "imports": [],
        "import_dlls": [],
        "machine": None,
        "characteristics": None,
        "subsystem": None,
        "is_dll": False,
        "is_64bit": False,
        "error": None,
    }
    try:
        if data[:2] != b"MZ":
            result["error"] = "not_mz"
            return result
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            result["error"] = "bad_pe_sig"
            return result
        coff = e_lfanew + 4
        machine, num_sections = struct.unpack_from("<HH", data, coff)
        size_opt = struct.unpack_from("<H", data, coff + 16)[0]
        characteristics = struct.unpack_from("<H", data, coff + 18)[0]
        result["machine"] = hex(machine)
        result["characteristics"] = hex(characteristics)
        result["is_dll"] = bool(characteristics & 0x2000)
        result["is_64bit"] = machine in {0x8664, 0xAA64}

        opt_off = coff + 20
        magic_opt = struct.unpack_from("<H", data, opt_off)[0] if size_opt >= 2 else 0
        pe32plus = magic_opt == 0x20B
        result["pe32plus"] = pe32plus
        if size_opt >= 70:
            # Subsystem at +68 for both PE32 and PE32+
            result["subsystem"] = struct.unpack_from("<H", data, opt_off + 68)[0]

        # Data directories: PE32 at +96, PE32+ at +112
        dd_off = opt_off + (112 if pe32plus else 96)
        import_rva = import_size = 0
        if size_opt >= (pe32plus and 128 or 104) and dd_off + 8 <= len(data):
            # Import directory is index 1
            import_rva, import_size = struct.unpack_from("<II", data, dd_off + 8)

        sec_off = opt_off + size_opt
        sections: list[dict[str, Any]] = []
        rva_map: list[tuple[int, int, int]] = []  # rva, vsize, raw_ptr

        for i in range(min(num_sections, 96)):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            name = data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", "ignore")
            # IMAGE_SECTION_HEADER after name: VirtualSize, VirtualAddress, SizeOfRawData,
            # PointerToRawData, PointerToRelocations, PointerToLinenumbers,
            # NumberOfRelocations, NumberOfLinenumbers, Characteristics
            vsize, vrva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            chunk = b""
            if raw_ptr and raw_size and raw_ptr < len(data):
                end = min(len(data), raw_ptr + min(raw_size, 256_000))
                chunk = data[raw_ptr:end]
            ent = _shannon_entropy(chunk) if chunk else 0.0
            sec = {
                "name": name,
                "virtual_size": vsize,
                "virtual_address": hex(vrva),
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "characteristics": hex(chars),
                "entropy": ent,
                "high_entropy": ent >= 7.0,
                "executable": bool(chars & 0x20000000),
                "writable": bool(chars & 0x80000000),
            }
            sections.append(sec)
            rva_map.append((vrva, max(vsize, raw_size), raw_ptr))

        result["sections"] = sections

        def rva_to_off(rva: int) -> int | None:
            for vrva, vsz, raw in rva_map:
                if vrva <= rva < vrva + max(vsz, 1):
                    return raw + (rva - vrva)
            return None

        # Import table walk
        dlls: list[str] = []
        imports: list[dict[str, Any]] = []
        if import_rva:
            table_off = rva_to_off(import_rva)
            if table_off is not None:
                for di in range(256):
                    ent_off = table_off + di * 20
                    if ent_off + 20 > len(data):
                        break
                    oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, ent_off)
                    if oft == 0 and name_rva == 0 and ft == 0:
                        break
                    name_off = rva_to_off(name_rva)
                    if name_off is None or name_off >= len(data):
                        continue
                    end = data.find(b"\x00", name_off, name_off + 260)
                    if end < 0:
                        continue
                    dll = data[name_off:end].decode("ascii", "ignore")
                    if not dll:
                        continue
                    dlls.append(dll)
                    # sample a few thunk names
                    funcs: list[str] = []
                    thunk_rva = oft or ft
                    thunk_off = rva_to_off(thunk_rva) if thunk_rva else None
                    if thunk_off is not None:
                        step = 8 if pe32plus else 4
                        for ti in range(40):
                            to = thunk_off + ti * step
                            if to + step > len(data):
                                break
                            val = (
                                struct.unpack_from("<Q", data, to)[0]
                                if pe32plus
                                else struct.unpack_from("<I", data, to)[0]
                            )
                            if val == 0:
                                break
                            # ordinal bit
                            if pe32plus and (val & (1 << 63)):
                                funcs.append(f"ord_{val & 0xFFFF}")
                                continue
                            if not pe32plus and (val & 0x80000000):
                                funcs.append(f"ord_{val & 0xFFFF}")
                                continue
                            hint_rva = val & 0x7FFFFFFF
                            ho = rva_to_off(hint_rva)
                            if ho is None or ho + 2 >= len(data):
                                continue
                            fn_end = data.find(b"\x00", ho + 2, ho + 2 + 256)
                            if fn_end < 0:
                                continue
                            funcs.append(data[ho + 2 : fn_end].decode("ascii", "ignore"))
                    imports.append({"dll": dll, "functions": funcs[:40]})

        result["import_dlls"] = dlls
        result["imports"] = imports
        result["import_count"] = sum(len(i["functions"]) for i in imports)

        # Export directory — data dir index 0
        export_rva = export_size = 0
        if size_opt >= (pe32plus and 128 or 104) and dd_off + 8 <= len(data):
            export_rva, export_size = struct.unpack_from("<II", data, dd_off)
        exports: list[str] = []
        if export_rva:
            exp_off = rva_to_off(export_rva)
            if exp_off is not None and exp_off + 40 <= len(data):
                (
                    _chars,
                    _ts,
                    _maj,
                    _min,
                    name_rva_exp,
                    ordinal_base,
                    n_funcs,
                    n_names,
                    _aof,
                    aon,
                    _aoo,
                ) = struct.unpack_from("<IIHHIIIIIII", data, exp_off)
                # AddressOfNames RVA at offset +32 in IMAGE_EXPORT_DIRECTORY
                aon_off = rva_to_off(aon) if aon else None
                if aon_off is not None and n_names:
                    for ni in range(min(n_names, 200)):
                        nr_off = aon_off + ni * 4
                        if nr_off + 4 > len(data):
                            break
                        name_rva_i = struct.unpack_from("<I", data, nr_off)[0]
                        no = rva_to_off(name_rva_i)
                        if no is None:
                            continue
                        end = data.find(b"\x00", no, no + 256)
                        if end < 0:
                            continue
                        en = data[no:end].decode("ascii", "ignore")
                        if en:
                            exports.append(en)
        result["exports"] = exports
        result["export_count"] = len(exports)
        result["export_rva"] = hex(export_rva) if export_rva else None
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
    return result


def parse_elf(data: bytes) -> dict[str, Any]:
    """Minimal ELF header + program/section string table clues (for .so / Linux bins)."""
    out: dict[str, Any] = {
        "format": "elf",
        "class": None,
        "endian": None,
        "machine": None,
        "type": None,
        "sections": [],
        "needed": [],
        "exports_hint": [],
        "error": None,
    }
    try:
        if data[:4] != b"\x7fELF":
            out["error"] = "not_elf"
            return out
        ei_class = data[4]  # 1=32, 2=64
        ei_data = data[5]  # 1=LE, 2=BE
        out["class"] = {1: "ELF32", 2: "ELF64"}.get(ei_class, ei_class)
        endian = "<" if ei_data == 1 else ">"
        out["endian"] = "le" if ei_data == 1 else "be"
        is64 = ei_class == 2
        if is64:
            if len(data) < 64:
                out["error"] = "short_ehdr"
                return out
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
            e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 58)
        else:
            if len(data) < 52:
                out["error"] = "short_ehdr"
                return out
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
            e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 46)
        out["type"] = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, e_type)
        out["machine"] = {
            3: "i386",
            62: "x86_64",
            40: "arm",
            183: "aarch64",
        }.get(e_machine, hex(e_machine))
        out["is_64bit"] = is64

        # Section headers + shstrtab for names; dynamic needed via string scan fallback
        sections: list[dict[str, Any]] = []
        shstr: bytes = b""
        if e_shoff and e_shnum and e_shentsize:
            # load shstrtab first
            if e_shstrndx < e_shnum:
                sho = e_shoff + e_shstrndx * e_shentsize
                if is64 and sho + 64 <= len(data):
                    sh_offset = struct.unpack_from(endian + "Q", data, sho + 24)[0]
                    sh_size = struct.unpack_from(endian + "Q", data, sho + 32)[0]
                elif not is64 and sho + 40 <= len(data):
                    sh_offset = struct.unpack_from(endian + "I", data, sho + 16)[0]
                    sh_size = struct.unpack_from(endian + "I", data, sho + 20)[0]
                else:
                    sh_offset = sh_size = 0
                if sh_offset and sh_size and sh_offset + min(sh_size, 1_000_000) <= len(data):
                    shstr = data[sh_offset : sh_offset + min(sh_size, 1_000_000)]

            for i in range(min(e_shnum, 128)):
                sho = e_shoff + i * e_shentsize
                if is64:
                    if sho + 64 > len(data):
                        break
                    sh_name = struct.unpack_from(endian + "I", data, sho)[0]
                    sh_type = struct.unpack_from(endian + "I", data, sho + 4)[0]
                    sh_flags = struct.unpack_from(endian + "Q", data, sho + 8)[0]
                    sh_addr = struct.unpack_from(endian + "Q", data, sho + 16)[0]
                    sh_offset = struct.unpack_from(endian + "Q", data, sho + 24)[0]
                    sh_size = struct.unpack_from(endian + "Q", data, sho + 32)[0]
                else:
                    if sho + 40 > len(data):
                        break
                    sh_name = struct.unpack_from(endian + "I", data, sho)[0]
                    sh_type = struct.unpack_from(endian + "I", data, sho + 4)[0]
                    sh_flags = struct.unpack_from(endian + "I", data, sho + 8)[0]
                    sh_addr = struct.unpack_from(endian + "I", data, sho + 12)[0]
                    sh_offset = struct.unpack_from(endian + "I", data, sho + 16)[0]
                    sh_size = struct.unpack_from(endian + "I", data, sho + 20)[0]
                name = ""
                if shstr and sh_name < len(shstr):
                    name = shstr[sh_name:].split(b"\x00", 1)[0].decode("ascii", "ignore")
                chunk = b""
                if sh_offset and sh_size and sh_offset < len(data):
                    end = min(len(data), sh_offset + min(int(sh_size), 64_000))
                    chunk = data[sh_offset:end]
                ent = _shannon_entropy(chunk) if chunk else 0.0
                sections.append(
                    {
                        "name": name or f"sec_{i}",
                        "type": sh_type,
                        "flags": hex(sh_flags),
                        "addr": hex(sh_addr),
                        "size": int(sh_size),
                        "entropy": ent,
                        "high_entropy": ent >= 7.0,
                        "executable": bool(sh_flags & 0x4),
                    }
                )
        out["sections"] = sections

        # DT_NEEDED via scanning .dynamic for string table pointers is complex;
        # also harvest lib*.so from readable strings in file (reliable enough for RE).
        needed: list[str] = []
        for m in re.finditer(rb"lib[\w.+-]+\.so(?:\.\d+)*", data[: min(len(data), 2_000_000)]):
            s = m.group().decode("ascii", "ignore")
            if s not in needed:
                needed.append(s)
            if len(needed) >= 40:
                break
        out["needed"] = needed

        # Export-ish: global function-like names near .dynstr
        exports_hint: list[str] = []
        for m in re.finditer(
            rb"(?:Java_|JNI_|SSL_|AES_|HMAC_|EVP_|curl_|okhttp)[\w]{2,40}",
            data[: min(len(data), 2_000_000)],
        ):
            s = m.group().decode("ascii", "ignore")
            if s not in exports_hint:
                exports_hint.append(s)
            if len(exports_hint) >= 60:
                break
        out["exports_hint"] = exports_hint
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Return (value, new_offset)."""
    result = 0
    shift = 0
    pos = offset
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 63:
            break
    return result, pos


def parse_export_trie(data: bytes, *, limit: int = 500) -> list[str]:
    """Walk a dyld export trie and return exported symbol names.

    Spec (simplified): each node is
      ULEB128 terminal_size
      [if terminal_size>0: ULEB128 flags, ULEB128 address | reexport…]
      u8 edge_count
      for each edge: C-string label + ULEB128 child_offset (from trie start)
    """
    if not data:
        return []
    names: list[str] = []

    def walk(node_off: int, prefix: str, depth: int = 0) -> None:
        if len(names) >= limit or depth > 64:
            return
        if node_off < 0 or node_off >= len(data):
            return
        try:
            terminal_size, pos = _read_uleb128(data, node_off)
        except Exception:  # noqa: BLE001
            return
        if terminal_size:
            # skip terminal info
            end = pos + terminal_size
            if end > len(data):
                return
            if prefix and len(names) < limit:
                # skip pure re-exports with empty flags handling — still a name
                names.append(prefix)
            pos = end
        if pos >= len(data):
            return
        edge_count = data[pos]
        pos += 1
        for _ in range(edge_count):
            if pos >= len(data):
                break
            # null-terminated edge label
            z = data.find(b"\x00", pos, min(len(data), pos + 512))
            if z < 0:
                break
            try:
                label = data[pos:z].decode("utf-8", "ignore")
            except Exception:  # noqa: BLE001
                label = ""
            pos = z + 1
            child_off, pos = _read_uleb128(data, pos)
            walk(child_off, prefix + label, depth + 1)

    walk(0, "")
    # stable unique
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def parse_macho_header(data: bytes) -> dict[str, Any]:
    """Best-effort single-arch Mach-O load command summary (no external deps)."""
    out: dict[str, Any] = {
        "format": "macho",
        "cpu": None,
        "filetype": None,
        "ncmds": 0,
        "dylibs": [],
        "rpaths": [],
        "segments": [],
        "symbols": [],
        "exports": [],
        "exports_trie": [],
        "undefined": [],
        "imports": [],
        "error": None,
    }
    try:
        if len(data) < 32:
            out["error"] = "too_small"
            return out
        # Fat headers are big-endian (0xCAFEBABE). Thin Mach-O may be LE or BE.
        magic_be = struct.unpack_from(">I", data, 0)[0]
        magic_le = struct.unpack_from("<I", data, 0)[0]
        if magic_be == 0xCAFEBABE or magic_le == 0xCAFEBABE:
            out["format"] = "macho_fat"
            # fat_header always big-endian on disk
            nfat = struct.unpack_from(">I", data, 4)[0]
            out["nfat_arch"] = nfat
            # Enumerate fat_arch entries; prefer host-matching CPU when possible
            import platform as _plat

            prefer_arm64 = _plat.machine().lower() in {"arm64", "aarch64"}
            slices: list[dict[str, Any]] = []
            best: tuple[int, int, int] | None = None  # score, offset, size
            for i in range(min(nfat, 16)):
                base = 8 + i * 20
                if base + 20 > len(data):
                    break
                cputype, _sub, offset, size, _align = struct.unpack_from(">IIIII", data, base)
                slices.append(
                    {"cputype": cputype, "offset": offset, "size": size}
                )
                score = 0
                if prefer_arm64 and cputype == 0x0100000C:
                    score = 3
                elif not prefer_arm64 and cputype == 0x01000007:
                    score = 3
                elif cputype in {0x01000007, 0x0100000C}:
                    score = 1
                if best is None or score > best[0]:
                    best = (score, offset, size)
            out["fat_slices"] = slices
            if best is not None:
                _score, offset, size = best
                out["first_arch"] = {"offset": offset, "size": size}
                if 0 < offset < len(data):
                    end = offset + size if size else None
                    inner = parse_macho_header(data[offset:end])
                    out.update(
                        {
                            k: v
                            for k, v in inner.items()
                            if k not in {"format", "error"} or v
                        }
                    )
                    out["format"] = "macho_fat"
                    out["nfat_arch"] = nfat
                    out["slice_cpu_name"] = inner.get("cpu_name")
                    out["slice_dylibs"] = list(inner.get("dylibs") or [])
                    out["dylibs"] = list(inner.get("dylibs") or [])
                    out["rpaths"] = list(inner.get("rpaths") or [])
                    out["segments"] = list(inner.get("segments") or [])
                    out["symbols"] = list(inner.get("symbols") or [])
                    out["exports"] = list(inner.get("exports") or [])
                    out["exports_trie"] = list(inner.get("exports_trie") or [])
                    out["undefined"] = list(inner.get("undefined") or [])
                    out["imports"] = list(inner.get("imports") or [])
                    out["export_source"] = inner.get("export_source")
                    out["export_trie_meta"] = inner.get("export_trie_meta")
                    return out
            return out
        magic = magic_le

        le = magic in {0xFEEDFACF, 0xFEEDFACE}
        be = magic in {0xCFFAEDFE, 0xCEFAEDFE}
        if not (le or be):
            out["error"] = f"bad_magic_{hex(magic)}"
            return out
        endian = "<" if le else ">"
        is64 = magic in {0xFEEDFACF, 0xCFFAEDFE}
        # mach_header: 7×uint32 (28B); mach_header_64: 8×uint32 (32B, +reserved)
        # Wrong size shifts every load-command and yields empty dylibs.
        hdr_fmt = endian + ("IIIIIIII" if is64 else "IIIIIII")
        hdr_size = 32 if is64 else 28
        assert struct.calcsize(hdr_fmt) == hdr_size
        if len(data) < hdr_size:
            out["error"] = "short_header"
            return out
        fields = struct.unpack_from(hdr_fmt, data, 0)
        # skip magic
        cputype, _cpusub, filetype, ncmds, sizeofcmds = fields[1:6]
        out["cpu"] = cputype
        out["filetype"] = filetype
        out["ncmds"] = ncmds
        out["is_64bit"] = is64
        out["hdr_size"] = hdr_size

        # CPU types
        cpu_map = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64"}
        out["cpu_name"] = cpu_map.get(cputype & 0xFF, cpu_map.get(cputype, hex(cputype)))
        # ABI64 bit in cputype
        if cputype in {0x01000007, 0x0100000C} or (cputype & 0x01000000):
            out["cpu_name"] = {
                0x01000007: "x86_64",
                0x0100000C: "arm64",
            }.get(cputype, out["cpu_name"])

        # LC_LOAD_DYLIB=0x0C, LC_LOAD_WEAK_DYLIB=0x18, LC_REEXPORT_DYLIB=0x1F,
        # LC_LOAD_UPWARD_DYLIB=0x23.  Note: 0x19 is LC_SEGMENT_64 — never a dylib.
        _DYLIB_CMDS = frozenset({0x0C, 0x18, 0x1F, 0x23})
        _LC_RPATH = 0x1C
        _LC_SEGMENT = 0x1
        _LC_SEGMENT_64 = 0x19
        _LC_SYMTAB = 0x2
        _LC_DYSYMTAB = 0xB
        # LC_DYLD_INFO=0x22, LC_DYLD_INFO_ONLY=0x80000022, LC_DYLD_EXPORTS_TRIE=0x80000033
        _LC_DYLD_INFO = 0x22
        _LC_DYLD_EXPORTS_TRIE = 0x33  # base without REQ_DYLD bit

        off = hdr_size
        dylibs: list[str] = []
        rpaths: list[str] = []
        segments: list[dict[str, Any]] = []
        symtab_cmd: dict[str, int] | None = None
        export_blob_off: int | None = None
        export_blob_size: int = 0
        export_blob_kind: str | None = None
        for _ in range(min(ncmds, 512)):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
            if cmdsize < 8 or off + cmdsize > len(data):
                break
            cmd_base = cmd & 0x7FFFFFFF
            if cmd_base in _DYLIB_CMDS:
                # dylib_command: cmd, cmdsize, name.offset (relative to start of LC), ...
                if cmdsize >= 24:
                    no = struct.unpack_from(endian + "I", data, off + 8)[0]
                    if 0 < no < cmdsize:
                        raw = data[off + no : off + cmdsize]
                        name = raw.split(b"\x00", 1)[0].decode("utf-8", "ignore")
                        if name:
                            dylibs.append(name)
            elif cmd_base == _LC_RPATH:
                if cmdsize >= 12:
                    no = struct.unpack_from(endian + "I", data, off + 8)[0]
                    if 0 < no < cmdsize:
                        raw = data[off + no : off + cmdsize]
                        name = raw.split(b"\x00", 1)[0].decode("utf-8", "ignore")
                        if name:
                            rpaths.append(name)
            elif cmd_base in {_LC_SEGMENT, _LC_SEGMENT_64}:
                # segment_command(_64): segname at +8 (16 bytes)
                if cmdsize >= 24:
                    segname = data[off + 8 : off + 24].split(b"\x00", 1)[0].decode(
                        "ascii", "ignore"
                    )
                    if cmd_base == _LC_SEGMENT_64 and cmdsize >= 72:
                        vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                            endian + "QQQQ", data, off + 24
                        )
                        nsects = struct.unpack_from(endian + "I", data, off + 64)[0]
                    elif cmd_base == _LC_SEGMENT and cmdsize >= 56:
                        vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                            endian + "IIII", data, off + 24
                        )
                        nsects = struct.unpack_from(endian + "I", data, off + 48)[0]
                    else:
                        vmaddr = vmsize = fileoff = filesize = nsects = 0
                    chunk = b""
                    if fileoff and filesize and fileoff < len(data):
                        end = min(len(data), int(fileoff) + min(int(filesize), 128_000))
                        chunk = data[int(fileoff) : end]
                    ent = _shannon_entropy(chunk) if chunk else 0.0
                    segments.append(
                        {
                            "name": segname,
                            "vmaddr": hex(vmaddr),
                            "vmsize": int(vmsize),
                            "fileoff": int(fileoff),
                            "filesize": int(filesize),
                            "nsects": int(nsects),
                            "entropy": ent,
                            "high_entropy": ent >= 7.0,
                        }
                    )
            elif cmd_base == _LC_SYMTAB and cmdsize >= 24:
                symoff, nsyms, stroff, strsize = struct.unpack_from(
                    endian + "IIII", data, off + 8
                )
                symtab_cmd = {
                    "symoff": symoff,
                    "nsyms": nsyms,
                    "stroff": stroff,
                    "strsize": strsize,
                }
            elif cmd_base == _LC_DYLD_INFO and cmdsize >= 48:
                # dyld_info_command: 10×u32 after cmd/cmdsize → export_off/size at end
                # cmd,cmdsize, rebase_off,size, bind_off,size, weak_*, lazy_*, export_off,size
                fields = struct.unpack_from(endian + "IIIIIIIIIIII", data, off)
                # indices: 0=cmd 1=cmdsize 10=export_off 11=export_size
                e_off, e_sz = int(fields[10]), int(fields[11])
                if e_sz and e_off:
                    export_blob_off, export_blob_size = e_off, e_sz
                    export_blob_kind = "dyld_info"
            elif cmd_base == _LC_DYLD_EXPORTS_TRIE and cmdsize >= 16:
                # linkedit_data_command: dataoff, datasize
                e_off, e_sz = struct.unpack_from(endian + "II", data, off + 8)
                if e_sz and e_off:
                    export_blob_off, export_blob_size = int(e_off), int(e_sz)
                    export_blob_kind = "exports_trie"
            off += cmdsize

        out["dylibs"] = dylibs
        out["rpaths"] = rpaths
        out["segments"] = segments

        # Prefer export trie (authoritative for dyld; works when symtab is stripped)
        trie_exports: list[str] = []
        if export_blob_off is not None and export_blob_size > 0:
            end = min(len(data), export_blob_off + export_blob_size)
            if 0 <= export_blob_off < len(data):
                trie_exports = parse_export_trie(
                    data[export_blob_off:end], limit=500
                )
        out["exports_trie"] = trie_exports
        out["export_trie_meta"] = {
            "kind": export_blob_kind,
            "offset": export_blob_off,
            "size": export_blob_size,
            "count": len(trie_exports),
        }

        symbols: list[str] = []
        exports: list[str] = []
        undefined: list[str] = []  # N_UNDF|N_EXT — imported external symbols
        if symtab_cmd:
            stroff = symtab_cmd["stroff"]
            strsize = min(symtab_cmd["strsize"], 2_000_000)
            symoff = symtab_cmd["symoff"]
            nsyms = min(symtab_cmd["nsyms"], 50_000)
            strtab = b""
            if stroff and strsize and stroff < len(data):
                strtab = data[stroff : stroff + min(strsize, len(data) - stroff)]
            # nlist_64: 16 bytes (strx u32, type u8, sect u8, desc u16, value u64)
            # nlist: 12 bytes
            # n_type: N_STAB=0xe0, N_PEXT=0x10, N_TYPE=0x0e, N_EXT=0x01
            # N_TYPE values: N_UNDF=0x0, N_ABS=0x2, N_SECT=0xe, N_PBUD=0xc, N_INDR=0xa
            _N_STAB = 0xE0
            _N_TYPE = 0x0E
            _N_EXT = 0x01
            _N_UNDF = 0x0
            _N_SECT = 0x0E
            entry_size = 16 if is64 else 12
            for i in range(nsyms):
                so = symoff + i * entry_size
                if so + entry_size > len(data):
                    break
                strx = struct.unpack_from(endian + "I", data, so)[0]
                n_type = data[so + 4]
                if not strtab or strx >= len(strtab):
                    continue
                # skip debug stab entries
                if n_type & _N_STAB:
                    continue
                name = strtab[strx:].split(b"\x00", 1)[0].decode("utf-8", "ignore")
                if not name or (name.startswith("l") and len(name) < 3):
                    continue
                type_bits = n_type & _N_TYPE
                is_ext = bool(n_type & _N_EXT)
                if len(symbols) < 250 and (is_ext or name.startswith("_") or "." in name):
                    symbols.append(name)
                # True defined exports: defined in a section + external
                if is_ext and type_bits == _N_SECT and len(exports) < 120:
                    exports.append(name)
                # Undefined externals are imports, not exports
                elif is_ext and type_bits == _N_UNDF and len(undefined) < 200:
                    undefined.append(name)
        # Merge: trie is preferred when non-empty; keep symtab N_SECT exports as fallback
        if trie_exports:
            # union preserving trie-first order
            merged = list(trie_exports)
            seen = set(merged)
            for n in exports:
                if n not in seen:
                    merged.append(n)
                    seen.add(n)
            exports = merged[:200]
            out["export_source"] = export_blob_kind or "exports_trie"
        else:
            out["export_source"] = "symtab" if exports else None
        out["symbols"] = symbols
        out["exports"] = exports
        out["undefined"] = undefined
        out["imports"] = undefined  # alias for RE consumers expecting "imports"
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


def _macho_otool_libs(path: Path) -> list[str]:
    if not shutil.which("otool"):
        return []
    try:
        r = subprocess.run(
            ["otool", "-L", str(path)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        lines = []
        for line in (r.stdout or "").splitlines()[1:]:
            line = line.strip().split(" (")[0].strip()
            if line:
                lines.append(line)
        return lines
    except Exception:  # noqa: BLE001
        return []


def _classify_findings(
    strings: list[str],
    pe: dict[str, Any] | None,
    macho: dict[str, Any] | None,
    elf: dict[str, Any] | None = None,
) -> dict[str, Any]:
    blob = "\n".join(strings)
    packing_str = bool(_PACKER_HINTS.search(blob))
    high_ent_secs = [
        s["name"] for s in (pe or {}).get("sections") or [] if s.get("high_entropy")
    ]
    high_ent_segs = [
        s["name"] for s in (macho or {}).get("segments") or [] if s.get("high_entropy")
    ]
    high_ent_elf = [
        s["name"] for s in (elf or {}).get("sections") or [] if s.get("high_entropy")
    ]
    packing = packing_str or bool(high_ent_secs or high_ent_segs) or any(
        (s.get("name") or "").lower().startswith("upx")
        for s in (pe or {}).get("sections") or []
    )
    anti_debug = bool(_ANTI_DEBUG.search(blob))
    crypto = sorted({m.group(0) for m in _CRYPTO_HINTS.finditer(blob)})[:40]
    net = sorted({m.group(0) for m in _NET_HINTS.finditer(blob)})[:40]

    # Import-based signals for PE
    import_dlls = [d.lower() for d in (pe or {}).get("import_dlls") or []]
    if any(x in import_dlls for x in ("bcrypt.dll", "ncrypt.dll", "advapi32.dll")):
        crypto = list(dict.fromkeys(crypto + ["CryptoAPI/BCrypt(import)"]))
    if any(x in import_dlls for x in ("winhttp.dll", "wininet.dll", "ws2_32.dll")):
        net = list(dict.fromkeys(net + ["WinHTTP/WinINet/Winsock(import)"]))

    # Mach-O dylib signals
    dylibs_l = "\n".join((macho or {}).get("dylibs") or []).lower()
    if "security" in dylibs_l or "commoncrypto" in dylibs_l:
        crypto = list(dict.fromkeys(crypto + ["Security/CommonCrypto(dylib)"]))
    if "cfnetwork" in dylibs_l or "network" in dylibs_l:
        net = list(dict.fromkeys(net + ["CFNetwork(dylib)"]))

    interesting = [
        s
        for s in strings
        if any(k.lower() in s.lower() for k in _INTERESTING_SUBSTR)
    ][:100]

    urls = sorted(
        {
            s
            for s in strings
            if re.search(r"https?://[^\s\"'<>]{6,}", s)
        }
    )[:60]
    # extract clean URLs
    clean_urls: list[str] = []
    for s in urls:
        for m in re.finditer(r"https?://[^\s\"'<>]{6,200}", s):
            clean_urls.append(m.group(0).rstrip(".,);"))
    clean_urls = list(dict.fromkeys(clean_urls))[:60]

    findings_list: list[dict[str, Any]] = []
    if packing:
        findings_list.append({"kind": "packing", "detail": "high_entropy_or_packer_string"})
    if anti_debug:
        findings_list.append({"kind": "anti_debug", "detail": "debugger_api_or_string"})
    if crypto:
        findings_list.append({"kind": "crypto", "detail": crypto[:8]})
    if net:
        findings_list.append({"kind": "network", "detail": net[:8]})
    if clean_urls:
        findings_list.append({"kind": "urls", "count": len(clean_urls)})

    return {
        "packing_suspected": packing,
        "packing_signals": {
            "string_match": packing_str,
            "high_entropy_sections": high_ent_secs,
            "high_entropy_segments": high_ent_segs,
            "high_entropy_elf_sections": high_ent_elf,
        },
        "anti_debug": anti_debug,
        "crypto_hints": crypto,
        "network_hints": net,
        "interesting_strings": interesting,
        "urls": clean_urls,
        "findings": findings_list,
    }


async def analyze_binary(
    binary: str | Path,
    *,
    platform: Platform = Platform.MACOS,
) -> dict[str, Any]:
    path = Path(binary).expanduser().resolve()
    if not path.is_file():
        return {
            "ok": False,
            "error": f"binary not found: {path}",
            "artifact_paths": [],
        }

    data = path.read_bytes()
    magic = _file_magic(path)
    # recompute size from data
    magic["size"] = len(data)
    strings = extract_strings(data)

    pe: dict[str, Any] | None = None
    macho: dict[str, Any] | None = None
    elf: dict[str, Any] | None = None
    imports_or_libs: list[str] = []
    sections: list[Any] = []
    exports: list[str] = []
    segments: list[Any] = []

    if magic.get("format") == "pe":
        pe = parse_pe(data)
        imports_or_libs = pe.get("import_dlls") or []
        sections = pe.get("sections") or []
        exports = list(pe.get("exports") or [])
    elif magic.get("format") in {"macho", "macho_fat"}:
        macho = parse_macho_header(data)
        otool_libs = _macho_otool_libs(path)
        imports_or_libs = otool_libs or (macho.get("dylibs") or [])
        segments = list(macho.get("segments") or [])
        sections = segments  # expose segments under sections for uniform consumers
        # Only true N_SECT|N_EXT exports — never fall back to symbols (mixes imports)
        exports = list(macho.get("exports") or [])[:120]
    elif magic.get("format") == "elf":
        elf = parse_elf(data)
        imports_or_libs = list(elf.get("needed") or [])
        sections = list(elf.get("sections") or [])
        exports = list(elf.get("exports_hint") or [])

    findings = _classify_findings(strings, pe, macho, elf)

    out_dir = artifacts_dir() / "desktop" / path.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "ok": True,
        "binary": str(path),
        "platform": platform.value,
        "magic": magic,
        "packing_suspected": findings["packing_suspected"],
        "packing_signals": findings["packing_signals"],
        "anti_debug": findings["anti_debug"],
        "crypto_hints": findings["crypto_hints"],
        "network_hints": findings["network_hints"],
        "imports_or_libs": imports_or_libs[:80],
        "exports": exports[:120],
        "export_count": len(exports),
        "export_source": (macho or {}).get("export_source") or ("pe" if pe else None),
        "exports_trie": list((macho or {}).get("exports_trie") or [])[:120],
        "undefined_symbols": list((macho or {}).get("undefined") or [])[:120],
        "sections": sections,
        "segments": segments,
        "pe": pe,
        "macho": macho,
        "elf": elf,
        "interesting_strings": findings["interesting_strings"],
        "urls": findings["urls"],
        "findings": findings.get("findings") or [],
        "string_count": len(strings),
    }
    report_path = out_dir / "static_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    strings_path = out_dir / "strings.txt"
    strings_path.write_text("\n".join(strings[:4000]), encoding="utf-8")

    report["artifact_paths"] = [str(report_path), str(strings_path)]
    report["summary"] = {
        "format": magic.get("format"),
        "packing_suspected": findings["packing_suspected"],
        "anti_debug": findings["anti_debug"],
        "crypto_hint_count": len(findings["crypto_hints"]),
        "network_hint_count": len(findings["network_hints"]),
        "import_or_lib_count": len(imports_or_libs),
        "export_count": len(exports),
        "section_or_segment_count": len(sections),
        "url_count": len(findings["urls"]),
        "interesting_string_count": len(findings["interesting_strings"]),
        "finding_count": len(findings.get("findings") or []),
    }
    return report
