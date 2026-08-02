"""Commercial-depth static analysis for APK / IPA packages."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

from easy_rev.core.paths import artifacts_dir
from easy_rev.core.platform import Platform

_PKG_RE = re.compile(r'package="([^"]+)"')
_PERM_RE = re.compile(r'android\.permission\.([A-Z0-9_]+)')
_URL_RE = re.compile(rb"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{6,200}")
_PINNING = re.compile(
    r"(CertificatePinner|SSLPeerUnverified|TrustManagerImpl|OkHttpClient|"
    r"NetworkSecurityConfig|pin-set|NSPinnedDomains|TrustKit|"
    r"ssl.?pin|PublicKeyPin|X509TrustManager)",
    re.I,
)
_OBFUSCATION = re.compile(
    r"(classes\d+\.dex|allatori|dexguard|ijiami|bangcle|qihoo|legu|tencent\.bugly)",
    re.I,
)
_CRYPTO = re.compile(
    r"(javax\.crypto|Cipher\.getInstance|SecretKeySpec|Mac\.getInstance|"
    r"MessageDigest|AES/|RSA/|HmacSHA|CCCrypt|SecKey)",
    re.I,
)
_DOTTED_ID = re.compile(r"\b[a-zA-Z][\w]*(?:\.[a-zA-Z][\w]*){2,}\b")

# DEX / assets string classification buckets
_DEX_BUCKETS: dict[str, re.Pattern[str]] = {
    "crypto": re.compile(
        r"(javax\.crypto|Cipher|SecretKeySpec|Mac\.getInstance|MessageDigest|"
        r"AES/|RSA/|HmacSHA|PBKDF2|KeyGenerator|IvParameterSpec)",
        re.I,
    ),
    "network": re.compile(
        r"(OkHttp|HttpURLConnection|Retrofit|Volley|Socket|WebSocket|"
        r"URLConnection|Cronet|Interceptor)",
        re.I,
    ),
    "pinning": re.compile(
        r"(CertificatePinner|TrustManager|X509TrustManager|HostnameVerifier|"
        r"NetworkSecurityConfig|pin-set|PublicKeyPin)",
        re.I,
    ),
    "api_path": re.compile(
        r"(/api/|/v\d+/|/auth/|/oauth|/graphql|/register|/signup|/login)",
        re.I,
    ),
    "token": re.compile(
        r"(Bearer\s|access_token|refresh_token|Authorization|x-api-key|api_key)",
        re.I,
    ),
    "jni": re.compile(r"(System\.loadLibrary|JNI_OnLoad|native\s+\w+|Java_)", re.I),
    "webview": re.compile(r"(WebView|addJavascriptInterface|evaluateJavascript)", re.I),
    "storage": re.compile(
        r"(SharedPreferences|getSharedPreferences|SQLiteDatabase|Room\.|EncryptedSharedPreferences)",
        re.I,
    ),
}


def _readable_strings(data: bytes, min_len: int = 4) -> str:
    return "\n".join(
        m.group().decode("ascii", "ignore")
        for m in re.finditer(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)
    )


def classify_dex_strings(text: str, *, limit_per: int = 20) -> dict[str, Any]:
    """Bucket DEX/assets readable strings into crypto/network/api/token categories."""
    buckets: dict[str, list[str]] = {k: [] for k in _DEX_BUCKETS}
    lines = text.splitlines() if "\n" in text[:2000] else re.split(r"[\x00\n]", text)
    for line in lines:
        s = line.strip()
        if len(s) < 4 or len(s) > 300:
            continue
        for kind, pat in _DEX_BUCKETS.items():
            if len(buckets[kind]) >= limit_per:
                continue
            if pat.search(s):
                if s not in buckets[kind]:
                    buckets[kind].append(s[:200])
    counts = {k: len(v) for k, v in buckets.items() if v}
    return {
        "buckets": {k: v for k, v in buckets.items() if v},
        "counts": counts,
        "hot": sorted(counts, key=counts.get, reverse=True),  # type: ignore[arg-type]
    }


def parse_dex_string_ids(data: bytes, *, limit: int = 4000) -> dict[str, Any]:
    """Parse DEX header string_ids table (UTF-16LE MUTF-8 best-effort) without androguard.

    DEX format: magic 'dex\\n035\\0', string_ids_size @0x38, string_ids_off @0x3c (LE).
    Each string_id is a u32 offset into data section pointing at uleb128 length + MUTF-8.
    """
    out: dict[str, Any] = {
        "format": "dex",
        "string_count": 0,
        "strings": [],
        "error": None,
    }
    try:
        if len(data) < 0x70 or not data.startswith(b"dex\n"):
            # still allow synthetic non-header blobs used in tests
            out["error"] = "not_dex_header"
            strings = [
                m.group().decode("ascii", "ignore")
                for m in re.finditer(rb"[\x20-\x7e]{4,200}", data[: min(len(data), 500_000)])
            ]
            out["strings"] = strings[:limit]
            out["string_count"] = len(out["strings"])
            out["source"] = "raw_scan"
            return out

        import struct

        string_ids_size = struct.unpack_from("<I", data, 0x38)[0]
        string_ids_off = struct.unpack_from("<I", data, 0x3C)[0]
        out["string_ids_size"] = string_ids_size
        out["string_ids_off"] = string_ids_off
        strings: list[str] = []
        n = min(int(string_ids_size), limit)
        for i in range(n):
            off = string_ids_off + i * 4
            if off + 4 > len(data):
                break
            str_data_off = struct.unpack_from("<I", data, off)[0]
            if str_data_off >= len(data):
                continue
            # uleb128 length
            pos = str_data_off
            shift = 0
            length = 0
            while pos < len(data) and shift < 35:
                b = data[pos]
                pos += 1
                length |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            end = min(len(data), pos + min(length, 400))
            raw = data[pos:end]
            # MUTF-8 ≈ UTF-8 for ASCII-heavy Android strings
            try:
                s = raw.split(b"\x00", 1)[0].decode("utf-8", "ignore")
            except Exception:  # noqa: BLE001
                s = raw.decode("latin-1", "ignore")
            if 2 <= len(s) <= 300:
                strings.append(s)
        out["strings"] = strings
        out["string_count"] = len(strings)
        out["source"] = "string_ids"
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


def _decode_axml_string_pool(data: bytes, pool_pos: int, chunk_size: int, *, limit: int) -> list[str]:
    """Decode ResStringPool at pool_pos (chunk start)."""
    import struct

    base = pool_pos + 8
    if base + 20 > len(data):
        return []
    string_count, _sc, flags, strings_start, _styles = struct.unpack_from("<IIIII", data, base)
    is_utf8 = bool(flags & (1 << 8))
    offsets_off = base + 20
    pool: list[str] = []
    for i in range(min(int(string_count), limit)):
        opos = offsets_off + i * 4
        if opos + 4 > len(data):
            break
        rel = struct.unpack_from("<I", data, opos)[0]
        s_off = pool_pos + strings_start + rel
        if s_off >= len(data):
            continue
        if is_utf8:
            p = s_off
            if p + 2 > len(data):
                continue
            if data[p] & 0x80:
                p += 2
            else:
                p += 1
            if p < len(data) and data[p] & 0x80:
                p += 2
            else:
                p += 1
            end = data.find(b"\x00", p, min(len(data), p + 400))
            if end < 0:
                end = min(len(data), p + 80)
            pool.append(data[p:end].decode("utf-8", "ignore"))
        else:
            if s_off + 2 > len(data):
                continue
            char_len = struct.unpack_from("<H", data, s_off)[0]
            if char_len & 0x8000:
                char_len = ((char_len & 0x7FFF) << 16) | struct.unpack_from("<H", data, s_off + 2)[0]
                p = s_off + 4
            else:
                p = s_off + 2
            nbytes = min(char_len * 2, 400)
            pool.append(data[p : p + nbytes].decode("utf-16le", "ignore"))
    return [s for s in pool if s]


def parse_axml_tree(data: bytes, *, limit_nodes: int = 200) -> dict[str, Any]:
    """Parse binary AndroidManifest-style AXML into string pool + start-element nodes.

    Chunk types (Android res):
      0x0001 RES_STRING_POOL_TYPE
      0x0100 RES_XML_TYPE (root)
      0x0102 RES_XML_START_ELEMENT_TYPE
      0x0103 RES_XML_END_ELEMENT_TYPE
      0x0104 RES_XML_CDATA_TYPE
    """
    import struct

    out: dict[str, Any] = {
        "strings": [],
        "nodes": [],
        "package": None,
        "permissions": [],
        "activities": [],
        "source": "none",
        "error": None,
    }
    if len(data) < 8:
        out["error"] = "too_small"
        return out

    try:
        pool: list[str] = []
        nodes: list[dict[str, Any]] = []
        pos = 0
        # Some files are raw XML text (our synthetic tests)
        if data.lstrip().startswith(b"<") or b'package="' in data[:200]:
            text = _readable_strings(data, min_len=3)
            out["strings"] = [ln for ln in text.splitlines() if ln][:500]
            out["source"] = "text_or_islands"
            m = _PKG_RE.search(text)
            if m:
                out["package"] = m.group(1)
            perms = sorted(set(_PERM_RE.findall(text)))
            out["permissions"] = [f"android.permission.{p}" for p in perms]
            return out

        while pos + 8 <= len(data) and len(nodes) < limit_nodes:
            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, pos)
            if chunk_size < 8 or pos + chunk_size > len(data):
                break
            if chunk_type == 0x0001:
                pool = _decode_axml_string_pool(data, pos, chunk_size, limit=2000)
                out["source"] = "string_pool"
            elif chunk_type == 0x0102:  # START_ELEMENT
                # ResChunk_header(8) + lineNumber(4) + comment(4) + attrExt
                # attrExt: ns(4) name(4) attributeStart(2) attributeSize(2) attributeCount(2) ...
                ext = pos + 8 + 8  # after header + line + comment
                if ext + 12 <= len(data):
                    ns_idx, name_idx = struct.unpack_from("<II", data, ext)
                    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, ext + 8)

                    str_pool = pool  # bind for nested lookup (ruff B023)

                    def s(i: int, _pool: list[str] = str_pool) -> str | None:
                        if i < 0 or i == 0xFFFFFFFF or i >= len(_pool):
                            return None
                        return _pool[i]

                    tag = s(name_idx) or f"idx:{name_idx}"
                    attrs: dict[str, str] = {}
                    attr_base = ext + attr_start
                    step = attr_size if attr_size >= 20 else 20
                    for ai in range(min(int(attr_count), 40)):
                        aoff = attr_base + ai * step
                        if aoff + 20 > len(data) or aoff + 20 > pos + chunk_size:
                            break
                        _a_ns, a_name, a_raw = struct.unpack_from("<III", data, aoff)
                        _t_size, _t_res0, t_type, t_data = struct.unpack_from("<HBBI", data, aoff + 12)
                        key = s(a_name) or f"a{a_name}"
                        if t_type == 3:  # TYPE_STRING
                            val = s(t_data) or s(a_raw) or ""
                        elif t_type == 0x10:
                            val = str(t_data)
                        elif t_type == 0x12:
                            val = "true" if t_data else "false"
                        else:
                            val = s(a_raw) or str(t_data)
                        attrs[str(key)] = str(val)
                    node = {"tag": tag, "ns": s(ns_idx), "attrs": attrs}
                    nodes.append(node)
                    if tag.endswith("manifest") or tag == "manifest":
                        pkg = attrs.get("package")
                        if pkg:
                            out["package"] = pkg
                    if "permission" in str(tag).lower():
                        perm = attrs.get("name")
                        if perm:
                            out["permissions"].append(perm)
                    elif str(attrs.get("name", "")).startswith("android.permission."):
                        out["permissions"].append(attrs["name"])
                    if "activity" in str(tag).lower():
                        act = attrs.get("name") or attrs.get("android:name")
                        if act:
                            out["activities"].append(act)
            pos += chunk_size

        out["strings"] = pool[:500]
        out["string_count"] = len(pool)
        out["nodes"] = nodes[:limit_nodes]
        out["node_count"] = len(nodes)
        out["permissions"] = sorted(set(out["permissions"]))[:100]
        out["activities"] = list(dict.fromkeys(out["activities"]))[:40]
        if not out["source"]:
            out["source"] = "tree" if nodes else "empty"
        if not pool and not nodes:
            text = _readable_strings(data, min_len=4)
            out["strings"] = [ln for ln in text.splitlines() if ln][:500]
            out["source"] = "readable_islands"
            m = _PKG_RE.search(text)
            if m:
                out["package"] = m.group(1)
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
        text = _readable_strings(data, min_len=4)
        out["strings"] = text.splitlines()[:500]
        out["source"] = "error_fallback"
    return out


def parse_axml_strings(data: bytes, *, limit: int = 500) -> dict[str, Any]:
    """Best-effort binary Android XML string pool + tree extraction.

    Prefer parse_axml_tree for structured nodes; this keeps the legacy string-focused API.
    """
    tree = parse_axml_tree(data, limit_nodes=200)
    strings = list(tree.get("strings") or [])[:limit]
    if not strings:
        text = _readable_strings(data, min_len=4)
        strings = [ln for ln in text.splitlines() if ln][:limit]
        tree["source"] = tree.get("source") or "readable_islands"
    return {
        "strings": strings,
        "source": tree.get("source"),
        "string_count": len(strings),
        "error": tree.get("error"),
        "package": tree.get("package"),
        "permissions": tree.get("permissions") or [],
        "activities": tree.get("activities") or [],
        "nodes": (tree.get("nodes") or [])[:50],
        "node_count": tree.get("node_count") or 0,
    }


def analyze_native_so(data: bytes, *, name: str = "lib.so") -> dict[str, Any]:
    """ELF header + interesting symbols/strings for a single .so (reuses desktop ELF parser)."""
    from easy_rev.platforms.desktop.common.static import parse_elf

    elf = parse_elf(data)
    urls = [
        u.decode("ascii", "ignore").rstrip(".,);")
        for u in _URL_RE.findall(data[: min(len(data), 1_500_000)])[:20]
    ]
    readable = _readable_strings(data[: min(len(data), 800_000)], min_len=6)
    classified = classify_dex_strings(readable, limit_per=12)
    return {
        "name": name,
        "size": len(data),
        "is_elf": data[:4] == b"\x7fELF",
        "elf": {
            "class": elf.get("class"),
            "machine": elf.get("machine"),
            "type": elf.get("type"),
            "needed": (elf.get("needed") or [])[:30],
            "exports_hint": (elf.get("exports_hint") or [])[:40],
            "section_count": len(elf.get("sections") or []),
            "error": elf.get("error"),
        },
        "urls": urls[:20],
        "string_classes": classified.get("counts") or {},
        "string_hits": classified.get("buckets") or {},
    }


def scan_apk_bytes(data: bytes, *, name_hint: str = "app.apk") -> dict[str, Any]:
    """Parse APK from raw zip bytes (pure path for tests)."""
    import io

    out: dict[str, Any] = {
        "kind": "apk",
        "entries": [],
        "package": None,
        "permissions": [],
        "urls": [],
        "dex_files": [],
        "native_libs": [],
        "native_analysis": [],
        "dex_string_classes": {},
        "assets": [],
        "ssl_pinning_hints": [],
        "crypto_hints": [],
        "obfuscated": False,
        "has_network_security_config": False,
        "signing": {"v1_meta_inf": False, "cert_files": []},
        "activities_hint": [],
        "error": None,
    }
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            return _scan_apk_zip(zf, out)
    except zipfile.BadZipFile as e:
        out["error"] = f"bad_zip: {e}"
        return out


def _scan_apk_zip(zf: zipfile.ZipFile, out: dict[str, Any]) -> dict[str, Any]:
    names = zf.namelist()
    out["entries"] = names[:300]
    out["entry_count"] = len(names)
    out["dex_files"] = [n for n in names if n.endswith(".dex")]
    out["native_libs"] = [
        n
        for n in names
        if n.endswith(".so") and ("/lib/" in n or n.startswith("lib/"))
    ]
    out["assets"] = [n for n in names if n.startswith("assets/")][:80]
    out["obfuscated"] = len(out["dex_files"]) > 1 or bool(
        _OBFUSCATION.search("\n".join(names))
    )
    out["has_network_security_config"] = any(
        "network_security_config" in n.lower() for n in names
    )
    certs = [
        n
        for n in names
        if n.upper().startswith("META-INF/")
        and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF", ".MF"))
    ]
    out["signing"] = {
        "v1_meta_inf": any(n.upper().endswith((".RSA", ".DSA", ".EC")) for n in certs),
        "cert_files": certs[:20],
    }

    # AndroidManifest — AXML string pool when possible, else readable islands
    if "AndroidManifest.xml" in names:
        raw = zf.read("AndroidManifest.xml")
        axml = parse_axml_strings(raw)
        out["manifest_parse"] = {
            "source": axml.get("source"),
            "string_count": axml.get("string_count") or len(axml.get("strings") or []),
            "node_count": axml.get("node_count") or 0,
        }
        if axml.get("package"):
            out["package"] = axml["package"]
        if axml.get("permissions"):
            out["permissions"] = list(axml["permissions"])[:100]
        if axml.get("activities"):
            out["activities_hint"] = list(axml["activities"])[:40]
        pool_text = "\n".join(axml.get("strings") or [])
        text = pool_text + "\n" + _readable_strings(raw, min_len=4)
        m = _PKG_RE.search(text)
        if m and not out.get("package"):
            out["package"] = m.group(1)
        if not out["package"]:
            # dotted ids heuristic from string pool first
            candidates = _DOTTED_ID.findall(text)
            filtered = [
                c
                for c in candidates
                if not c.startswith("android.")
                and not c.startswith("http")
                and c.count(".") >= 2
            ]
            if filtered:
                out["package"] = max(filtered, key=len)
        perms = sorted(set(_PERM_RE.findall(text)))
        # also catch bare permission names from pool
        for s in axml.get("strings") or []:
            if s.startswith("android.permission."):
                perms.append(s.split("android.permission.", 1)[-1])
        perms = sorted(set(perms))
        out["permissions"] = [
            p if p.startswith("android.permission.") else f"android.permission.{p}" for p in perms
        ][:100]
        if _PINNING.search(text):
            out["ssl_pinning_hints"].append("manifest_strings:pinning_keyword")
        acts = re.findall(r"([a-zA-Z0-9_.]*Activity[a-zA-Z0-9_.]*)", text)
        out["activities_hint"] = list(dict.fromkeys(acts))[:40]

    urls: set[str] = set()
    pin_hits: list[str] = []
    crypto_hits: list[str] = []
    dex_blob_parts: list[str] = []
    native_analysis: list[dict[str, Any]] = []

    for name in names:
        info = zf.getinfo(name)
        if info.file_size > 2_500_000:
            continue
        is_so = name.endswith(".so") and ("/lib/" in name or name.startswith("lib/"))
        if name.endswith((".png", ".webp", ".jpg", ".jpeg", ".gif", ".mp4")):
            continue
        try:
            blob = zf.read(name)
        except Exception:  # noqa: BLE001
            continue

        if is_so:
            # Deep native: ELF parse first few libs
            if len(native_analysis) < 6:
                native_analysis.append(analyze_native_so(blob, name=name))
            for u in _URL_RE.findall(blob)[:15]:
                try:
                    urls.add(u.decode("ascii", errors="ignore").rstrip(".,);"))
                except Exception:  # noqa: BLE001
                    pass
            continue

        for u in _URL_RE.findall(blob)[:30]:
            try:
                urls.add(u.decode("ascii", errors="ignore").rstrip(".,);"))
            except Exception:  # noqa: BLE001
                pass
        try:
            t = blob.decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            t = ""
        if name.endswith(".dex"):
            dex_meta = parse_dex_string_ids(blob, limit=3000)
            out.setdefault("dex_meta", []).append(
                {
                    "name": name,
                    "source": dex_meta.get("source"),
                    "string_count": dex_meta.get("string_count"),
                    "error": dex_meta.get("error"),
                }
            )
            if dex_meta.get("strings"):
                dex_blob_parts.append("\n".join(dex_meta["strings"][:2500]))
            readable = _readable_strings(blob[: min(len(blob), 1_200_000)], min_len=5)
            dex_blob_parts.append(readable[:200_000])
        elif name.startswith("assets/"):
            readable = _readable_strings(blob[: min(len(blob), 1_200_000)], min_len=5)
            dex_blob_parts.append(readable[:200_000])
            if t:
                dex_blob_parts.append(t[:50_000])
        if _PINNING.search(name) or (t and _PINNING.search(t[:8000])):
            pin_hits.append(name)
        if t and _CRYPTO.search(t[:8000]):
            crypto_hits.append(name)
        if name.endswith("network_security_config.xml") or "network_security_config" in name:
            out["has_network_security_config"] = True
            if "pin-set" in t or "pin set" in t.lower():
                pin_hits.append(name)

    out["urls"] = sorted(urls)[:80]
    out["ssl_pinning_hints"] = sorted(set(out["ssl_pinning_hints"] + pin_hits))[:40]
    out["crypto_hints"] = sorted(set(crypto_hits))[:40]
    out["native_analysis"] = native_analysis

    # DEX/assets string classification
    if dex_blob_parts:
        merged = "\n".join(dex_blob_parts)[:800_000]
        classified = classify_dex_strings(merged)
        out["dex_string_classes"] = classified.get("counts") or {}
        out["dex_string_hits"] = classified.get("buckets") or {}
        out["dex_hot_categories"] = classified.get("hot") or []
        # fold crypto/pinning from classification into hints
        for hit in (classified.get("buckets") or {}).get("pinning") or []:
            pin_hits.append(f"dex:{hit[:80]}")
        for hit in (classified.get("buckets") or {}).get("crypto") or []:
            crypto_hits.append(f"dex:{hit[:80]}")
        out["ssl_pinning_hints"] = sorted(set(out["ssl_pinning_hints"] + pin_hits))[:40]
        out["crypto_hints"] = sorted(set(crypto_hits))[:40]
    else:
        out["dex_string_classes"] = {}
        out["dex_string_hits"] = {}
        out["dex_hot_categories"] = []

    return out


def scan_apk_file(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as zf:
        out: dict[str, Any] = {
            "kind": "apk",
            "entries": [],
            "package": None,
            "permissions": [],
            "urls": [],
            "dex_files": [],
            "native_libs": [],
            "native_analysis": [],
            "dex_string_classes": {},
            "assets": [],
            "ssl_pinning_hints": [],
            "crypto_hints": [],
            "obfuscated": False,
            "has_network_security_config": False,
            "signing": {"v1_meta_inf": False, "cert_files": []},
            "activities_hint": [],
            "error": None,
        }
        return _scan_apk_zip(zf, out)


def scan_ipa_bytes(data: bytes) -> dict[str, Any]:
    import io

    out: dict[str, Any] = {
        "kind": "ipa",
        "entries": [],
        "package": None,
        "urls": [],
        "frameworks": [],
        "binaries": [],
        "binary_analysis": [],
        "ssl_pinning_hints": [],
        "crypto_hints": [],
        "obfuscated": False,
        "info_plist_keys": [],
        "minimum_os_version": None,
        "error": None,
    }
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            return _scan_ipa_zip(zf, out)
    except zipfile.BadZipFile as e:
        out["error"] = f"bad_zip: {e}"
        return out


def _looks_like_macho(blob: bytes) -> bool:
    if len(blob) < 4:
        return False
    return blob[:4] in {
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xfe\xed\xfa\xcf",
        b"\xfe\xed\xfa\xce",
    }


def _scan_ipa_zip(zf: zipfile.ZipFile, out: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.desktop.common.static import parse_macho_header

    names = zf.namelist()
    out["entries"] = names[:300]
    out["entry_count"] = len(names)
    out["frameworks"] = [n for n in names if ".framework/" in n][:60]
    out["plugins"] = [n for n in names if ".appex/" in n][:40]

    for name in names:
        if not name.endswith("Info.plist"):
            continue
        # Prefer Payload/*/Info.plist
        if "Payload/" not in name and out.get("package"):
            continue
        data = zf.read(name)
        text = data.decode("utf-8", errors="ignore")
        # XML plist
        m = re.search(
            r"<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>",
            text,
        )
        if m:
            out["package"] = m.group(1)
        keys = re.findall(r"<key>([^<]+)</key>", text)
        if keys:
            out["info_plist_keys"] = keys[:100]
        mos = re.search(
            r"<key>MinimumOSVersion</key>\s*<string>([^<]+)</string>",
            text,
        )
        if mos:
            out["minimum_os_version"] = mos.group(1)
        if "NSPinnedDomains" in keys or "TSKConfiguration" in text or "TrustKit" in text:
            out["ssl_pinning_hints"].append(name)
        # binary plist: hunt for bundle id-like strings
        if not out.get("package"):
            readable = _readable_strings(data, min_len=6)
            # reverse-dns candidates
            cands = _DOTTED_ID.findall(readable)
            filtered = [
                c
                for c in cands
                if c.count(".") >= 2
                and not c.startswith("http")
                and "apple.com" not in c
            ]
            if filtered:
                out["package"] = max(filtered, key=len)
        break

    urls: set[str] = set()
    binaries: list[str] = []
    binary_analysis: list[dict[str, Any]] = []

    for name in names:
        info = zf.getinfo(name)
        if info.file_size > 3_000_000:
            continue
        if any(name.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".mp4", ".car", ".nib")):
            continue
        try:
            blob = zf.read(name)
        except Exception:  # noqa: BLE001
            continue
        for u in _URL_RE.findall(blob)[:20]:
            urls.add(u.decode("ascii", errors="ignore").rstrip(".,);"))
        t = blob.decode("utf-8", errors="ignore")[:8000]
        if _PINNING.search(name) or _PINNING.search(t):
            out["ssl_pinning_hints"].append(name)
        if _CRYPTO.search(t):
            out["crypto_hints"].append(name)

        # Payload main binary / framework binaries (Mach-O)
        is_payload_bin = (
            name.startswith("Payload/")
            and not any(
                name.endswith(ext)
                for ext in (
                    ".plist",
                    ".png",
                    ".jpg",
                    ".json",
                    ".strings",
                    ".car",
                    ".nib",
                    ".storyboardc",
                )
            )
            and (
                ".framework/" in name
                or name.count("/") == 2  # Payload/App.app/Binary
                or name.endswith(".dylib")
            )
        )
        if is_payload_bin and _looks_like_macho(blob) and len(binary_analysis) < 8:
            binaries.append(name)
            mh = parse_macho_header(blob)
            binary_analysis.append(
                {
                    "path": name,
                    "size": len(blob),
                    "format": mh.get("format"),
                    "cpu_name": mh.get("cpu_name") or mh.get("slice_cpu_name"),
                    "dylibs": (mh.get("dylibs") or mh.get("slice_dylibs") or [])[:40],
                    "segments": [
                        s.get("name") for s in (mh.get("segments") or [])[:20]
                    ],
                    # True N_SECT|N_EXT only (not N_UNDF imports)
                    "exports": list(mh.get("exports") or [])[:40],
                    "undefined": list(mh.get("undefined") or mh.get("imports") or [])[:40],
                    "ncmds": mh.get("ncmds"),
                }
            )
        elif is_payload_bin and len(blob) > 64 and len(binaries) < 20:
            # non-macho payload files still listed
            if name not in binaries and not name.endswith("/"):
                # only if no extension-like suffix
                base = name.rsplit("/", 1)[-1]
                if "." not in base or base.endswith(".dylib"):
                    binaries.append(name)

    out["urls"] = sorted(urls)[:80]
    out["ssl_pinning_hints"] = sorted(set(out["ssl_pinning_hints"]))[:40]
    out["crypto_hints"] = sorted(set(out["crypto_hints"]))[:40]
    out["binaries"] = binaries[:40]
    out["binary_analysis"] = binary_analysis
    return out


def scan_ipa_file(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as zf:
        out: dict[str, Any] = {
            "kind": "ipa",
            "entries": [],
            "package": None,
            "urls": [],
            "frameworks": [],
            "binaries": [],
            "binary_analysis": [],
            "ssl_pinning_hints": [],
            "crypto_hints": [],
            "obfuscated": False,
            "info_plist_keys": [],
            "minimum_os_version": None,
            "error": None,
        }
        return _scan_ipa_zip(zf, out)


async def analyze_package(
    binary: str | Path,
    *,
    platform: Platform = Platform.ANDROID,
) -> dict[str, Any]:
    path = Path(binary).expanduser().resolve()
    if not path.is_file():
        return {
            "ok": False,
            "error": f"package not found: {path}",
            "artifact_paths": [],
        }

    suffix = path.suffix.lower()
    if suffix == ".apk" or (platform is Platform.ANDROID and suffix != ".ipa"):
        try:
            report = scan_apk_file(path)
        except zipfile.BadZipFile:
            report = {"ok": False, "error": "not a zip/apk", "kind": "unknown"}
    elif suffix in {".ipa"} or platform is Platform.IOS:
        try:
            report = scan_ipa_file(path)
        except zipfile.BadZipFile:
            report = {"ok": False, "error": "not a zip/ipa", "kind": "unknown"}
    else:
        try:
            report = scan_apk_file(path)
        except Exception as e:  # noqa: BLE001
            report = {"ok": False, "error": str(e), "kind": "unknown"}

    if report.get("error") and not report.get("kind"):
        report["ok"] = False
        return {**report, "binary": str(path), "platform": platform.value, "artifact_paths": []}

    report["ok"] = True
    report["binary"] = str(path)
    report["platform"] = platform.value

    # Optional deep APK via androguard — never blocks base path
    if report.get("kind") == "apk":
        try:
            from androguard.misc import AnalyzeAPK

            a, _, _ = AnalyzeAPK(str(path))
            report["package"] = report.get("package") or a.get_package()
            report["app_name"] = a.get_app_name()
            ag_perms = sorted(set(a.get_permissions() or []))
            if ag_perms:
                report["permissions"] = ag_perms[:120]
            report["androguard"] = True
        except Exception as e:  # noqa: BLE001
            report["androguard"] = False
            report["androguard_error"] = str(e)

    out_dir = artifacts_dir() / "mobile" / path.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "static_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    report["artifact_paths"] = [str(report_path)]
    report["summary"] = {
        "kind": report.get("kind"),
        "package": report.get("package"),
        "url_count": len(report.get("urls") or []),
        "permission_count": len(report.get("permissions") or []),
        "ssl_pinning": bool(report.get("ssl_pinning_hints")),
        "obfuscated": report.get("obfuscated"),
        "native_lib_count": len(report.get("native_libs") or []),
        "native_analysis_count": len(report.get("native_analysis") or []),
        "dex_count": len(report.get("dex_files") or []),
        "dex_class_hot": (report.get("dex_hot_categories") or [])[:6],
        "binary_analysis_count": len(report.get("binary_analysis") or []),
        "framework_count": len(report.get("frameworks") or []),
    }
    return report
