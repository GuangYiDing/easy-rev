#!/usr/bin/env python3
"""Best-effort extract of OAuth tokens from SSLKEYLOG-enabled notes.

Full pcap decryption needs tshark+sslkeylog; this helper also scans any
side-car text dumps you export from Wireshark (File→Export Packet Dissections).
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

SESSION = (
    Path.home()
    / "Library/Application Support/easy-rev/simplysign-session/session.json"
)

TOKEN_RE = re.compile(
    r'"(access_token|refresh_token|expires_in|token_type)"\s*:\s*"?([^",}\s]+)"?'
)
FORM_RE = re.compile(
    r"(access_token|refresh_token)=([^&\s]+)"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="capture directory")
    ap.add_argument("--text", action="append", default=[], help="extra exported text files")
    ap.add_argument("--write-session", action="store_true")
    args = ap.parse_args()
    d = Path(args.dir)
    files = list(d.glob("**/*")) + [Path(p) for p in args.text]
    found: dict[str, str] = {}
    for f in files:
        if not f.is_file():
            continue
        if f.suffix in {".pcap", ".pcapng"}:
            continue
        try:
            data = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for k, v in TOKEN_RE.findall(data):
            found[k] = v
        for k, v in FORM_RE.findall(data):
            found[k] = v
        if "grant_type=refresh_token" in data:
            print("saw refresh grant in", f)
        if "card/v1/cards" in data:
            print("saw card API in", f)
        if "multipart/form-data" in data and "signature" in data:
            print("saw multipart signature-ish in", f)

    print("extracted fields:", {k: (v[:12] + "…") for k, v in found.items()})
    ssl = d / "sslkeys.log"
    print("sslkeys exists", ssl.exists(), "size", ssl.stat().st_size if ssl.exists() else 0)
    if args.write_session and found.get("access_token"):
        cur = {}
        if SESSION.exists():
            cur = json.loads(SESSION.read_text())
        cur.update(found)
        SESSION.parent.mkdir(parents=True, exist_ok=True)
        SESSION.write_text(json.dumps(cur, indent=2), encoding="utf-8")
        SESSION.chmod(0o600)
        print("wrote", SESSION)
    else:
        print("Tip: export decrypted HTTP from Wireshark using sslkeys.log, then re-run with --text export.txt --write-session")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
