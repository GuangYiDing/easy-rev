#!/usr/bin/env python3
"""Generate SimplySign TOTP and optionally type it into the login UI.

This does NOT bypass Certum MFA. It automates entering the same OTP you would
type from the mobile app, so CI / self-hosted runners can re-login unattended
after a session death.

Required secrets (store outside git, mode 600):

  ~/Library/Application Support/easy-rev/simplysign-session/totp.env
    CERTUM_OTP_URI=otpauth://totp/...?secret=BASE32&digits=6&period=30
    CERTUM_USER_ID=you@example.com   # optional, already cached by Desktop

Usage:
  python3 auto-connect-totp.py            # print current OTP only
  python3 auto-connect-totp.py --type     # focus login dialog + type OTP+Enter
  python3 auto-connect-totp.py --check    # probe PKCS session after typing
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import struct
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

ENV_FILE = (
    Path.home()
    / "Library/Application Support/easy-rev/simplysign-session/totp.env"
)
DEFAULT_MODULE = os.environ.get(
    "CERTUM_PKCS11_LIBRARY", "/usr/local/lib/libSimplySignPKCS.dylib"
)
DEFAULT_PIN = os.environ.get("CERTUM_TOKEN_PIN", "0000")


def load_env(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip().strip('"').strip("'")
    return data


def b32decode(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s + pad, casefold=True)


def totp(secret: str, digits: int = 6, period: int = 30, t: float | None = None) -> str:
    key = b32decode(secret)
    counter = int((time.time() if t is None else t) // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def parse_otpauth(uri: str) -> tuple[str, int, int]:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth":
        return uri, 6, 30
    q = urllib.parse.parse_qs(parsed.query)
    secret = (q.get("secret") or [""])[0]
    if not secret:
        raise SystemExit("otpauth URI missing secret=")
    digits = int((q.get("digits") or ["6"])[0])
    period = int((q.get("period") or ["30"])[0])
    return secret, digits, period


def type_otp_macos(otp: str) -> None:
    # Require Accessibility for Terminal/Codex host.
    script = "\n".join([
        'tell application "System Events"',
        '  set procs to every process whose name contains "SimplySign"',
        '  if (count of procs) is 0 then error "SimplySign process not found"',
        '  set frontmost of item 1 of procs to true',
        '  delay 0.4',
        f'  keystroke "{otp}"',
        '  delay 0.15',
        '  key code 36',
        'end tell',
    ])
    subprocess.run(["osascript", "-e", script], check=True)


def pkcs_ok() -> bool:
    tool_candidates = [
        "/Users/ding/.homebrew/bin/pkcs11-tool",
        "/opt/homebrew/bin/pkcs11-tool",
        "/usr/local/bin/pkcs11-tool",
    ]
    tool = next((p for p in tool_candidates if os.path.isfile(p)), None)
    if not tool:
        return False
    r = subprocess.run(
        [
            tool,
            "--module",
            DEFAULT_MODULE,
            "--login",
            "--pin",
            DEFAULT_PIN,
            "--list-objects",
            "--type",
            "cert",
        ],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0 and (
        "Certificate Object" in r.stdout or "label" in r.stdout.lower()
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--type", action="store_true", help="type OTP into SimplySign UI")
    ap.add_argument("--check", action="store_true", help="probe PKCS after typing")
    ap.add_argument("--env-file", default=str(ENV_FILE))
    args = ap.parse_args()

    env = load_env(Path(args.env_file))
    uri = os.environ.get("CERTUM_OTP_URI") or env.get("CERTUM_OTP_URI")
    if not uri:
        print(
            "Missing CERTUM_OTP_URI.\n"
            f"Create {ENV_FILE} with:\n"
            "  CERTUM_OTP_URI=otpauth://totp/SimplySign:you@example.com?secret=BASE32&digits=6&period=30\n"
            "Export once from 1Password/Bitwarden (same QR secret as mobile app).",
            file=sys.stderr,
        )
        return 1

    secret, digits, period = parse_otpauth(uri)
    code = totp(secret, digits=digits, period=period)
    remaining = period - int(time.time()) % period
    print(f"OTP={code}  valid_for≈{remaining}s")

    if args.type:
        if remaining < 5:
            time.sleep(remaining + 1)
            code = totp(secret, digits=digits, period=period)
            print(f"rolled OTP={code}")
        print("Typing into SimplySign login UI…")
        type_otp_macos(code)
        print("Typed. Wait a few seconds for cloud connect.")
        time.sleep(4)

    if args.check:
        ok = pkcs_ok()
        print("pkcs_session_ok=" + str(ok))
        return 0 if ok else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
