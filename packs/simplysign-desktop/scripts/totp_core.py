#!/usr/bin/env python3
"""Shared TOTP + macOS Keychain helpers for SimplySign unattended login.

Secret storage policy (per operator directive):
- The TOTP seed NEVER lives in chat, git, CI logs, or plaintext files.
- It is stored in the macOS login keychain as a generic password item:
    service:  easy-rev-simplysign-totp
    account:  <certum account email> or "simplysign"
- The stored value is a small JSON payload {secret, digits, period, label, issuer}.
- Writes go through `security -i` (command parsed from stdin), so the seed
  never appears in any process argv and never hits shell history.

The 6-digit code cannot be reversed into the seed; the seed must be captured
once from the activation QR / otpauth URI (see totp-keychain.py store).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import subprocess
import time
import urllib.parse
from pathlib import Path

DEFAULT_SERVICE = "easy-rev-simplysign-totp"
DEFAULT_ACCOUNT = "simplysign"
SECURITY = "/usr/bin/security"
PKCS11_CANDIDATES = [
    "/opt/homebrew/bin/pkcs11-tool",
    "/usr/local/bin/pkcs11-tool",
]
DEFAULT_MODULE = os.environ.get(
    "CERTUM_PKCS11_LIBRARY", "/usr/local/lib/libSimplySignPKCS.dylib"
)
DEFAULT_PIN = os.environ.get("CERTUM_TOKEN_PIN", "0000")


# --------------------------------------------------------------------------
# base32 / TOTP (RFC 6238)
# --------------------------------------------------------------------------


def normalize_secret(secret: str) -> str:
    """Validate base32 and return canonical unpadded uppercase form."""
    s = "".join(ch for ch in secret.strip() if ch not in " -").upper()
    if not s:
        raise ValueError("empty TOTP secret")
    raw = s.rstrip("=")
    pad = "=" * ((8 - len(raw) % 8) % 8)
    try:
        base64.b32decode(raw + pad, casefold=True)
    except Exception as e:
        raise ValueError(f"invalid base32 secret: {e}") from e
    return raw


def b32decode(secret: str) -> bytes:
    s = normalize_secret(secret)
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


def parse_otpauth(uri: str) -> dict:
    """Accept otpauth:// URI or a bare base32 seed."""
    uri = uri.strip()
    if uri.lower().startswith("otpauth://"):
        parsed = urllib.parse.urlparse(uri)
        q = urllib.parse.parse_qs(parsed.query)
        secret = (q.get("secret") or [""])[0]
        if not secret:
            raise ValueError("otpauth URI missing secret=")
        digits = int((q.get("digits") or ["6"])[0])
        period = int((q.get("period") or ["30"])[0])
        label = urllib.parse.unquote(parsed.path.lstrip("/"))
        issuer = urllib.parse.unquote((q.get("issuer") or [""])[0]) or parsed.netloc
        return {
            "secret": normalize_secret(secret),
            "digits": digits,
            "period": period,
            "label": label,
            "issuer": issuer,
        }
    return {
        "secret": normalize_secret(uri),
        "digits": 6,
        "period": 30,
        "label": "",
        "issuer": "",
    }


# --------------------------------------------------------------------------
# macOS Keychain (login keychain, generic password)
# --------------------------------------------------------------------------


def service_name() -> str:
    return os.environ.get("SIMPLYSIGN_TOTP_SERVICE", DEFAULT_SERVICE)


def keychain_store(service: str, account: str, payload: dict) -> None:
    """Store TOTP entry via `security -i`; seed stays out of argv."""
    secret = payload["secret"]
    safe_account = account.replace('"', "").replace("\\", "")
    # label must be whitespace-free for `security -i` tokenization
    label = "SimplySign-TOTP-Certum"
    safe_label = label.replace('"', "").replace("\\", "")
    # -w <secret> must remain unquoted-safe: canonical base32 is [A-Z2-7]
    cmd = (
        f'add-generic-password -U -a "{safe_account}" -s "{service}" '
        f'-w {secret} -l "{safe_label}"\n'
    )
    r = subprocess.run([SECURITY, "-i"], input=cmd.encode(), capture_output=True)
    if r.returncode != 0:
        err = r.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"keychain store failed: {err or r.returncode}")
    # verify round-trip without printing the secret
    got = keychain_find(service, account)
    if got is None or got != secret:
        raise RuntimeError("keychain store verification failed")


def keychain_find(service: str, account: str) -> str | None:
    r = subprocess.run(
        [SECURITY, "find-generic-password", "-s", service, "-a", account, "-w"],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        return r.stdout.rstrip("\n")
    return None


def keychain_delete(service: str, account: str) -> bool:
    r = subprocess.run(
        [SECURITY, "delete-generic-password", "-s", service, "-a", account],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0


def keychain_entry(service: str | None = None, account: str | None = None) -> dict | None:
    service = service or service_name()
    account = account or DEFAULT_ACCOUNT
    raw = keychain_find(service, account)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except Exception:
        # legacy: raw base32 seed stored without JSON wrapper
        data = {
            "secret": normalize_secret(raw),
            "digits": 6,
            "period": 30,
            "label": "",
            "issuer": "",
        }
    data.setdefault("digits", 6)
    data.setdefault("period", 30)
    return data


# --------------------------------------------------------------------------
# macOS UI automation (Accessibility) + PKCS#11 probe
# --------------------------------------------------------------------------


def accessibility_ok() -> bool:
    """True only when the current process may send keystrokes via System Events."""
    try:
        import ctypes
        import ctypes.util

        appserv = ctypes.CDLL(ctypes.util.find_library("ApplicationServices"))
        appserv.AXIsProcessTrusted.restype = ctypes.c_bool
        return bool(appserv.AXIsProcessTrusted())
    except Exception:
        r = subprocess.run(
            ["osascript", "-e", 'tell application "System Events" to get name of first process'],
            capture_output=True,
            text=True,
        )
        return r.returncode == 0


def type_otp_macos(otp: str) -> None:
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
    subprocess.run(["osascript", "-e", script], check=True, capture_output=True)


CONNECT_MENU_CANDIDATES = [
    "Connect with cloud",
    "Log in",
    "Zaloguj",
    "Zaloguj się",
    "Zaloguj do chmury",
    "Połącz z chmurą",
    "Sign in",
    "Login",
]


def click_connect_menu() -> bool:
    """Best-effort: open the cloud connect dialog via the menu bar."""
    for name in CONNECT_MENU_CANDIDATES:
        script = (
            'tell application "System Events"\n'
            '  tell process "SimplySign Desktop"\n'
            f'    click menu item "{name}" of menu 1 of menu bar item 1 of menu bar 1\n'
            '  end tell\n'
            'end tell'
        )
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        if r.returncode == 0:
            return True
    return False


def pkcs_tool() -> str | None:
    return next((p for p in PKCS11_CANDIDATES if Path(p).is_file()), None)


def pkcs_ok(module: str | None = None, pin: str | None = None, timeout: float = 15.0) -> bool:
    tool = pkcs_tool()
    if not tool:
        return False
    try:
        r = subprocess.run(
            [
                tool,
                "--module",
                module or DEFAULT_MODULE,
                "--login",
                "--pin",
                pin or DEFAULT_PIN,
                "--list-objects",
                "--type",
                "cert",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0 and (
        "Certificate Object" in r.stdout or "label" in r.stdout.lower()
    )
