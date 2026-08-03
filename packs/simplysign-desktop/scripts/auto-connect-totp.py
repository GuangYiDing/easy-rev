#!/usr/bin/env python3
"""Generate SimplySign TOTP and optionally type it into the login UI.

This does NOT bypass Certum MFA. It automates entering the same OTP you would
type from the mobile app, so an authorized local automation process can
re-login unattended after a session death.

Seed source (in priority order):
  1. macOS Keychain — service `easy-rev-simplysign-totp` (recommended; write once
     via `totp-keychain.py store`, never keep the URI in files/chat/CI).
  2. $CERTUM_OTP_URI (legacy, discouraged).
  3. Legacy totp.env (deprecated; delete once migrated to Keychain).

Usage:
  python3 auto-connect-totp.py            # print current OTP only
  python3 auto-connect-totp.py --type     # focus login dialog + type OTP+Enter
  python3 auto-connect-totp.py --check    # probe PKCS session after typing
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from totp_core import (  # noqa: E402
    DEFAULT_ACCOUNT,
    accessibility_ok,
    keychain_entry,
    parse_otpauth,
    pkcs_ok,
    service_name,
    totp,
    type_otp_macos,
)

ENV_FILE = (
    Path.home()
    / "Library/Application Support/easy-rev/simplysign-session/totp.env"
)


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


def resolve_entry(args: argparse.Namespace) -> dict:
    account = (
        args.account
        or os.environ.get("SIMPLYSIGN_TOTP_ACCOUNT")
        or DEFAULT_ACCOUNT
    )
    entry = keychain_entry(account=account)
    if entry:
        return entry

    uri = os.environ.get("CERTUM_OTP_URI")
    source = "$CERTUM_OTP_URI"
    if not uri:
        env = load_env(Path(args.env_file))
        uri = env.get("CERTUM_OTP_URI")
        source = str(Path(args.env_file))
        if uri:
            print(
                f"警告：正在使用已废弃的明文文件 {source}。\n"
                "请迁移到钥匙串：pbpaste | totp-keychain.py store，然后删除该文件。",
                file=sys.stderr,
            )
    if not uri:
        print(
            "钥匙串中没有 TOTP 种子，也没有 CERTUM_OTP_URI。\n"
            f"请先一次性导入：pbpaste | packs/simplysign-desktop/scripts/totp-keychain.py store\n"
            f"（service={service_name()} account={account}）",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return parse_otpauth(uri)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--type", action="store_true", help="type OTP into SimplySign UI")
    ap.add_argument("--check", action="store_true", help="probe PKCS after typing")
    ap.add_argument("--account", default=None, help="keychain account (default: simplysign)")
    ap.add_argument("--env-file", default=str(ENV_FILE))
    args = ap.parse_args()

    entry = resolve_entry(args)
    secret, digits, period = entry["secret"], entry["digits"], entry["period"]
    code = totp(secret, digits=digits, period=period)
    remaining = period - int(time.time()) % period
    print(f"OTP={code}  valid_for≈{remaining}s")

    if args.type:
        if not accessibility_ok():
            print(
                "自动键入需要辅助功能权限。请到\n"
                "  系统设置 → 隐私与安全性 → 辅助功能\n"
                "勾选运行本脚本的终端/Codex 应用，然后重试。",
                file=sys.stderr,
            )
            return 2
        if remaining < 5:
            time.sleep(remaining + 1)
            code = totp(secret, digits=digits, period=period)
            print(f"rolled OTP={code}")
        print("Typing into SimplySign login UI…")
        try:
            type_otp_macos(code)
        except Exception as e:
            print(
                f"自动键入失败：{e}\n"
                "请确认：1) 辅助功能已授权；2) SimplySign 登录框已打开。",
                file=sys.stderr,
            )
            return 2
        print("Typed. Wait a few seconds for cloud connect.")
        time.sleep(4)

    if args.check:
        ok = pkcs_ok()
        print("pkcs_session_ok=" + str(ok))
        return 0 if ok else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
