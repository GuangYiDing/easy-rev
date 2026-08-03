#!/usr/bin/env python3
"""Manage the SimplySign TOTP seed in the macOS Keychain.

The seed is captured ONCE from the activation QR / otpauth URI (or from a
re-bind of the mobile token in the Certum account security settings). It is
then stored in the login keychain under service `easy-rev-simplysign-totp` and
never written to chat, git, CI logs, or a plaintext file.

Usage:
  totp-keychain.py store [--uri URI | --from-clipboard] [--account NAME]
      # reads otpauth:// URI (or bare base32) from stdin when no --uri given
  totp-keychain.py show [--code-only]
  totp-keychain.py type [--check]
  totp-keychain.py check
  totp-keychain.py accessibility
  totp-keychain.py delete --yes

Env overrides: SIMPLYSIGN_TOTP_SERVICE, SIMPLYSIGN_TOTP_ACCOUNT
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from datetime import UTC, datetime

from totp_core import (
    DEFAULT_ACCOUNT,
    accessibility_ok,
    keychain_delete,
    keychain_entry,
    keychain_store,
    parse_otpauth,
    pkcs_ok,
    service_name,
    totp,
    type_otp_macos,
)


def _account(args: argparse.Namespace) -> str:
    return (
        args.account
        or os.environ.get("SIMPLYSIGN_TOTP_ACCOUNT")
        or DEFAULT_ACCOUNT
    )


def cmd_store(args: argparse.Namespace) -> int:
    if args.from_clipboard:
        r = subprocess.run(["pbpaste"], capture_output=True, text=True)
        raw = r.stdout
    elif args.uri:
        raw = args.uri
    else:
        raw = sys.stdin.read()
    raw = (raw or "").strip()
    if not raw:
        print(
            "没有输入。请从密码管理器复制 otpauth:// URI 后运行：\n"
            "  pbpaste | totp-keychain.py store\n"
            "或粘贴到 stdin（不要发到聊天/仓库/CI）。",
            file=sys.stderr,
        )
        return 1
    try:
        entry = parse_otpauth(raw)
    except ValueError as e:
        print(f"种子无效：{e}", file=sys.stderr)
        return 1

    account = _account(args)
    service = service_name()
    # sanity: must produce a 6-digit code before committing
    code = totp(entry["secret"], digits=entry["digits"], period=entry["period"])
    if len(code) != entry["digits"]:
        print("生成的验证码长度异常，已中止。", file=sys.stderr)
        return 1

    entry["stored_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    try:
        keychain_store(service, account, entry)
    except RuntimeError as e:
        print(f"写入钥匙串失败：{e}", file=sys.stderr)
        return 1

    label = entry.get("label") or account
    print(
        f"OK 种子已写入钥匙串\n"
        f"  service : {service}\n"
        f"  account : {account}\n"
        f"  label   : {label}\n"
        f"  digits  : {entry['digits']}  period: {entry['period']}s\n"
        f"  校验码  : {code}（仅用于确认，已丢弃）"
    )
    print("种子本身未打印、未落盘；后续可用 `totp-keychain.py show/type`。")
    return 0


def _load_entry(args: argparse.Namespace):
    entry = keychain_entry(service=service_name(), account=_account(args))
    if entry is None:
        print(
            f"钥匙串中没有 TOTP 种子（service={service_name()} account={_account(args)}）。\n"
            "请先一次性导入：pbpaste | totp-keychain.py store",
            file=sys.stderr,
        )
        return None
    return entry


def cmd_show(args: argparse.Namespace) -> int:
    entry = _load_entry(args)
    if entry is None:
        return 1
    code = totp(entry["secret"], digits=entry["digits"], period=entry["period"])
    remaining = entry["period"] - int(time.time()) % entry["period"]
    if args.code_only:
        print(code)
        return 0
    print(f"OTP={code}  valid_for≈{remaining}s  account={_account(args)}")
    return 0


def cmd_type(args: argparse.Namespace) -> int:
    entry = _load_entry(args)
    if entry is None:
        return 1
    if not accessibility_ok():
        print(
            "自动键入需要辅助功能权限。请到\n"
            "  系统设置 → 隐私与安全性 → 辅助功能\n"
            "勾选运行本脚本的终端/Codex 应用，然后重试。",
            file=sys.stderr,
        )
        return 2
    code = totp(entry["secret"], digits=entry["digits"], period=entry["period"])
    remaining = entry["period"] - int(time.time()) % entry["period"]
    if remaining < 5:
        time.sleep(remaining + 1)
        code = totp(entry["secret"], digits=entry["digits"], period=entry["period"])
    print("正在将 OTP 键入 SimplySign 登录框…")
    try:
        type_otp_macos(code)
    except Exception as e:
        print(
            f"自动键入失败：{e}\n"
            "请确认：1) 辅助功能已授权；2) SimplySign 登录框已打开（菜单栏 Connect with cloud）。",
            file=sys.stderr,
        )
        return 2
    print("已键入，等待云连接…")
    time.sleep(4)
    if args.check:
        ok = pkcs_ok()
        print("pkcs_session_ok=" + str(ok))
        return 0 if ok else 2
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    entry = _load_entry(args)
    if entry is None:
        return 1
    print(
        f"OK 种子存在\n"
        f"  service : {service_name()}\n"
        f"  account : {_account(args)}\n"
        f"  label   : {entry.get('label') or '(未提供)'}\n"
        f"  digits  : {entry['digits']}  period: {entry['period']}s\n"
        f"  stored_at: {entry.get('stored_at', '未知')}"
    )
    return 0


def cmd_accessibility(_: argparse.Namespace) -> int:
    if accessibility_ok():
        print("辅助功能权限：已授予")
        return 0
    print(
        "辅助功能权限：未授予。请到\n"
        "  系统设置 → 隐私与安全性 → 辅助功能\n"
        "勾选运行本脚本的终端/Codex 应用。",
        file=sys.stderr,
    )
    return 1


def cmd_delete(args: argparse.Namespace) -> int:
    if not args.yes:
        print("请加 --yes 确认删除钥匙串中的 TOTP 种子。", file=sys.stderr)
        return 1
    ok = keychain_delete(service_name(), _account(args))
    print("已删除。" if ok else "未找到条目，无需删除。")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="SimplySign TOTP 种子钥匙串管理")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--service", default=None, help=f"钥匙串 service（默认 {service_name()}）"
    )
    common.add_argument(
        "--account", default=None, help=f"钥匙串 account（默认 {DEFAULT_ACCOUNT}，可用 Certum 邮箱）"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_store = sub.add_parser("store", parents=[common], help="从 otpauth URI 导入种子到钥匙串")
    p_store.add_argument("--uri", default=None, help="otpauth:// URI（不提供则读 stdin）")
    p_store.add_argument("--from-clipboard", action="store_true", help="从剪贴板读取 URI")
    p_store.set_defaults(func=cmd_store)

    p_show = sub.add_parser("show", parents=[common], help="显示当前 OTP（不显示种子）")
    p_show.add_argument("--code-only", action="store_true")
    p_show.set_defaults(func=cmd_show)

    p_type = sub.add_parser("type", parents=[common], help="生成 OTP 并键入 SimplySign 登录框")
    p_type.add_argument("--check", action="store_true", help="键入后探测 PKCS 会话")
    p_type.set_defaults(func=cmd_type)

    sub.add_parser("check", parents=[common], help="检查种子是否存在（不输出种子）").set_defaults(
        func=cmd_check
    )
    sub.add_parser("accessibility", parents=[common], help="检查辅助功能权限").set_defaults(
        func=cmd_accessibility
    )

    p_del = sub.add_parser("delete", parents=[common], help="删除钥匙串中的种子")
    p_del.add_argument("--yes", action="store_true")
    p_del.set_defaults(func=cmd_delete)

    args = ap.parse_args()
    if args.service:
        import os

        os.environ["SIMPLYSIGN_TOTP_SERVICE"] = args.service
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
