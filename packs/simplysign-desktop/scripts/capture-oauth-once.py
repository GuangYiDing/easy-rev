#!/usr/bin/env python3
"""One-time OTP capture for reboot-proof SimplySign session.

Uses the ad-hoc signed debug build (get-task-allow) + Frida.
Saves refresh/access tokens to:
  ~/Library/Application Support/easy-rev/simplysign-session/session.json
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import frida

DBG_APP = Path("/Users/ding/Developer/easy-rev/artifacts/simplysign-debug/SimplySign Desktop.app")
HOOK = Path("/Users/ding/Developer/easy-rev/artifacts/simplysign-debug/capture_oauth.js")
SESSION_DIR = Path.home() / "Library/Application Support/easy-rev/simplysign-session"
SESSION_FILE = SESSION_DIR / "session.json"
HOOK_JS = HOOK.read_text(encoding="utf-8")


def kill_debug_instances() -> None:
    # only kill debug path instances
    try:
        out = subprocess.check_output(["pgrep", "-x", "SimplySign Desktop"], text=True).split()
    except subprocess.CalledProcessError:
        return
    for pid in out:
        try:
            txt = subprocess.check_output(["lsof", "-p", pid], text=True, errors="replace")
        except Exception:
            continue
        if "artifacts/simplysign-debug" in txt:
            os.kill(int(pid), signal.SIGTERM)


def main() -> int:
    if not DBG_APP.exists():
        print("debug app missing:", DBG_APP)
        return 1
    SESSION_DIR.mkdir(parents=True, exist_ok=True)

    print("=== SimplySign 一次性 OTP 捕获 ===")
    print("1) 会启动可调试副本（不是 /Applications 里那份）")
    print("2) 在菜单栏点 Connect with cloud，输入一次 OTP")
    print("3) 捕获到 refresh_token 后自动保存并退出")
    print("注意：请先不要退出当前已登录的正式版，除非你接受重新登录。")
    print("本脚本只启动 debug 副本；正式版可继续保持会话。")

    kill_debug_instances()
    # open debug app
    subprocess.check_call(["open", "-n", "-a", str(DBG_APP)])
    time.sleep(2)

    pid = None
    for _ in range(30):
        try:
            for p in subprocess.check_output(["pgrep", "-x", "SimplySign Desktop"], text=True).split():
                txt = subprocess.check_output(["lsof", "-p", p], text=True, errors="replace")
                if "artifacts/simplysign-debug" in txt:
                    pid = int(p)
                    break
        except Exception:
            pass
        if pid:
            break
        time.sleep(0.5)
    if not pid:
        print("无法找到 debug 进程")
        return 1
    print("attached debug pid", pid)

    session = frida.attach(pid)
    # frida CLI loads bridge; python needs handler
    from frida_tools.application import try_handle_bridge_request  # type: ignore

    class BridgeHelper:
        def try_handle_bridge_request(self, message, script):  # noqa: ANN001
            return try_handle_bridge_request(self, message, script)

    helper = BridgeHelper()
    saved = {"tokens": []}

    def on_message(message, data):  # noqa: ANN001
        if helper.try_handle_bridge_request(message, script):
            return
        if message["type"] == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("type") == "token":
                tok = payload.get("payload") or {}
                print("[token]", {k: (str(v)[:16] + "...") if v and k in ("accessToken", "refreshToken", "clientSecret") else v for k, v in tok.items()})
                saved["tokens"].append(tok)
                # persist best effort when refresh present
                if tok.get("refreshToken") and tok.get("refreshToken") not in ("None", "nil", ""):
                    best = {
                        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "access_token": tok.get("accessToken"),
                        "refresh_token": tok.get("refreshToken"),
                        "expires_at": tok.get("expiresAt"),
                        "token_type": tok.get("tokenType"),
                        "client_id": tok.get("clientID"),
                        "client_secret": tok.get("clientSecret"),
                        "keychain_group": tok.get("keyChainGroup"),
                        "persistent": tok.get("persistent"),
                        "response_body": tok.get("responseBody"),
                        "raw": tok,
                    }
                    SESSION_FILE.write_text(json.dumps(best, ensure_ascii=False, indent=2), encoding="utf-8")
                    os.chmod(SESSION_FILE, 0o600)
                    print("SAVED", SESSION_FILE)
        elif message["type"] == "error":
            print("frida error", message)

    script = session.create_script(HOOK_JS)
    script.on("message", on_message)
    script.load()
    print("hooks loaded — 请在 debug 版 SimplySign 中完成一次 OTP 登录…")
    print("按 Ctrl+C 结束（若已保存 refresh_token 可直接结束）")
    try:
        while True:
            time.sleep(1)
            if SESSION_FILE.exists():
                # keep running a bit more to catch client secrets if they arrive later
                data = json.loads(SESSION_FILE.read_text())
                if data.get("refresh_token") and data.get("client_id") and data.get("client_secret"):
                    print("完整凭证已齐，10 秒后退出…")
                    time.sleep(10)
                    break
    except KeyboardInterrupt:
        print("stopped by user")
    session.detach()
    if SESSION_FILE.exists():
        print("完成。会话文件:", SESSION_FILE)
        return 0
    print("未捕获到 refresh_token。请确认在 *debug 副本* 里登录成功。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
