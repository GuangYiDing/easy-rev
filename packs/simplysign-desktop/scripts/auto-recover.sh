#!/usr/bin/env bash
# 自动恢复 SimplySign 云会话（首次 OTP 之后无人值守）。
#
# 顺序：
#   1) 确保 Desktop 在运行
#   2) 探测 PKCS#11 会话；在线则结束
#   3) 协议层：若 session.json 存在，先尝试 headless refresh（不恢复 PKCS，
#      但保住 client.py 的 headless 签名路径）
#   4) 钥匙串必须已有 TOTP 种子（service=easy-rev-simplysign-totp）
#   5) 辅助功能权限必须已授予
#   6) 触发登录对话框（菜单栏 Connect + PKCS 访问请求）
#   7) 自动键入 OTP 并复探 PKCS
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACK_DIR="$(dirname "$SCRIPT_DIR")"
PY="${SIMPLYSIGN_PYTHON:-/opt/homebrew/bin/python3}"
SESSION_DIR="$HOME/Library/Application Support/easy-rev/simplysign-session"
LOG_FILE="${SIMPLYSIGN_KEEPALIVE_LOG:-$HOME/Library/Logs/simplysign-keepalive.log}"
MODULE="${CERTUM_PKCS11_LIBRARY:-/usr/local/lib/libSimplySignPKCS.dylib}"
PIN="${CERTUM_TOKEN_PIN:-0000}"
export CERTUM_PKCS11_LIBRARY="$MODULE"
export CERTUM_TOKEN_PIN="$PIN"

ts() { date '+%Y-%m-%d %H:%M:%S'; }
mkdir -p "$(dirname "$LOG_FILE")"
log() { echo "[$(ts)] $*" | tee -a "$LOG_FILE"; }
notify() {
  log "$@"
  /usr/bin/osascript -e "display notification \"$*\" with title \"SimplySign 自动恢复\"" 2>/dev/null || true
}

probe_pkcs() {
  "$PY" - "$SCRIPT_DIR" <<'PY' >/dev/null 2>&1
import sys
sys.path.insert(0, sys.argv[1])
from totp_core import pkcs_ok
raise SystemExit(0 if pkcs_ok() else 1)
PY
}

# 1. 确保 Desktop 在跑
if ! pgrep -x "SimplySign Desktop" >/dev/null 2>&1; then
  log "Desktop 未运行，尝试启动"
  /usr/bin/open -ga "SimplySign Desktop" 2>/dev/null || true
  sleep 4
fi

# 2. 直接探测：还在线就结束
if probe_pkcs; then
  log "ok: PKCS 会话在线"
  exit 0
fi
log "PKCS 会话不可用 — 开始自动恢复"

# 3. 协议层 headless refresh（尽力而为，不影响后续 TOTP 重登）
if [[ -f "$SESSION_DIR/session.json" ]]; then
  if "$PY" "$PACK_DIR/protocol/client.py" --session "$SESSION_DIR/session.json" refresh >/dev/null 2>&1; then
    log "headless refresh OK（client.py 签名路径可用；PKCS/Desktop 仍需重新登录）"
  else
    log "headless refresh 失败（refresh_token 可能已被 Certum 吊销，走 OTP 重登）"
  fi
fi

# 4. 种子在钥匙串？
if ! "$PY" "$SCRIPT_DIR/totp-keychain.py" check >/dev/null 2>&1; then
  notify "钥匙串缺少 TOTP 种子：请先一次性执行 pbpaste | totp-keychain.py store"
  exit 1
fi

# 5. 辅助功能权限？
if ! "$PY" "$SCRIPT_DIR/totp-keychain.py" accessibility >/dev/null 2>&1; then
  notify "自动键入被拒：系统设置 → 隐私与安全性 → 辅助功能，勾选运行脚本的终端/Codex"
  exit 1
fi

# 6. 触发登录对话框（菜单栏 Connect 尽力而为 + PKCS 访问请求按偏好弹窗）
"$PY" - "$SCRIPT_DIR" <<'PY' >/dev/null 2>&1 || true
import sys
sys.path.insert(0, sys.argv[1])
from totp_core import click_connect_menu
click_connect_menu()
PY
pkcs11-tool --module "$MODULE" --list-slots >/dev/null 2>&1 || true
sleep 3

# 7. 自动键入 OTP 并复探
if "$PY" "$SCRIPT_DIR/totp-keychain.py" type --check; then
  log "自动恢复成功：OTP 已键入，PKCS 会话在线"
  exit 0
fi
notify "自动恢复失败：请手动 Connect with cloud 输入一次 OTP"
exit 1
