#!/usr/bin/env bash
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
MODULE="${CERTUM_PKCS11_LIBRARY:-/usr/local/lib/libSimplySignPKCS.dylib}"
PIN="${CERTUM_TOKEN_PIN:-0000}"
PKCS11_TOOL="/opt/homebrew/bin/pkcs11-tool"
LOG_FILE="${SIMPLYSIGN_KEEPALIVE_LOG:-$HOME/Library/Logs/simplysign-keepalive.log}"
ts(){ date '+%Y-%m-%d %H:%M:%S'; }
mkdir -p "$(dirname "$LOG_FILE")"

notify() {
  local msg=$1
  echo "[$(ts)] $msg" | tee -a "$LOG_FILE"
  /usr/bin/osascript -e "display notification \"$msg\" with title \"SimplySign\" subtitle \"需要一次 OTP 登录\"" 2>/dev/null || true
}

# Ensure single Desktop process exists
if ! pgrep -x "SimplySign Desktop" >/dev/null 2>&1; then
  /usr/bin/open -ga "SimplySign Desktop" 2>/dev/null || true
  sleep 3
fi

if ! pgrep -x "SimplySign Desktop" >/dev/null 2>&1; then
  notify "Desktop 未运行，请打开 SimplySign 并输入一次 OTP"
  exit 0
fi

if [[ ! -x "$PKCS11_TOOL" ]]; then
  notify "找不到 pkcs11-tool，请 brew install opensc"
  exit 0
fi

if ! "$PKCS11_TOOL" --module "$MODULE" --list-slots >/dev/null 2>&1; then
  notify "PKCS 槽不可用，请检查 SimplySign Desktop 是否已连接云"
  exit 0
fi

if ! "$PKCS11_TOOL" --module "$MODULE" --login --pin "$PIN" --list-objects --type cert >/dev/null 2>&1; then
  notify "云会话失效：菜单栏点 Connect with cloud，输入一次 OTP 后即可继续签名"
  exit 0
fi

echo "[$(ts)] ok session alive pid=$(pgrep -x 'SimplySign Desktop' | tr '\n' ' ')" >>"$LOG_FILE"
