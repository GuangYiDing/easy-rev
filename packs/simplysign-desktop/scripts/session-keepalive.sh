#!/usr/bin/env bash
# 周期性探测 SimplySign PKCS#11 会话；失败时提醒重新 Connect（输入一次 OTP）
set -euo pipefail

MODULE="${CERTUM_PKCS11_LIBRARY:-/usr/local/lib/libSimplySignPKCS.dylib}"
PIN="${CERTUM_TOKEN_PIN:-0000}"
INTERVAL_SEC="${SIMPLYSIGN_KEEPALIVE_INTERVAL:-300}"
LOG_FILE="${SIMPLYSIGN_KEEPALIVE_LOG:-$HOME/simplysign-keepalive.log}"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

check_process() {
  pgrep -x "SimplySign Desktop" >/dev/null 2>&1
}

check_pkcs() {
  # list-slots 很快；list-objects 需要已登录云会话
  pkcs11-tool --module "$MODULE" --list-slots >/dev/null 2>&1 || return 1
  pkcs11-tool --module "$MODULE" --login --pin "$PIN" --list-objects --type cert >/dev/null 2>&1
}

notify() {
  local msg=$1
  echo "[$(ts)] $msg" | tee -a "$LOG_FILE"
  if command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"$msg\" with title \"SimplySign Keepalive\"" || true
  fi
}

echo "[$(ts)] keepalive start interval=${INTERVAL_SEC}s module=$MODULE" | tee -a "$LOG_FILE"

while true; do
  if ! check_process; then
    notify "SimplySign Desktop 未运行 — 请启动并完成一次 OTP 登录"
  elif ! check_pkcs; then
    notify "PKCS 会话不可用 — 请在菜单栏 Connect with cloud 并输入 OTP"
  else
    echo "[$(ts)] ok: process+pkcs session alive" >>"$LOG_FILE"
  fi
  sleep "$INTERVAL_SEC"
done
