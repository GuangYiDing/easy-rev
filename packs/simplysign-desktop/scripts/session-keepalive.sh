#!/usr/bin/env bash
# 周期性探测 SimplySign PKCS#11 会话；失效时自动恢复（钥匙串 TOTP），
# 自动恢复失败才通知人工。探测与恢复逻辑都在 auto-recover.sh。
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTERVAL_SEC="${SIMPLYSIGN_KEEPALIVE_INTERVAL:-300}"
LOG_FILE="${SIMPLYSIGN_KEEPALIVE_LOG:-$HOME/Library/Logs/simplysign-keepalive.log}"

ts() { date '+%Y-%m-%d %H:%M:%S'; }
mkdir -p "$(dirname "$LOG_FILE")"

echo "[$(ts)] keepalive start interval=${INTERVAL_SEC}s" | tee -a "$LOG_FILE"

while true; do
  "$SCRIPT_DIR/auto-recover.sh" || true
  sleep "$INTERVAL_SEC"
done
