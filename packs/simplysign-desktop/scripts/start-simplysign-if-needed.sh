#!/usr/bin/env bash
# launchd entrypoint: never start a second SimplySign Desktop instance
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

if pgrep -x "SimplySign Desktop" >/dev/null 2>&1; then
  # Already running (possibly with live OTP session). Exit success so KeepAlive is calm.
  exit 0
fi

# Start the real app and exit; do not exec-replace so launchd doesn't track wrong lifecycle
open -ga "SimplySign Desktop"
exit 0
