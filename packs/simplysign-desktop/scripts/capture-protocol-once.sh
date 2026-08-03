#!/usr/bin/env bash
# Capture one OTP login + one jsign with SSLKEYLOGFILE + tcpdump.
# Produces decryptable material for protocol completion.
set -euo pipefail
export PATH="/Users/ding/.homebrew/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

OUT_DIR="${SIMPLYSIGN_CAPTURE_DIR:-$HOME/Library/Application Support/easy-rev/simplysign-session/captures/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR" || true
SSLKEYLOGFILE="$OUT_DIR/sslkeys.log"
PCAP="$OUT_DIR/traffic.pcap"
LOG="$OUT_DIR/capture.log"
export SSLKEYLOGFILE

echo "=== SimplySign protocol capture ===" | tee "$LOG"
echo "out: $OUT_DIR" | tee -a "$LOG"
echo "This will STOP SimplySign Desktop and require ONE OTP login." | tee -a "$LOG"

# stop keepalive noise
launchctl bootout "gui/$(id -u)/com.easyrev.simplysign-keepalive" 2>/dev/null || true

# stop app
pkill -x 'SimplySign Desktop' 2>/dev/null || true
sleep 1
pkill -9 -x 'SimplySign Desktop' 2>/dev/null || true
sleep 1
rm -f "$HOME/SimplySignDesktop-Lock" 2>/dev/null || true

# start tcpdump if possible (may need password for bpf)
TCPDUMP_PID=""
if command -v tcpdump >/dev/null 2>&1; then
  if tcpdump -i any -w "$PCAP" host cloudsign.webnotarius.pl or host simplysign.certum.pl 2>"$OUT_DIR/tcpdump.err" & then
    TCPDUMP_PID=$!
    echo "tcpdump pid=$TCPDUMP_PID -> $PCAP" | tee -a "$LOG"
  else
    echo "tcpdump failed (need bpf/sudo?). Continue with SSLKEYLOG only." | tee -a "$LOG"
  fi
else
  echo "tcpdump not found; SSLKEYLOG only" | tee -a "$LOG"
fi

cleanup() {
  if [[ -n "${TCPDUMP_PID}" ]]; then
    kill "$TCPDUMP_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# launch Desktop with SSLKEYLOGFILE in environment via launchctl / open wrapper
WRAPPER="$OUT_DIR/run-desktop.sh"
cat > "$WRAPPER" <<EOF
#!/bin/bash
export SSLKEYLOGFILE='$SSLKEYLOGFILE'
export PATH='$PATH'
exec '/Applications/SimplySign Desktop.app/Contents/MacOS/SimplySign Desktop'
EOF
chmod +x "$WRAPPER"

# Prefer direct exec so env is inherited (open -a drops custom env)
nohup "$WRAPPER" >"$OUT_DIR/desktop.stdout" 2>"$OUT_DIR/desktop.stderr" &
echo "desktop launched with SSLKEYLOGFILE" | tee -a "$LOG"
sleep 2
pgrep -lf 'SimplySign Desktop' | tee -a "$LOG" || true

cat <<MSG | tee -a "$LOG"

Now do:
  1) Menu bar SimplySign → Connect with cloud → enter OTP once
  2) In another terminal, run a sign, e.g.:
       jsign --storetype PKCS11 --keystore /tmp/simplysign-pkcs11.cfg \\
         --storepass 0000 --alias <CERT_ALIAS> \\
         --tsaurl http://time.certum.pl --alg SHA-256 --replace some.exe
  3) Come back here and press ENTER to stop capture

MSG
read -r _

cleanup
trap - EXIT

# restart keepalive if plist exists
if [[ -f "$HOME/Library/LaunchAgents/com.easyrev.simplysign-keepalive.plist" ]]; then
  launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.easyrev.simplysign-keepalive.plist" 2>/dev/null || true
fi

echo "sslkeys bytes: $(wc -c < "$SSLKEYLOGFILE" 2>/dev/null || echo 0)" | tee -a "$LOG"
echo "pcap: $PCAP ($(wc -c < "$PCAP" 2>/dev/null || echo 0) bytes)" | tee -a "$LOG"
echo "Next: python3 packs/simplysign-desktop/protocol/parse_capture.py --dir '$OUT_DIR'" | tee -a "$LOG"
