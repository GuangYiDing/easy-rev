#!/usr/bin/env bash
set -euo pipefail
export PATH="/Users/ding/.homebrew/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
MODULE="${CERTUM_PKCS11_LIBRARY:-/usr/local/lib/libSimplySignPKCS.dylib}"
PIN="${CERTUM_TOKEN_PIN:-0000}"
LOG_FILE="${SIMPLYSIGN_KEEPALIVE_LOG:-$HOME/Library/Logs/simplysign-keepalive.log}"
WORK="${TMPDIR:-/tmp}/simplysign-keepalive-$$"
CFG="$WORK/pkcs11.cfg"
JAVA_SRC="$WORK/Probe.java"
ts(){ date '+%Y-%m-%d %H:%M:%S'; }
mkdir -p "$(dirname "$LOG_FILE")"

notify() {
  local msg=$1
  echo "[$(ts)] $msg" | tee -a "$LOG_FILE"
  /usr/bin/osascript -e "display notification \"$msg\" with title \"SimplySign\" subtitle \"需要一次 OTP 登录\"" 2>/dev/null || true
}

cleanup(){ rm -rf "$WORK" 2>/dev/null || true; }
trap cleanup EXIT

if ! pgrep -x "SimplySign Desktop" >/dev/null 2>&1; then
  /usr/bin/open -ga "SimplySign Desktop" 2>/dev/null || true
  sleep 3
fi

if ! pgrep -x "SimplySign Desktop" >/dev/null 2>&1; then
  notify "Desktop 未运行，请打开 SimplySign 并输入一次 OTP"
  exit 0
fi

if [[ ! -e "$MODULE" ]]; then
  notify "找不到 PKCS#11 库: $MODULE"
  exit 0
fi

if ! command -v java >/dev/null 2>&1; then
  echo "[$(ts)] java missing; only checked process alive pid=$(pgrep -x 'SimplySign Desktop' | tr '\n' ' ')" >>"$LOG_FILE"
  exit 0
fi

mkdir -p "$WORK"
cat > "$CFG" <<EOF
name = SimplySignKeepalive
library = $MODULE
slotListIndex = 0
EOF

cat > "$JAVA_SRC" <<'JAVA'
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;

public class Probe {
  public static void main(String[] args) throws Exception {
    String cfgPath = args[0];
    String pin = args[1];
    Provider base = Security.getProvider("SunPKCS11");
    if (base == null) throw new IllegalStateException("SunPKCS11 missing");
    Provider p = base.configure(cfgPath);
    Security.addProvider(p);
    KeyStore ks = KeyStore.getInstance("PKCS11", p);
    ks.load(null, pin.toCharArray());
    int n = 0;
    for (String a : Collections.list(ks.aliases())) {
      System.out.println("ALIAS " + a);
      n++;
    }
    if (n == 0) throw new IllegalStateException("no aliases");
    System.out.println("OK aliases=" + n);
  }
}
JAVA

set +e
OUT="$WORK/out.txt"
java "$JAVA_SRC" "$CFG" "$PIN" >"$OUT" 2>&1
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "[$(ts)] probe failed rc=$RC" >>"$LOG_FILE"
  tail -n 30 "$OUT" >>"$LOG_FILE" 2>/dev/null || true
  notify "云会话失效或 PKCS 不可用：菜单栏 Connect with cloud，输入一次 OTP"
  exit 0
fi

ALIASES=$(grep -c '^ALIAS ' "$OUT" 2>/dev/null || echo 0)
echo "[$(ts)] ok session aliases=$ALIASES pid=$(pgrep -x 'SimplySign Desktop' | tr '\n' ' ')" >>"$LOG_FILE"
