#!/usr/bin/env bash
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
DBG_APP="/Users/ding/Developer/easy-rev/artifacts/simplysign-debug/SimplySign Desktop.app"
HOOK="/Users/ding/Developer/easy-rev/artifacts/simplysign-debug/capture_oauth.js"
SESSION_DIR="$HOME/Library/Application Support/easy-rev/simplysign-session"
SESSION="$SESSION_DIR/session.json"
mkdir -p "$SESSION_DIR"

echo "=== 重启免 OTP：一次性 OAuth 捕获 ==="
echo "重要：正式版与 DEBUG 不能同时占锁，捕获期间会暂时退出正式版。"
echo "捕获成功后可再开正式版；真正开机免 OTP 会改走 DEBUG + 静默恢复。"
echo

# Stop keepalive that steals/cancels the login dialog every 5 minutes
launchctl bootout "gui/$(id -u)/com.easyrev.simplysign-keepalive" 2>/dev/null || true
pkill -f 'session-keepalive.sh' 2>/dev/null || true
pkill -f 'session-check-once.sh' 2>/dev/null || true

# Stop ALL simplysign instances for clean single debug login
pkill -x 'SimplySign Desktop' 2>/dev/null || true
sleep 1
pkill -9 -x 'SimplySign Desktop' 2>/dev/null || true
sleep 1
# clear lock if stale
rm -f "$HOME/SimplySignDesktop-Lock" 2>/dev/null || true

# clear previous incomplete capture artifacts (keep client_credentials)
rm -f "$SESSION" "$SESSION_DIR/last_code.json" 2>/dev/null || true
: > "$SESSION_DIR/raw_events.jsonl"

open -n -a "$DBG_APP"
sleep 2

pid=""
for _ in $(seq 1 50); do
  for p in $(pgrep -x 'SimplySign Desktop' || true); do
    if lsof -p "$p" 2>/dev/null | grep -q 'artifacts/simplysign-debug'; then
      pid=$p; break 2
    fi
  done
  sleep 0.2
done
if [[ -z "${pid}" ]]; then
  # maybe only one path
  pid=$(pgrep -x 'SimplySign Desktop' | head -1 || true)
fi
if [[ -z "${pid}" ]]; then
  echo "DEBUG 进程未启动"
  exit 1
fi
echo "debug/target pid=$pid"
echo "请现在在菜单栏 SimplySign → Connect with cloud → 输入 OTP"
echo "等待捕获 refresh_token…"

frida -p "$pid" -l "$HOOK" 2>&1 | tee /tmp/simplysign-capture.log &
FRIDA_PID=$!
cleanup(){ kill "$FRIDA_PID" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 600); do
  # if process died, abort
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "目标进程已退出，查看 /tmp/simplysign-capture.log"
    # if session already written, still success
    if [[ -f "$SESSION" ]]; then
      break
    fi
    exit 3
  fi
  if [[ -f "$SESSION" ]]; then
    if python3 - "$SESSION" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
rt=(d.get('refresh_token') or '')
# also accept response_body containing refresh
rb=(d.get('response_body') or '')
ok = bool(rt and rt not in {'None','nil','null'}) or ('refresh_token' in rb)
sys.exit(0 if ok else 1)
PY
    then
      echo
      echo "捕获成功 → $SESSION"
      python3 - <<PY
import json
from pathlib import Path
d=json.loads(Path("$SESSION").read_text())
# if refresh only in body, extract
if not d.get('refresh_token') and d.get('response_body'):
    import re, urllib.parse
    s=d['response_body']
    try:
        j=json.loads(s); d.update({k:j[k] for k in ['access_token','refresh_token','expires_in','token_type'] if k in j})
    except Exception:
        m=re.search(r'refresh_token=([^&"]+)', s)
        if m: d['refresh_token']=urllib.parse.unquote(m.group(1))
        m=re.search(r'access_token=([^&"]+)', s)
        if m: d['access_token']=urllib.parse.unquote(m.group(1))
    Path("$SESSION").write_text(json.dumps(d,ensure_ascii=False,indent=2))
show={k:(str(v)[:8]+f'…({len(str(v))} chars)' if k in {'access_token','refresh_token','client_secret','response_body'} and v else v) for k,v in d.items()}
print(json.dumps(show, ensure_ascii=False, indent=2))
PY
      chmod 600 "$SESSION" || true
      echo
      echo "下一步验证静默刷新："
      echo "  python3 packs/simplysign-desktop/scripts/silent-restore.py"
      exit 0
    fi
  fi
  sleep 1
done
echo "超时或未拿到 refresh_token。日志: /tmp/simplysign-capture.log / raw_events.jsonl"
ls -la "$SESSION_DIR" || true
tail -n 50 /tmp/simplysign-capture.log || true
exit 2
