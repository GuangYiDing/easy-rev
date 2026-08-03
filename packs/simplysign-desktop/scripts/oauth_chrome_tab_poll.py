#!/usr/bin/env python3
import json, os, re, ssl, subprocess, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

OUT = Path(open("/tmp/simplysign-capture-dir.txt").read().strip())
SESSION = Path.home() / "Library/Application Support/easy-rev/simplysign-session/session.json"
CLIENT_ID = "44rvDKKEWY53a7xBeF5w"
REDIRECT = "https://cloudsign.webnotarius.pl/redirect"
TOKEN_URL = "https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken"
ASCRIPT = "/tmp/ss_chrome_tabs.applescript"

def tab_urls():
    r = subprocess.run(["osascript", ASCRIPT], capture_output=True, text=True, timeout=8)
    if r.returncode != 0:
        print("osascript err", r.stderr.strip(), flush=True)
        return []
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip().startswith("http")]

def post(form):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(TOKEN_URL, data=data, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

print("polling normal Chrome tabs...", flush=True)
code = None
for i in range(900):
    urls = tab_urls()
    for u in urls:
        if "cloudsign" in u:
            if i % 5 == 0:
                print("see", u[:180], flush=True)
        if "cloudsign.webnotarius.pl/redirect" in u and "code=" in u:
            print("URL", u[:220], flush=True)
            m = re.search(r"[?&]code=(OC-[A-Za-z0-9_\-]+)", u)
            if m:
                code = m.group(1)
                break
    if code:
        break
    if i % 5 == 0:
        print("waiting", i, "tabs", len(urls), flush=True)
    time.sleep(1)

if not code:
    raise SystemExit("timeout no code")
print("FOUND", code[:28] + "...", flush=True)

tok = None
for form in (
    {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "redirect_uri": REDIRECT},
    {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "client_name": "CasOAuthClient"},
):
    st, text = post(form)
    print("exchange", st, text[:500], flush=True)
    if st < 400:
        try:
            tok = json.loads(text)
        except Exception:
            tok = dict(urllib.parse.parse_qsl(text))
        break
if not tok:
    raise SystemExit("exchange failed")

data = {
    "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "access_token": tok.get("access_token"),
    "refresh_token": tok.get("refresh_token"),
    "expires_in": tok.get("expires_in"),
    "token_type": tok.get("token_type"),
    "client_id": CLIENT_ID,
    "client_secret": "",
    "source": "chrome-tab-poll",
    "raw_token_response": tok,
}
SESSION.parent.mkdir(parents=True, exist_ok=True)
SESSION.write_text(json.dumps(data, ensure_ascii=False, indent=2))
os.chmod(SESSION, 0o600)
(OUT / "session.json").write_text(SESSION.read_text())
print("SAVED", SESSION, flush=True)
print("HAS", {k: bool(data.get(k)) for k in ("access_token", "refresh_token")}, flush=True)
if data.get("refresh_token"):
    st, text = post({"grant_type": "refresh_token", "client_id": CLIENT_ID, "refresh_token": data["refresh_token"]})
    print("refresh", st, text[:300], flush=True)
print("DONE", flush=True)
