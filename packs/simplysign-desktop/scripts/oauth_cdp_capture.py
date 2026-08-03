#!/usr/bin/env python3
import asyncio, json, os, re, ssl, subprocess, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
import websockets

OUT = Path(open('/tmp/simplysign-capture-dir.txt').read().strip())
SESSION = Path.home() / 'Library/Application Support/easy-rev/simplysign-session/session.json'
PROFILE = Path('/tmp/simplysign-chrome-oauth-profile2')
PROFILE.mkdir(parents=True, exist_ok=True)
PORT = 9334
CLIENT_ID = '44rvDKKEWY53a7xBeF5w'
REDIRECT = 'https://cloudsign.webnotarius.pl/redirect'
TOKEN_URL = 'https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken'

service = 'https://cloudsign.webnotarius.pl/idp/oauth2.0/callbackAuthorize?' + urllib.parse.urlencode({
    'client_id': CLIENT_ID,
    'response_type': 'code',
    'redirect_uri': REDIRECT,
    'client_name': 'CasOAuthClient',
})
LOGIN = 'https://cloudsign.webnotarius.pl/idp/login?' + urllib.parse.urlencode({'service': service})
print('LOGIN', LOGIN, flush=True)

chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
proc = subprocess.Popen([
    chrome,
    f'--remote-debugging-port={PORT}',
    f'--user-data-dir={PROFILE}',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-background-networking',
    '--new-window',
    LOGIN,
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print('chrome pid', proc.pid, flush=True)
(OUT / 'cdp_chrome.pid').write_text(str(proc.pid))

def list_pages():
    with urllib.request.urlopen(f'http://127.0.0.1:{PORT}/json/list', timeout=1) as r:
        return json.loads(r.read().decode())

def score(p):
    u = p.get('url') or ''
    s = 0
    if p.get('type') == 'page':
        s += 10
    if 'cloudsign' in u or 'certum' in u:
        s += 50
    if u.startswith('http'):
        s += 5
    if u.startswith('chrome-extension'):
        s -= 100
    if u.startswith('chrome://'):
        s -= 50
    return s

ws_url = None
for i in range(80):
    try:
        pages = list_pages()
        pages = [p for p in pages if p.get('webSocketDebuggerUrl')]
        pages.sort(key=score, reverse=True)
        if pages and score(pages[0]) >= 10:
            ws_url = pages[0]['webSocketDebuggerUrl']
            print('attach', pages[0].get('type'), (pages[0].get('url') or '')[:160], flush=True)
            break
        # force create tab
        req = urllib.request.Request(
            f'http://127.0.0.1:{PORT}/json/new?{urllib.parse.quote(LOGIN, safe="")}',
            method='PUT',
        )
        with urllib.request.urlopen(req, timeout=2) as r:
            p0 = json.loads(r.read().decode())
            if p0.get('webSocketDebuggerUrl'):
                ws_url = p0['webSocketDebuggerUrl']
                print('created', (p0.get('url') or '')[:160], flush=True)
                break
    except Exception as e:
        if i % 10 == 0:
            print('wait cdp', i, e, flush=True)
    time.sleep(0.25)

if not ws_url:
    raise SystemExit('CDP page not ready')

found = {'code': None}

async def run():
    async with websockets.connect(ws_url, max_size=8_000_000) as ws:
        rid = 0
        async def cdp(method, params=None):
            nonlocal rid
            rid += 1
            msg = {'id': rid, 'method': method}
            if params is not None:
                msg['params'] = params
            await ws.send(json.dumps(msg))
        await cdp('Network.enable')
        await cdp('Page.enable')
        await cdp('Page.navigate', {'url': LOGIN})
        print('Please complete OTP in the NEW Chrome window (profile2).', flush=True)
        deadline = time.time() + 900
        while time.time() < deadline and not found['code']:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=1)
            except asyncio.TimeoutError:
                continue
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            method = msg.get('method')
            params = msg.get('params') or {}
            url = None
            if method == 'Network.requestWillBeSent':
                url = (params.get('request') or {}).get('url')
            elif method == 'Network.responseReceived':
                url = (params.get('response') or {}).get('url')
            elif method == 'Page.frameNavigated':
                url = (params.get('frame') or {}).get('url')
            elif method == 'Page.navigatedWithinDocument':
                url = params.get('url')
            if not url:
                continue
            if any(x in url for x in ('cloudsign', 'code=', 'certum.pl', 'callbackAuthorize', 'login')):
                print('URL', url[:240], flush=True)
            m = re.search(r'[?&]code=(OC-[A-Za-z0-9_\-]+)', url)
            if m:
                found['code'] = m.group(1)
                print('FOUND', found['code'][:28] + '...', flush=True)
                break
    return found['code']

code = asyncio.get_event_loop().run_until_complete(run())
if not code:
    raise SystemExit('no code')

def post(form):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(TOKEN_URL, data=data, method='POST', headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    })
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')

tok = None
for form in (
    {'grant_type': 'authorization_code', 'code': code, 'client_id': CLIENT_ID, 'redirect_uri': REDIRECT},
    {'grant_type': 'authorization_code', 'code': code, 'client_id': CLIENT_ID, 'redirect_uri': REDIRECT, 'client_name': 'CasOAuthClient'},
):
    st, text = post(form)
    print('exchange', st, text[:500], flush=True)
    if st < 400:
        try:
            tok = json.loads(text)
        except Exception:
            tok = dict(urllib.parse.parse_qsl(text))
        break
if not tok:
    raise SystemExit('exchange failed')

data = {
    'captured_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
    'access_token': tok.get('access_token'),
    'refresh_token': tok.get('refresh_token'),
    'expires_in': tok.get('expires_in'),
    'token_type': tok.get('token_type'),
    'client_id': CLIENT_ID,
    'client_secret': '',
    'source': 'cdp-browser-capture',
    'raw_token_response': tok,
}
SESSION.parent.mkdir(parents=True, exist_ok=True)
SESSION.write_text(json.dumps(data, ensure_ascii=False, indent=2))
os.chmod(SESSION, 0o600)
(OUT / 'session.json').write_text(SESSION.read_text())
print('SAVED', SESSION, flush=True)
print('HAS', {k: bool(data.get(k)) for k in ('access_token', 'refresh_token')}, flush=True)
if data.get('refresh_token'):
    st, text = post({'grant_type': 'refresh_token', 'client_id': CLIENT_ID, 'refresh_token': data['refresh_token']})
    print('refresh', st, text[:300], flush=True)
print('DONE', flush=True)
