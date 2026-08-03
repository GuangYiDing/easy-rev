#!/usr/bin/env python3
import asyncio, json, os, re, ssl, time, urllib.error, urllib.parse, urllib.request, traceback
from pathlib import Path
import websockets

OUT = Path(open('/tmp/simplysign-capture-dir.txt').read().strip())
SESSION = Path.home() / 'Library/Application Support/easy-rev/simplysign-session/session.json'
PORT = 9335
CLIENT_ID = '44rvDKKEWY53a7xBeF5w'
REDIRECT = 'https://cloudsign.webnotarius.pl/redirect'
TOKEN_URL = 'https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken'
LOG = OUT / 'cdp_capture.out'

def log(*a):
    msg = ' '.join(str(x) for x in a)
    print(msg, flush=True)
    with LOG.open('a') as f:
        f.write(msg + '\n')

def list_pages():
    with urllib.request.urlopen(f'http://127.0.0.1:{PORT}/json/list', timeout=2) as r:
        return json.loads(r.read().decode())

def pick():
    pages = [p for p in list_pages() if p.get('type') == 'page' and p.get('webSocketDebuggerUrl')]
    def score(p):
        u = p.get('url') or ''
        s = 0
        if 'cloudsign' in u: s += 50
        if u.startswith('http'): s += 5
        if 'chrome-extension' in u: s -= 100
        return s
    pages.sort(key=score, reverse=True)
    return pages[0] if pages else None

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

async def main():
    p0 = None
    for i in range(60):
        try:
            p0 = pick()
            if p0:
                break
        except Exception as e:
            log('wait page', i, e)
        await asyncio.sleep(0.25)
    if not p0:
        raise SystemExit('no page')
    log('listen', (p0.get('url') or '')[:180])
    ws_url = p0['webSocketDebuggerUrl']
    code = None
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
        log('CDP listening — please OTP in the front Chrome window')
        deadline = time.time() + 900
        while time.time() < deadline and not code:
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
            if any(x in url for x in ('code=', 'redirect', 'callbackAuthorize', 'login', 'certum')):
                log('URL', url[:240])
            m = re.search(r'[?&]code=(OC-[A-Za-z0-9_\-]+)', url)
            if m:
                code = m.group(1)
                log('FOUND', code[:28] + '...')
                break
    if not code:
        raise SystemExit('no code')

    tok = None
    for form in (
        {'grant_type': 'authorization_code', 'code': code, 'client_id': CLIENT_ID, 'redirect_uri': REDIRECT},
        {'grant_type': 'authorization_code', 'code': code, 'client_id': CLIENT_ID, 'redirect_uri': REDIRECT, 'client_name': 'CasOAuthClient'},
    ):
        st, text = post(form)
        log('exchange', st, text[:500])
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
        'source': 'cdp-listen-visible',
        'raw_token_response': tok,
    }
    SESSION.parent.mkdir(parents=True, exist_ok=True)
    SESSION.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    os.chmod(SESSION, 0o600)
    (OUT / 'session.json').write_text(SESSION.read_text())
    log('SAVED', SESSION)
    log('HAS', {k: bool(data.get(k)) for k in ('access_token', 'refresh_token')})
    if data.get('refresh_token'):
        st, text = post({'grant_type': 'refresh_token', 'client_id': CLIENT_ID, 'refresh_token': data['refresh_token']})
        log('refresh', st, text[:300])
    log('DONE')

if __name__ == '__main__':
    try:
        asyncio.get_event_loop().run_until_complete(main())
    except Exception:
        traceback.print_exc()
        raise
