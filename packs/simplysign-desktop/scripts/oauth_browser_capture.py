#!/usr/bin/env python3
"""Capture SimplySign OAuth tokens via system browser (no Desktop WebView).

1) Opens authorize URL in default browser
2) Polls browser history / paste for redirect URL with ?code=
3) Exchanges authorization code for access/refresh tokens
4) Writes session.json
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

SESSION = (
    Path.home()
    / "Library/Application Support/easy-rev/simplysign-session/session.json"
)
XML = Path.home() / "SimplySignDesktop.xml"
TOKEN_URL = "https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken"
AUTHORIZE_URL = "https://cloudsign.webnotarius.pl/idp/oauth2.0/authorize"
REDIRECT_URI = "https://cloudsign.webnotarius.pl/redirect"


def load_oauth_config() -> dict[str, str]:
    root = ET.parse(XML).getroot()
    d = root.find("dict")
    kids = list(d)
    m: dict[str, str] = {}
    i = 0
    while i < len(kids) - 1:
        if kids[i].tag == "key":
            m[kids[i].text or ""] = kids[i + 1].text or ""
        i += 1
    return {
        "client_id": m.get("OAuth2ClientId") or "",
        "client_secret": m.get("OAuth2ClientSecret") or "",
        "authorize_url": m.get("OAuth2AuthorizeUrl") or AUTHORIZE_URL,
        "token_url": m.get("OAuth2AccessTokenUrl") or TOKEN_URL,
        "redirect_uri": m.get("OAuth2RedirectionUrl") or REDIRECT_URI,
        "scope_url": m.get("OAuth2ScopeUrl") or "",
    }


def build_authorize_url(cfg: dict[str, str]) -> str:
    q = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
    }
    # Some IDPs want scope; profile URL may be scope value
    if cfg.get("scope_url"):
        q["scope"] = cfg["scope_url"]
    return cfg["authorize_url"] + "?" + urllib.parse.urlencode(q)


def http_post_form(url: str, form: dict[str, str], headers: dict[str, str] | None = None):
    data = urllib.parse.urlencode(form).encode()
    h = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method="POST", headers=h)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def exchange_code(cfg: dict[str, str], code: str) -> dict:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "redirect_uri": cfg["redirect_uri"],
    }
    status, text = http_post_form(cfg["token_url"], form)
    print("exchange status", status)
    print(text[:500])
    if status >= 400:
        # try Basic
        import base64

        basic = base64.b64encode(
            f'{cfg["client_id"]}:{cfg["client_secret"]}'.encode()
        ).decode()
        form2 = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": cfg["redirect_uri"],
        }
        status, text = http_post_form(
            cfg["token_url"],
            form2,
            headers={"Authorization": f"Basic {basic}"},
        )
        print("exchange(basic) status", status)
        print(text[:500])
    if status >= 400:
        raise SystemExit(f"token exchange failed: {status}")
    try:
        return json.loads(text)
    except Exception:
        # form response
        return dict(urllib.parse.parse_qsl(text))


def copy_db(src: Path) -> Path | None:
    if not src.exists():
        return None
    td = Path(tempfile.mkdtemp(prefix="hist-"))
    dst = td / src.name
    try:
        shutil.copy2(src, dst)
        # chrome wal
        for suf in ("-wal", "-shm", "-journal"):
            side = Path(str(src) + suf)
            if side.exists():
                shutil.copy2(side, td / (src.name + suf))
        return dst
    except Exception:
        return None


def find_codes_in_chrome(since_ts: float) -> list[str]:
    roots = [
        Path.home() / "Library/Application Support/Google/Chrome/Default/History",
        Path.home() / "Library/Application Support/Google/Chrome/Profile 1/History",
        Path.home() / "Library/Application Support/Chromium/Default/History",
        Path.home() / "Library/Application Support/Microsoft Edge/Default/History",
        Path.home() / "Library/Application Support/Arc/User Data/Default/History",
        Path.home() / "Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
    ]
    codes: list[str] = []
    # Chrome stores UTC microseconds since 1601-01-01
    epoch_delta = 11644473600
    chrome_since = int((since_ts + epoch_delta) * 1_000_000)
    for src in roots:
        db = copy_db(src)
        if not db:
            continue
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            cur = con.execute(
                "SELECT url, last_visit_time FROM urls WHERE url LIKE ? AND last_visit_time >= ? ORDER BY last_visit_time DESC LIMIT 20",
                ("%cloudsign.webnotarius.pl/redirect%code=%", chrome_since - 60_000_000),
            )
            for url, ts in cur.fetchall():
                m = re.search(r"[?&]code=([^&]+)", url)
                if m:
                    codes.append(urllib.parse.unquote(m.group(1)))
            con.close()
        except Exception as e:
            print("chrome history read fail", src, e)
    return codes


def find_codes_in_safari(since_ts: float) -> list[str]:
    src = Path.home() / "Library/Safari/History.db"
    db = copy_db(src)
    if not db:
        return []
    codes = []
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        # Safari uses CoreData-ish; try common schema
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        if "history_items" in tables and "history_visits" in tables:
            cur = con.execute(
                """
                SELECT i.url, v.visit_time
                FROM history_items i
                JOIN history_visits v ON v.history_item = i.id
                WHERE i.url LIKE ?
                ORDER BY v.visit_time DESC LIMIT 20
                """,
                ("%cloudsign.webnotarius.pl/redirect%code=%",),
            )
            # Safari visit_time is seconds since 2001-01-01
            safari_epoch = 978307200
            for url, vt in cur.fetchall():
                abs_ts = float(vt) + safari_epoch
                if abs_ts >= since_ts - 60:
                    m = re.search(r"[?&]code=([^&]+)", url)
                    if m:
                        codes.append(urllib.parse.unquote(m.group(1)))
        con.close()
    except Exception as e:
        print("safari history read fail", e)
    return codes


def find_codes_in_simplysign_cache() -> list[str]:
    src = Path.home() / "Library/Caches/pl.ads.SimplySign-Desktop/Cache.db"
    db = copy_db(src)
    if not db:
        return []
    codes = []
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        cur = con.execute(
            "SELECT request_key FROM cfurl_cache_response WHERE request_key LIKE ? ORDER BY entry_ID DESC LIMIT 10",
            ("%redirect/?code=%",),
        )
        for (url,) in cur.fetchall():
            m = re.search(r"[?&]code=([^&]+)", url)
            if m:
                codes.append(urllib.parse.unquote(m.group(1)))
        con.close()
    except Exception as e:
        print("simply cache fail", e)
    return codes


def main() -> int:
    cfg = load_oauth_config()
    if not cfg["client_id"]:
        print("missing client_id in SimplySignDesktop.xml")
        return 1
    auth = build_authorize_url(cfg)
    print("Authorize URL:")
    print(auth)
    print()
    print("Opening browser... Complete OTP login there.")
    print("When finished, either leave the final redirect page open,")
    print("or paste the redirect URL (with code=) here and press Enter.")
    print()
    subprocess.run(["open", auth], check=False)

    since = time.time()
    seen: set[str] = set()
    # preload old codes so we only accept new ones
    for c in find_codes_in_chrome(0) + find_codes_in_safari(0) + find_codes_in_simplysign_cache():
        seen.add(c)
    print(f"ignoring {len(seen)} historical codes; waiting for a NEW code...")

    deadline = time.time() + 600
    code = None
    while time.time() < deadline:
        # non-blocking paste check: if user typed into a file
        paste_file = Path("/tmp/simplysign-oauth-redirect-url.txt")
        if paste_file.exists():
            url = paste_file.read_text(encoding="utf-8", errors="ignore").strip()
            m = re.search(r"[?&]code=([^&\s]+)", url)
            if m:
                c = urllib.parse.unquote(m.group(1))
                if c not in seen:
                    code = c
                    print("got code from paste file")
                    break
        for c in find_codes_in_chrome(since) + find_codes_in_safari(since):
            if c not in seen:
                code = c
                print("got NEW code from browser history")
                break
        if code:
            break
        # also allow interactive stdin if provided as arg --stdin later
        time.sleep(1)
        print(".", end="", flush=True)

    print()
    if not code:
        print("No new code found automatically.")
        print("Paste the final browser URL containing code= then press Enter:")
        try:
            url = input().strip()
        except EOFError:
            url = ""
        m = re.search(r"[?&]code=([^&\s]+)", url)
        if not m:
            print("no code in input")
            return 2
        code = urllib.parse.unquote(m.group(1))

    print("code prefix", code[:12] + "...")
    tok = exchange_code(cfg, code)
    data = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "access_token": tok.get("access_token"),
        "refresh_token": tok.get("refresh_token"),
        "expires_in": tok.get("expires_in"),
        "token_type": tok.get("token_type"),
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "source": "oauth-browser-capture",
        "raw_token_response": tok,
    }
    SESSION.parent.mkdir(parents=True, exist_ok=True)
    SESSION.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(SESSION, 0o600)
    print("SAVED", SESSION)
    print(
        "HAS",
        {
            "access_token": bool(data.get("access_token")),
            "refresh_token": bool(data.get("refresh_token")),
        },
    )
    return 0 if data.get("access_token") or data.get("refresh_token") else 3


if __name__ == "__main__":
    raise SystemExit(main())
