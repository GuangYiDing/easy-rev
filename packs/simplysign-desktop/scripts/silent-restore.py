#!/usr/bin/env python3
"""After session.json exists: refresh access_token without OTP and keep PKCS usable.

Phase 1: validate refresh_token against Certum IDP.
Phase 2: (next) inject into debug Desktop / headless sign API.
"""
from __future__ import annotations

import json
import re
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

SESSION = Path.home() / "Library/Application Support/easy-rev/simplysign-session/session.json"
TOKEN_URL = "https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken"
# fallback public client_id observed in OAuth authorize URL cache
DEFAULT_CLIENT_ID = "44rvDKKEWY53a7xBeF5w"


def redact(text: str, max_len: int = 400) -> str:
    masked = re.sub(
        r'"(access_token|refresh_token|client_secret)"\s*:\s*"[^"]*"',
        r'"\1":"<redacted>"',
        text,
    )
    return masked[:max_len] + ("…" if len(masked) > max_len else "")


def main() -> int:
    if not SESSION.exists():
        print("no session file; run capture-oauth-once.sh first")
        return 1
    data = json.loads(SESSION.read_text())
    refresh = data.get("refresh_token")
    client_id = data.get("client_id") or DEFAULT_CLIENT_ID
    client_secret = data.get("client_secret") or ""
    if not refresh:
        print("session.json missing refresh_token")
        return 1

    body = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh,
    }
    if client_secret:
        body["client_secret"] = client_secret

    req = urllib.request.Request(
        TOKEN_URL,
        data=urllib.parse.urlencode(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            raw = resp.read().decode()
            print("refresh status", resp.status)
            print(redact(raw))
            parsed = json.loads(raw) if raw.startswith("{") else {}
            # CAS-style may return form
    except Exception as e:
        err = getattr(e, "read", lambda: b"")()
        try:
            err = err.decode()
        except Exception:
            err = str(err)
        print("refresh FAILED:", e)
        print(redact(err, 800))
        print("若 refresh 被拒，说明云端仍要求交互 OTP，无法纯静默续期。")
        return 2

    # update session
    if isinstance(parsed, dict) and parsed.get("access_token"):
        data["access_token"] = parsed.get("access_token")
        if parsed.get("refresh_token"):
            data["refresh_token"] = parsed.get("refresh_token")
        data["expires_in"] = parsed.get("expires_in")
        data["last_refresh_ok"] = True
        SESSION.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        print("session updated with new access_token")
        return 0
    print("unexpected token response shape; saved raw for analysis")
    (SESSION.parent / "last_refresh_response.txt").write_text(raw)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
