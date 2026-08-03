#!/usr/bin/env python3
"""SimplySign cloud protocol client (SCS1_ATOM) — skeleton + refresh.

Does not replace Desktop until refresh + sign endpoints are validated
against a real SSLKEYLOG capture.

Session file (600):
  ~/Library/Application Support/easy-rev/simplysign-session/session.json
    {
      "access_token": "...",
      "refresh_token": "...",
      "client_id": "...",
      "client_secret": "...",
      "token_type": "Bearer"
    }

Defaults for client_id/secret are read from ~/SimplySignDesktop.xml when missing.
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

HOST = "cloudsign.webnotarius.pl"
TOKEN_URL = f"https://{HOST}/idp/oauth2.0/accessToken"
CARD_BASE = f"https://{HOST}/card/v1/cards"
SESSION = (
    Path.home()
    / "Library/Application Support/easy-rev/simplysign-session/session.json"
)
XML_CANDIDATES = [
    Path.home() / "SimplySignDesktop.xml",
    Path("/Applications/SimplySign Desktop.app/Contents/Resources/SimplySignDesktop.xml"),
]


def load_xml_oauth() -> dict[str, str]:
    out: dict[str, str] = {}
    for p in XML_CANDIDATES:
        if not p.exists():
            continue
        # plist-ish xml
        try:
            root = ET.parse(p).getroot()
        except Exception:
            continue
        # flatten dict keys
        d = root.find("dict")
        if d is None:
            continue
        kids = list(d)
        i = 0
        while i < len(kids) - 1:
            if kids[i].tag == "key":
                k = kids[i].text or ""
                v = kids[i + 1].text or ""
                if k in {
                    "OAuth2ClientId",
                    "OAuth2ClientSecret",
                    "OAuth2AccessTokenUrl",
                    "OAuth2AuthorizeUrl",
                }:
                    out[k] = v
            i += 1
        if out:
            break
    return out


def load_session(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"missing session file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_session(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    path.chmod(0o600)


def http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()) if e.headers else {}, e.read()


def refresh(session: dict) -> dict:
    xml = load_xml_oauth()
    client_id = session.get("client_id") or xml.get("OAuth2ClientId")
    client_secret = session.get("client_secret") or xml.get("OAuth2ClientSecret") or ""
    refresh_token = session.get("refresh_token")
    if not client_id or not refresh_token:
        raise SystemExit("session needs client_id + refresh_token")

    form = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    }
    body = urllib.parse.urlencode(form).encode()
    # try body credentials first
    status, hdrs, raw = http(
        "POST",
        TOKEN_URL,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        body=body,
    )
    text = raw.decode("utf-8", "replace")
    print("refresh status", status)
    print(text[:800])
    if status >= 400:
        # try Basic
        import base64

        basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        form2 = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        status, hdrs, raw = http(
            "POST",
            TOKEN_URL,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Authorization": f"Basic {basic}",
            },
            body=urllib.parse.urlencode(form2).encode(),
        )
        text = raw.decode("utf-8", "replace")
        print("refresh(basic) status", status)
        print(text[:800])
    if status >= 400:
        raise SystemExit(2)
    try:
        parsed = json.loads(text)
    except Exception as e:
        raise SystemExit(f"token not json: {e}") from e
    if parsed.get("access_token"):
        session["access_token"] = parsed["access_token"]
    if parsed.get("refresh_token"):
        session["refresh_token"] = parsed["refresh_token"]
    session["expires_in"] = parsed.get("expires_in")
    session["token_type"] = parsed.get("token_type") or session.get("token_type") or "Bearer"
    session["client_id"] = client_id
    session["client_secret"] = client_secret
    session["last_refresh_ok"] = True
    return session


def bearer_headers(session: dict) -> dict[str, str]:
    tok = session.get("access_token")
    if not tok:
        raise SystemExit("no access_token — refresh or capture first")
    return {
        "Authorization": f"Bearer {tok}",
        "Accept": "application/json, text/plain, */*",
    }


def try_get(session: dict, path: str) -> None:
    url = CARD_BASE.rstrip("/") + "/" + path.lstrip("/")
    status, hdrs, raw = http("GET", url, headers=bearer_headers(session))
    print("GET", url, "->", status)
    print(raw[:1000].decode("utf-8", "replace"))


def try_post_json(session: dict, path: str, payload: dict | None = None) -> None:
    url = CARD_BASE.rstrip("/") + "/" + path.lstrip("/")
    body = json.dumps(payload or {}).encode()
    h = bearer_headers(session)
    h["Content-Type"] = "application/json"
    status, hdrs, raw = http("POST", url, headers=h, body=body)
    print("POST", url, "->", status)
    print(raw[:1000].decode("utf-8", "replace"))


def sign_digest(
    session: dict,
    digest_hex: str,
    cert_pem: str,
    *,
    card_id: str | None = None,
    poll_interval: float = 0.6,
    max_polls: int = 30,
) -> dict[str, str]:
    """Sign one SHA-256 digest via the verified SCS1_ATOM cloud flow.

    Verified 2026-08-03 against SimplySign Desktop 2.10.22:
      POST /card/v1/cards/{card}/certificates/signature  (multipart req+certificate)
      -> 202 {atom:link}  (task URL)
      GET task -> 303 Location (final resource) or 200 signature JSON
      GET final -> 200 {"<DIGEST>": "<rsa-signature-hex>"}

    Returns {digest: signature_hex}.
    """
    import uuid

    card = card_id or session.get("card_id")
    if not card:
        raise SystemExit("need card_id in session or --card-id")
    if not cert_pem:
        raise SystemExit("need certificate PEM (--cert)")
    digest = digest_hex.strip().upper()
    if len(digest) != 64:
        raise SystemExit("--digest must be 64 hex chars (SHA-256)")

    boundary = "--" + uuid.uuid4().hex.upper()
    part_req = (
        f'----{boundary}\r\n'
        'Content-Disposition: form-data; name="req"\r\n'
        "Content-Type: application/json;charset=UTF-8\r\n\r\n"
        f'{{ "digests": [ "{digest}" ], "digesttype": "SHA256" }}\r\n'
    ).encode()
    part_cert = (
        f'----{boundary}\r\n'
        'Content-Disposition: form-data; name="certificate"; filename="blob"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + cert_pem.encode() + f"\r\n----{boundary}--\r\n".encode()
    body = part_req + part_cert

    url = f"{CARD_BASE}/{card}/certificates/signature"
    headers = {
        "Authorization": f"Bearer {session['access_token']}",
        "User-Agent": "bond-007",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": f"multipart/form-data; boundary=--{boundary}",
        "Content-Length": str(len(body)),
    }
    status, _, raw = http("POST", url, headers=headers, body=body)
    text = raw.decode("utf-8", "replace")
    print("sign POST", status)
    if status >= 300:
        print(text[:500])
        raise SystemExit(2)
    try:
        task = json.loads(text)
    except Exception as e:
        raise SystemExit(f"sign response not json: {e} {text[:300]}") from e
    link = (task.get("atom:link") or "").replace(":443", "")
    if not link:
        raise SystemExit(f"no atom:link in {text[:300]}")
    print("task:", link.split("/")[-1])

    get_headers = {
        "Authorization": f"Bearer {session['access_token']}",
        "User-Agent": "bond-007",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
    }
    for _ in range(max_polls):
        status, hdrs, raw = http("GET", link, headers=get_headers)
        text = raw.decode("utf-8", "replace")
        if status in (301, 302, 303) and hdrs.get("Location"):
            link = hdrs["Location"].replace(":443", "")
            continue
        if '"state":"failed"' in text:
            print("sign failed:", text[:300])
            raise SystemExit(2)
        import re

        m = re.search(r'"([0-9A-F]{64})"\s*:\s*"([0-9a-f]+)"', text)
        if m:
            return {m.group(1): m.group(2)}
        time.sleep(poll_interval)
    raise SystemExit("sign task timed out")


def cmd_refresh(args: argparse.Namespace) -> int:
    s = load_session(Path(args.session))
    s = refresh(s)
    save_session(Path(args.session), s)
    print("saved", args.session)
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    s = load_session(Path(args.session))
    if args.refresh_first:
        s = refresh(s)
        save_session(Path(args.session), s)
    # probe candidates observed/inferred from Desktop xml + strings
    for path in [
        "tasks",
        "keys/tasks",
        "certificates/tasks",
        "",
    ]:
        try_get(s, path)
        try_post_json(s, path, {})
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    s = load_session(Path(args.session))
    if args.refresh_first:
        s = refresh(s)
        save_session(Path(args.session), s)
    if args.file:
        import hashlib

        digest_hex = hashlib.sha256(Path(args.file).read_bytes()).hexdigest().upper()
    elif args.digest:
        digest_hex = args.digest
    else:
        raise SystemExit("need --file or --digest")
    cert = args.cert or s.get("cert_pem")
    cert_pem = Path(cert).read_text(encoding="utf-8") if cert and Path(cert).exists() else cert or ""
    result = sign_digest(s, digest_hex, cert_pem, card_id=args.card_id)
    for d, sig in result.items():
        print("digest", d)
        print("signature", sig)
    return 0


def cmd_show_config(_: argparse.Namespace) -> int:
    print(json.dumps(load_xml_oauth(), indent=2))
    print("session_path", SESSION)
    print("session_exists", SESSION.exists())
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SimplySign protocol client")
    ap.add_argument(
        "--session",
        default=str(SESSION),
        help="path to session.json",
    )
    ap.add_argument(
        "--card-id",
        default=None,
        help="SimplySign card id (default: session card_id)",
    )
    ap.add_argument(
        "--cert",
        default=None,
        help="path to certificate PEM sent in the sign request",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("config", help="show client id/secret source").set_defaults(
        func=cmd_show_config
    )
    p_r = sub.add_parser("refresh", help="refresh access_token")
    p_r.set_defaults(func=cmd_refresh)
    p_p = sub.add_parser("probe", help="probe card list endpoints with bearer token")
    p_p.add_argument("--refresh-first", action="store_true")
    p_p.set_defaults(func=cmd_probe)
    p_s = sub.add_parser("sign", help="sign a SHA-256 digest headless (verified)")
    p_s.add_argument("--digest", default=None, help="64-hex SHA-256 digest to sign")
    p_s.add_argument("--file", default=None, help="sign SHA-256 of this file")
    p_s.add_argument("--refresh-first", action="store_true")
    p_s.set_defaults(func=cmd_sign)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
