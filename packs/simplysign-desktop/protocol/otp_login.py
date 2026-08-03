#!/usr/bin/env python3
"""SimplySign OTP 登录 → 换取 access_token / refresh_token（纯 HTTP，无浏览器/Desktop）。

目标：为授权的无界面自动化现场走完 CAS + OAuth 授权码流程，
换取短期 token，避免在代码或日志中持久化凭据。

链路（2026-08-03 实测表单结构）：
  1) GET /idp/oauth2.0/authorize?client_id=…&response_type=code&redirect_uri=…
     → 302 /idp/login?service=<encoded callbackAuthorize>
     → 200 登录表单（hidden: execution, _eventId=submit, username, password）
  2) POST /idp/login?service=…  (username=<邮箱>, password=<OTP>, execution=…, _eventId=submit)
     → 302 /idp/oauth2.0/callbackAuthorize?…&ticket=ST-…
     → 302 https://cloudsign.webnotarius.pl/redirect/?code=OC-…
  3) POST /idp/oauth2.0/accessToken
     grant_type=authorization_code&client_id=…&client_secret=…&redirect_uri=…&code=OC-…
     → {access_token, refresh_token, expires_in}

安全：不打印 token；--json 输出脱敏；--write-session 写 600 权限 session.json。
OTP 只存在内存/进程环境，不落盘、不入 secrets 长期保存。
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_AUTHORIZE_URL = "https://cloudsign.webnotarius.pl/idp/oauth2.0/authorize"
DEFAULT_TOKEN_URL = "https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken"
DEFAULT_REDIRECT_URI = "https://cloudsign.webnotarius.pl/redirect"
DEFAULT_CARD_BASE_URL = "https://cloudsign.webnotarius.pl/card/v1/cards"
CREDENTIALS_FILE = (
    Path.home()
    / "Library/Application Support/easy-rev/simplysign-session/client_credentials.json"
)
SESSION_FILE = (
    Path.home()
    / "Library/Application Support/easy-rev/simplysign-session/session.json"
)


def load_credentials(path: Path | None = None) -> dict:
    p = path or CREDENTIALS_FILE
    if not p.exists():
        raise SystemExit(f"缺少 OAuth 客户端配置：{p}")
    data = json.loads(p.read_text())
    for key in ("client_id", "client_secret", "authorize_url", "token_url", "redirect_uri"):
        if not data.get(key):
            raise SystemExit(f"client_credentials.json 缺少 {key}")
    return data


def redact(text: str, max_len: int = 400) -> str:
    masked = re.sub(
        r'"(access_token|refresh_token|client_secret|code|ticket)"\s*:\s*"[^"]*"',
        r'"\1":"<redacted>"',
        text,
    )
    return masked[:max_len] + ("…" if len(masked) > max_len else "")


class OtpLoginClient:
    def __init__(self, cfg: dict):
        self.client_id = cfg["client_id"]
        self.client_secret = cfg["client_secret"]
        self.authorize_url = cfg["authorize_url"]
        self.token_url = cfg["token_url"]
        self.redirect_uri = cfg["redirect_uri"]
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPRedirectHandler(),
        )
        self.ctx = ssl.create_default_context()

    def _open(self, url: str, *, data: bytes | None = None, headers: dict | None = None,
              max_redirects: int = 8) -> tuple[int, str, str]:
        """Manual redirect walk so we can see each hop (code/ticket extraction)."""
        h = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) easy-rev/0.1"}
        h.update(headers or {})
        current = url
        for _ in range(max_redirects):
            req = urllib.request.Request(current, data=data, method="POST" if data else "GET", headers=h)
            try:
                resp = self.opener.open(req, timeout=30)
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                    current = urllib.parse.urljoin(current, e.headers["Location"])
                    data = None  # redirects after POST are GET
                    continue
                err_body = e.read().decode("utf-8", "replace")
                raise RuntimeError(f"HTTP {e.code} on {current}: {redact(err_body, 300)}") from e
            body = resp.read().decode("utf-8", "replace")
            return resp.status, resp.geturl(), body
        raise RuntimeError("redirect loop")

    def login(self, username: str, otp: str, *, scope: str = "") -> dict:
        cb_params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "client_name": "CasOAuthClient",
        }
        if scope:
            cb_params["scope"] = scope
        callback = (
            "https://cloudsign.webnotarius.pl/idp/oauth2.0/callbackAuthorize?"
            + urllib.parse.urlencode(cb_params)
        )

        # 1) authorize → CAS login page
        auth_q = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "client_name": "CasOAuthClient",
        }
        if scope:
            auth_q["scope"] = scope
        status, final_url, body = self._open(
            self.authorize_url + "?" + urllib.parse.urlencode(auth_q)
        )
        if "idp/login" not in final_url:
            raise RuntimeError(f"authorize 未到 CAS 登录页（{final_url}）")
        m = re.search(r'name="execution"\s+value="([^"]+)"', body)
        if not m:
            raise RuntimeError("登录表单缺少 execution 字段")
        execution = m.group(1)
        service = urllib.parse.quote(callback, safe="")
        login_url = "https://cloudsign.webnotarius.pl/idp/login?service=" + service

        # 2) submit username + OTP
        form = urllib.parse.urlencode({
            "username": username,
            "password": otp,
            "execution": execution,
            "_eventId": "submit",
        }).encode()
        status, final_url, body = self._open(
            login_url,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if "code=" not in final_url:
            if "callbackAuthorize" in final_url and "ticket=" in final_url:
                # follow one more hop manually (callbackAuthorize → redirect/?code=)
                status, final_url, body = self._open(final_url)
            else:
                hint = re.search(r'<div[^>]*class="[^"]*error[^"]*"[^>]*>(.*?)</div>', body, re.S)
                detail = re.sub(r"<[^>]+>", "", hint.group(1)).strip()[:200] if hint else body[:200]
                raise RuntimeError(f"登录未返回 code（final={final_url}）: {detail}")
        if "code=" not in final_url:
            raise RuntimeError(f"授权码未出现在回调（final={final_url}）")
        code = urllib.parse.parse_qs(urllib.parse.urlparse(final_url).query)["code"][0]

        # 3) exchange authorization code
        token_form = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "code": code,
        }).encode()
        status, final_url, body = self._open(
            self.token_url,
            data=token_form,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        try:
            payload = json.loads(body)
        except Exception as e:
            raise RuntimeError(f"token 响应不是 JSON（HTTP {status}）: {redact(body, 200)}") from e
        if not payload.get("access_token"):
            raise RuntimeError(f"token 响应缺少 access_token（HTTP {status}）")
        return payload

    def discover_card(self, access_token: str, *, max_polls: int = 20) -> str:
        """POST /card/v1/cards/tasks → poll → 返回 Code Signing 卡号（2026-08-03 实测）。"""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "bond-007",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(
            DEFAULT_CARD_BASE_URL + "/tasks",
            data=b"{}",
            method="POST",
            headers=headers,
        )
        with self.opener.open(req, timeout=30) as resp:
            task = json.loads(resp.read().decode())
        link = str(task.get("atom:link") or "").replace(":443", "")
        if not link:
            raise RuntimeError("cards 任务缺少 atom:link")
        for _ in range(max_polls):
            import time

            time.sleep(1.0)
            req = urllib.request.Request(link, headers=headers)
            with self.opener.open(req, timeout=30) as resp:
                obj = json.loads(resp.read().decode())
            if isinstance(obj, dict) and obj.get("state") == "pending":
                continue
            cards = obj if isinstance(obj, list) else obj.get("cards", [])
            for card in cards:
                label = str(card.get("label", ""))
                cardno = str(card.get("cardno", ""))
                if "code signing" in label.lower() and cardno:
                    return cardno
            if cards:
                return str(cards[0].get("cardno", ""))
        raise RuntimeError("cards 任务超时")


def main() -> int:
    ap = argparse.ArgumentParser(description="SimplySign OTP 登录换 token")
    ap.add_argument("--username", default=None, help="Certum 登录邮箱")
    ap.add_argument("--otp", default=None, help="当前 6 位 OTP（也可用 SIMPLYSIGN_OTP）")
    ap.add_argument("--credentials", default=str(CREDENTIALS_FILE))
    ap.add_argument("--write-session", action="store_true", help="写 session.json（600）")
    ap.add_argument("--json", action="store_true", help="输出脱敏 JSON")
    ap.add_argument("--probe", action="store_true", help="只读：检查 authorize→登录页表单结构")
    ap.add_argument("--discover-card", action="store_true", help="登录后自动发现 Code Signing card_id 并写入 session")
    args = ap.parse_args()

    import os

    cfg = load_credentials(Path(args.credentials))
    client = OtpLoginClient(cfg)

    if args.probe:
        try:
            status, final_url, body = client._open(
                cfg["authorize_url"]
                + "?"
                + urllib.parse.urlencode({
                    "client_id": cfg["client_id"],
                    "response_type": "code",
                    "redirect_uri": cfg["redirect_uri"],
                    "client_name": "CasOAuthClient",
                })
            )
            has_execution = 'name="execution"' in body
            has_lt = 'name="lt"' in body
            print(json.dumps({
                "ok": True,
                "status": status,
                "login_page": "idp/login" in final_url,
                "has_execution": has_execution,
                "has_lt": has_lt,
                "needs_otp_submit": has_execution,
            }, ensure_ascii=False))
            return 0 if ("idp/login" in final_url and has_execution) else 1
        except Exception as e:
            print(f"probe 失败：{e}", file=sys.stderr)
            return 2

    username = args.username or os.environ.get("SIMPLYSIGN_USERNAME")
    otp = args.otp or os.environ.get("SIMPLYSIGN_OTP")
    if not username:
        raise SystemExit("需要 --username（Certum 登录邮箱）")
    if not otp:
        raise SystemExit("需要 --otp（当前 6 位验证码，用 SIMPLYSIGN_OTP 传入避免进 shell 历史）")

    try:
        payload = client.login(username, otp)
    except Exception as e:
        print(f"OTP 登录失败：{e}", file=sys.stderr)
        return 2

    card_id = os.environ.get("SIMPLYSIGN_CARD_ID", "")
    if args.discover_card:
        try:
            card_id = client.discover_card(payload["access_token"])
        except Exception as e:
            print(f"卡片发现失败：{e}", file=sys.stderr)
            return 2

    if args.write_session:
        session = {
            "access_token": payload.get("access_token"),
            "refresh_token": payload.get("refresh_token"),
            "expires_in": payload.get("expires_in"),
            "token_type": payload.get("token_type") or "Bearer",
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "card_id": card_id,
            "last_login": "otp",
        }
        SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        SESSION_FILE.write_text(json.dumps(session, ensure_ascii=False, indent=2))
        SESSION_FILE.chmod(0o600)

    if args.json:
        out = {
            "ok": True,
            "access_token": "issued" if payload.get("access_token") else None,
            "refresh_token": "issued" if payload.get("refresh_token") else None,
            "expires_in": payload.get("expires_in"),
            "card_id": card_id,
            "session_file": str(SESSION_FILE) if args.write_session else None,
        }
        print(json.dumps(out, ensure_ascii=False))
    else:
        print("login ok: access_token", "issued" if payload.get("access_token") else "missing")
        print("login ok: refresh_token", "issued" if payload.get("refresh_token") else "missing")
        print("expires_in", payload.get("expires_in"))
        if args.write_session:
            print("session written:", SESSION_FILE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
