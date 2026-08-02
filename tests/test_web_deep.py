"""Web deepest offline RE chain: classify→graph→pack→sign_synth→diff."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.platforms.web.re.diff_capture import diff_captures
from easy_rev.platforms.web.re.sign_synth import (
    analyze_crypto_events,
    synthesize_sign_request_python,
)


def _hmac_hex(key: str, msg: str) -> str:
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


def test_sign_synth_recoverable_hmac():
    key = "app_secret_value"
    msg = '{"email":"a@b.c"}'
    digest = _hmac_hex(key, msg)
    events = [
        {
            "api": "CryptoJS.HmacSHA256",
            "key": key,
            "message": msg,
            "result": digest,
        }
    ]
    analysis = analyze_crypto_events(events)
    assert analysis["confidence"] in {"high", "medium"}
    assert analysis["recoverable"]
    assert analysis["recoverable"][0]["kind"] == "hmac"
    code = synthesize_sign_request_python(analysis)
    assert code
    assert "hmac" in code.lower() or "HMAC" in code or "sha256" in code.lower()
    assert key in code or "sign_request" in code


def test_diff_captures_body_and_apis(tmp_path: Path):
    a = {
        "url": "https://ex.test/a",
        "apis": [
            {
                "method": "POST",
                "url": "https://api.ex.test/v1/register",
                "status": 201,
                "post_data": '{"email":"a","nonce":"111"}',
                "request_headers": {"x-signature": "aaa", "content-type": "application/json"},
            }
        ],
        "signing": {"sig_headers": ["x-signature"]},
        "js_analysis": {"risk": "medium"},
    }
    b = {
        "url": "https://ex.test/b",
        "apis": [
            {
                "method": "POST",
                "url": "https://api.ex.test/v1/register",
                "status": 201,
                "post_data": '{"email":"a","nonce":"222","ts":1}',
                "request_headers": {"x-signature": "bbb", "content-type": "application/json"},
            },
            {
                "method": "GET",
                "url": "https://api.ex.test/v1/csrf",
                "status": 200,
            },
        ],
        "signing": {"sig_headers": ["x-signature", "x-ts"]},
        "js_analysis": {"risk": "high"},
    }
    d = diff_captures(a, b)
    assert "POST /v1/register" in "\n".join(
        [c.get("api", "") for c in d["apis"]["changed"]]
    ) or d["apis"]["changed"]
    assert any("csrf" in x.lower() for x in d["apis"]["added"])
    assert d["suggestions"]

    pa = tmp_path / "a.json"
    pb = tmp_path / "b.json"
    pa.write_text(json.dumps(a), encoding="utf-8")
    pb.write_text(json.dumps(b), encoding="utf-8")
    d2 = diff_captures(pa, pb)
    assert d2["apis"]["count_b"] == 2


@pytest.mark.asyncio
async def test_ai_sign_synth_and_diff(tmp_path: Path):
    key = "k"
    msg = "body"
    digest = _hmac_hex(key, msg)
    r = await call_tool(
        "web.sign_synth",
        {
            "events": [
                {"api": "CryptoJS.HmacSHA256", "key": key, "message": msg, "result": digest}
            ]
        },
    )
    assert r["ok"] is True
    assert r.get("confidence") in {"high", "medium"} or (r.get("analysis") or {}).get(
        "confidence"
    )
    assert r.get("sign_request_python") or (r.get("recoverable") or r.get("analysis"))

    a = tmp_path / "ca.json"
    b = tmp_path / "cb.json"
    a.write_text(
        json.dumps(
            {
                "apis": [
                    {
                        "method": "GET",
                        "url": "https://api.x/v1/a",
                        "status": 200,
                        "post_data": None,
                        "request_headers": {},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    b.write_text(
        json.dumps(
            {
                "apis": [
                    {
                        "method": "GET",
                        "url": "https://api.x/v1/a",
                        "status": 200,
                        "post_data": None,
                        "request_headers": {},
                    },
                    {
                        "method": "POST",
                        "url": "https://api.x/v1/b",
                        "status": 201,
                        "post_data": "{}",
                        "request_headers": {},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    d = await call_tool("web.diff_capture", {"a_path": str(a), "b_path": str(b)})
    assert d["ok"] is True
    assert d["apis"]["added"] or d["apis"]["count_b"] == 2


@pytest.mark.asyncio
async def test_offline_chain_full(tmp_path: Path):
    cap = {
        "url": "https://ex.test/signup",
        "apis": [
            {
                "method": "GET",
                "url": "https://api.ex.test/v1/csrf",
                "score": 8,
                "tags": ["csrf", "api_path"],
                "status": 200,
                "response_body": '{"token":"abc"}',
                "request_headers": {},
            },
            {
                "method": "POST",
                "url": "https://api.ex.test/v1/register",
                "score": 12,
                "tags": ["register_keyword", "credential_fields", "json"],
                "post_data": '{"email":"a@b.c","password":"x","csrf":"abc"}',
                "status": 201,
                "request_headers": {"content-type": "application/json", "x-signature": "dead"},
            },
        ],
        "crypto_events": [
            {
                "api": "CryptoJS.HmacSHA256",
                "key": "sec",
                "message": '{"email":"a@b.c"}',
                "result": _hmac_hex("sec", '{"email":"a@b.c"}'),
            }
        ],
        "auto_sign": {"mode": "browser_oracle", "best_signer": "signRequest"},
        "signing": {"sig_headers": ["x-signature"]},
    }
    dest = tmp_path / "offline-pack"
    r = await call_tool(
        "web.offline_chain",
        {
            "capture": cap,
            "pack_id": "offline-pack",
            "dest": str(dest),
            "write_pack": True,
            "min_score": 1,
        },
    )
    assert r["ok"] is True
    assert r.get("classified_count", 0) >= 2
    graph = r.get("graph") or {}
    assert graph.get("steps") is not None or graph.get("mode") or graph.get("graph")
    assert dest.joinpath("pack.yaml").is_file()
    assert dest.joinpath("flow.yaml").is_file() or any(dest.iterdir())
    assert r.get("sign") is None or r["sign"].get("analysis") or r["sign"].get(
        "sign_request_python"
    )


@pytest.mark.asyncio
async def test_scripts_load_source():
    d = await call_tool("desktop.scripts", {"name": "module_enum.js"})
    assert d["ok"] is True
    assert d.get("source") and "enumerateModules" in d["source"]
    m = await call_tool("mobile.scripts", {"name": "ios_ssl"})
    assert m["ok"] is True
    assert m.get("source") and len(m["source"]) > 50
