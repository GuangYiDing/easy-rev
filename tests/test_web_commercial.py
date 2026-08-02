"""Web commercial RE path: classify, JS risk, graph, pack.from_capture, bridge status."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from easy_rev.ai.handlers import call_tool
from easy_rev.platforms.web.re.classify import classify_entry, rank_api_candidates
from easy_rev.platforms.web.re.dependency_graph import smart_suggest_http_steps
from easy_rev.platforms.web.re.draft_protocol import write_protocol_pack
from easy_rev.platforms.web.re.extension_bridge import bridge_status, start_bridge, stop_bridge
from easy_rev.platforms.web.re.js_analyze import analyze_js_text
from easy_rev.platforms.web.re.network import NetworkEntry


def test_js_analyze_hmac_sign_signals():
    text = """
    const SECRET = 'app_secret_value';
    async function signRequest(body) {
      return CryptoJS.HmacSHA256(JSON.stringify(body), SECRET).toString();
    }
    fetch('/api/v1/register', { method: 'POST', body: JSON.stringify({email:'a'}) });
    """
    out = analyze_js_text(text)
    assert out.get("risk") in {"low", "medium", "high"} or out.get("crypto_kinds")
    kinds = out.get("crypto_kinds") or []
    # must surface hmac/sign-ish signal
    assert kinds or out.get("sign_function_candidates") or out.get("findings")


def test_classify_and_rank_registration_api():
    entries = [
        NetworkEntry(
            id=1,
            method="POST",
            url="https://api.example.com/v1/register",
            resource_type="xhr",
            status=201,
            request_headers={"content-type": "application/json"},
            post_data='{"email":"a@b.c","password":"Secret1!"}',
            content_type="application/json",
        ),
        NetworkEntry(
            id=2,
            method="GET",
            url="https://cdn.example.com/static/app.js",
            resource_type="script",
            status=200,
        ),
    ]
    c = classify_entry(entries[0])
    assert c.score >= 4
    ranked = rank_api_candidates(entries, min_score=1)
    assert ranked
    assert "register" in ranked[0].url


def test_dependency_graph_suggests_steps():
    apis = [
        {
            "method": "GET",
            "url": "https://api.example.com/v1/csrf",
            "score": 8,
            "tags": ["api_path", "csrf"],
            "post_data": None,
            "response_body": '{"token":"abc"}',
            "status": 200,
        },
        {
            "method": "POST",
            "url": "https://api.example.com/v1/register",
            "score": 12,
            "tags": ["register_keyword", "credential_fields", "json"],
            "post_data": '{"email":"a@b.c","password":"x","csrf":"abc"}',
            "status": 201,
        },
    ]
    out = smart_suggest_http_steps(apis, min_score=3)
    assert out["mode"] == "dependency_graph"
    assert out["steps"]
    assert out.get("graph")


def test_write_protocol_pack_from_capture(tmp_path: Path):
    cap = tmp_path / "capture.json"
    cap.write_text(
        json.dumps(
            {
                "url": "https://example.com/signup",
                "apis": [
                    {
                        "method": "POST",
                        "url": "https://api.example.com/v1/register",
                        "score": 12,
                        "tags": ["register_keyword", "json", "credential_fields"],
                        "post_data": '{"email":"a@b.c","password":"x"}',
                        "request_headers": {"content-type": "application/json"},
                        "status": 201,
                    }
                ],
                "auto_sign": {
                    "mode": "browser_oracle",
                    "best_signer": "signRequest",
                },
                "signing": {"sig_headers": ["x-signature"], "recommendations": ["use oracle"]},
            }
        ),
        encoding="utf-8",
    )
    dest = tmp_path / "proto-pack"
    out = write_protocol_pack(
        pack_path=dest,
        pack_id="proto-pack",
        capture_path=cap,
        hybrid=True,
    )
    assert dest.joinpath("pack.yaml").is_file()
    assert dest.joinpath("flow.yaml").is_file()
    flow = dest.joinpath("flow.yaml").read_text(encoding="utf-8")
    assert "http.request" in flow or "register" in flow.lower() or "api.example.com" in flow
    assert isinstance(out, dict)


@pytest.mark.asyncio
async def test_ai_pack_from_capture_and_analyze_js(tmp_path: Path):
    cap = tmp_path / "c.json"
    cap.write_text(
        json.dumps(
            {
                "url": "https://ex.test/signup",
                "apis": [
                    {
                        "method": "POST",
                        "url": "https://api.ex.test/reg",
                        "score": 10,
                        "tags": ["register_keyword"],
                        "post_data": '{"email":"a"}',
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    dest = tmp_path / "from-ai"
    r = await call_tool(
        "pack.from_capture",
        {"capture_path": str(cap), "pack_id": "from-ai", "dest": str(dest)},
    )
    assert r["ok"] is True
    assert dest.joinpath("pack.yaml").is_file()

    js = await call_tool(
        "web.analyze_js",
        {"text": "function signRequest(b){return CryptoJS.HmacSHA256(b,k)}"},
    )
    assert js["ok"] is True
    assert js.get("risk") or js.get("crypto_kinds") or js.get("findings")


@pytest.mark.asyncio
async def test_bridge_start_status_stop():
    started = await call_tool("web.bridge.start", {"host": "127.0.0.1", "port": 0})
    # port 0 may not bind as 0 on ThreadingHTTPServer the same way — use high port
    stop_bridge()
    started = start_bridge(host="127.0.0.1", port=18776, blocking=False)
    assert started.get("ok") is True
    st = bridge_status()
    assert st.get("running") is True
    assert st.get("port")
    stopped = stop_bridge()
    assert stopped.get("ok") is True
    st2 = bridge_status()
    assert st2.get("running") is False


@pytest.mark.asyncio
async def test_web_dependency_graph_tool():
    r = await call_tool(
        "web.dependency_graph",
        {
            "apis": [
                {
                    "method": "POST",
                    "url": "https://api.example.com/v1/register",
                    "score": 11,
                    "tags": ["register_keyword"],
                    "post_data": '{"email":"a"}',
                }
            ]
        },
    )
    assert r["ok"] is True
    assert r.get("steps") is not None or r.get("api_count") == 1
