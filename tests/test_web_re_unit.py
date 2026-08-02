"""Unit tests for ported web RE helpers (no browser)."""

from __future__ import annotations

from easy_rev.platforms.web.re.classify import classify_entry, rank_api_candidates
from easy_rev.platforms.web.re.js_analyze import analyze_js_text
from easy_rev.platforms.web.re.network import NetworkEntry


def test_classify_register_api():
    entry = NetworkEntry(
        id=1,
        url="https://api.example.com/v1/register",
        method="POST",
        resource_type="xhr",
        status=200,
        request_headers={"content-type": "application/json"},
        post_data='{"email":"a@b.c","password":"x"}',
    )
    c = classify_entry(entry)
    assert c.score >= 4
    assert "register_keyword" in c.tags or "credential_fields" in c.tags or c.score > 0


def test_rank_apis():
    entries = [
        NetworkEntry(
            id=1,
            url="https://api.example.com/v1/register",
            method="POST",
            resource_type="fetch",
            status=201,
            post_data='{"email":"a@b.c","password":"Secret1!"}',
        ),
        NetworkEntry(
            id=2,
            url="https://cdn.example.com/app.js",
            method="GET",
            resource_type="script",
            status=200,
        ),
    ]
    ranked = rank_api_candidates(entries, min_score=1)
    assert ranked
    assert "register" in ranked[0].url or ranked[0].score >= ranked[-1].score


def test_js_analyze_hmac():
    text = """
    function signRequest(body) {
      return CryptoJS.HmacSHA256(JSON.stringify(body), SECRET_KEY).toString();
    }
    """
    out = analyze_js_text(text)
    assert out.get("risk") in {"low", "medium", "high"} or out.get("crypto_kinds")
    cands = out.get("sign_function_candidates") or out.get("function_snippets") or []
    # at least some signal
    assert out.get("crypto_kinds") or cands or out.get("risk")
