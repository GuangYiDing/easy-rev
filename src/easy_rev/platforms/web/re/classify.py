"""Score and tag network entries as API / registration candidates."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from easy_rev.platforms.web.re.network import NetworkEntry

# Path / URL heuristics for signup / auth APIs
_API_PATH_RE = re.compile(
    r"(/api[/\w.-]*|"
    r"/v\d+/|"
    r"/graphql|"
    r"/auth|"
    r"/oauth|"
    r"/register|"
    r"/signup|"
    r"/sign-up|"
    r"/create[-_]?account|"
    r"/users?(?:/|$)|"
    r"/accounts?(?:/|$)|"
    r"/session|"
    r"/login|"
    r"/verify|"
    r"/otp|"
    r"/sms|"
    r"/phone|"
    r"/captcha|"
    r"/challenge)",
    re.I,
)

_REG_KEYWORDS = re.compile(
    r"(register|signup|sign[_-]?up|create[_-]?account|enrol+|"
    r"verify|otp|sms[_-]?code|phone[_-]?number|activation)",
    re.I,
)


def classify_entry(entry: NetworkEntry) -> NetworkEntry:
    """Mutate entry with score / tags / api_summary. Idempotent."""
    tags: list[str] = []
    score = 0
    url = entry.url or ""
    method = (entry.method or "GET").upper()
    rt = (entry.resource_type or "").lower()
    ct = (entry.content_type or "").lower()
    path = ""
    try:
        path = urlparse(url).path or ""
    except Exception:  # noqa: BLE001
        path = url

    # Transport / type
    if rt in {"xhr", "fetch"}:
        score += 4
        tags.append("xhr_fetch")
    elif rt == "websocket":
        score += 3
        tags.append("websocket")
    elif rt == "document":
        score += 1
        tags.append("document")

    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 3
        tags.append(f"method_{method.lower()}")
    elif method == "OPTIONS":
        score -= 2
        tags.append("cors_preflight")

    # Content types
    if "json" in ct:
        score += 3
        tags.append("json")
    if "graphql" in ct or "graphql" in url.lower():
        score += 4
        tags.append("graphql")
    if "x-www-form-urlencoded" in ct or "form-data" in ct or "multipart" in ct:
        score += 2
        tags.append("form_body")

    # URL path heuristics
    if _API_PATH_RE.search(url) or _API_PATH_RE.search(path):
        score += 3
        tags.append("api_path")
    if _REG_KEYWORDS.search(url):
        score += 4
        tags.append("register_keyword")

    # Body / post data
    body_blob = " ".join(filter(None, [entry.post_data or "", entry.response_body or ""]))
    if entry.post_data:
        score += 1
        if _looks_json(entry.post_data):
            score += 2
            tags.append("json_request")
        if _REG_KEYWORDS.search(entry.post_data):
            score += 3
            tags.append("register_body")
        if re.search(r"(email|password|username|phone|mobile)", entry.post_data, re.I):
            score += 3
            tags.append("credential_fields")

    if entry.response_body and _looks_json(entry.response_body):
        score += 1
        tags.append("json_response")

    # Status signals
    if entry.status is not None:
        if 200 <= entry.status < 300:
            score += 1
        elif entry.status in {401, 403, 422, 429}:
            score += 2
            tags.append("auth_or_validation_status")
        elif entry.status >= 500:
            tags.append("server_error")

    if entry.failed:
        tags.append("failed")

    # Auth headers
    for hk in entry.request_headers:
        hkl = hk.lower()
        if hkl in {"authorization", "x-csrf-token", "x-xsrf-token", "x-api-key"}:
            score += 2
            tags.append("auth_header")
            break

    # Deduplicate tags
    seen: set[str] = set()
    uniq_tags: list[str] = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            uniq_tags.append(t)

    entry.score = max(0, score)
    entry.tags = uniq_tags
    entry.api_summary = _summarize(entry, body_blob)
    return entry


def _looks_json(text: str) -> bool:
    s = text.strip()
    if not s or s[0] not in "{[":
        return False
    try:
        json.loads(s)
        return True
    except Exception:  # noqa: BLE001
        return False


def _summarize(entry: NetworkEntry, body_blob: str) -> str:
    host = ""
    path = entry.url
    try:
        p = urlparse(entry.url)
        host = p.netloc
        path = p.path
        if p.query:
            path += "?" + p.query[:80]
    except Exception:  # noqa: BLE001
        pass
    bits = [f"{entry.method} {path}"]
    if entry.status is not None:
        bits.append(f"→ {entry.status}")
    if "register_keyword" in entry.tags or "credential_fields" in entry.tags:
        bits.append("[signup-related]")
    if "graphql" in entry.tags:
        bits.append("[graphql]")
    if host:
        bits.append(f"@{host}")
    return " ".join(bits)


def rank_api_candidates(
    entries: list[NetworkEntry],
    *,
    min_score: int = 4,
    limit: int = 40,
) -> list[NetworkEntry]:
    """Return highest-scoring API-like entries."""
    scored: list[NetworkEntry] = []
    for e in entries:
        classify_entry(e)
        if e.score >= min_score:
            scored.append(e)
    scored.sort(key=lambda e: (-e.score, e.id))
    return scored[:limit]


def api_candidates_as_dicts(
    entries: list[NetworkEntry],
    *,
    min_score: int = 4,
    limit: int = 40,
    redact_secrets: bool = True,
    include_body: bool = True,
) -> list[dict[str, Any]]:
    ranked = rank_api_candidates(entries, min_score=min_score, limit=limit)
    return [
        {
            **e.to_dict(redact_secrets=redact_secrets, include_body=include_body),
            "why": e.tags,
            "summary": e.api_summary,
        }
        for e in ranked
    ]


def suggest_http_steps(apis: list[dict[str, Any]], *, max_steps: int = 8) -> list[dict[str, Any]]:
    """Turn top API candidates into draft flow steps (dependency-aware when possible)."""
    try:
        from easy_rev.platforms.web.re.dependency_graph import smart_suggest_http_steps

        smart = smart_suggest_http_steps(apis, max_steps=max_steps, use_browser_cookies=True)
        steps = smart.get("steps") or []
        if steps:
            return steps
    except Exception:  # noqa: BLE001
        pass
    return _suggest_http_steps_flat(apis, max_steps=max_steps)


def _suggest_http_steps_flat(apis: list[dict[str, Any]], *, max_steps: int = 8) -> list[dict[str, Any]]:
    """Legacy flat suggestion (no dependency wiring)."""
    steps: list[dict[str, Any]] = []
    for i, api in enumerate(apis[:max_steps]):
        method = str(api.get("method") or "GET").upper()
        url = str(api.get("url") or "")
        if not url:
            continue
        step: dict[str, Any] = {
            "id": f"api_{i}_{method.lower()}",
            "action": "http.request",
            "method": method,
            "url": url,
            "headers": {},
        }
        for k, v in (api.get("request_headers") or {}).items():
            kl = str(k).lower()
            if kl in {
                "content-type",
                "accept",
                "origin",
                "referer",
                "x-requested-with",
                "x-csrf-token",
                "x-xsrf-token",
            }:
                step["headers"][k] = v
        post = api.get("post_data")
        if post:
            try:
                parsed = json.loads(post)
                if isinstance(parsed, dict):
                    templated: dict[str, Any] = {}
                    for pk, pv in parsed.items():
                        pkl = str(pk).lower()
                        if "email" in pkl:
                            templated[pk] = "{{ account.email }}"
                        elif "pass" in pkl:
                            templated[pk] = "{{ account.password }}"
                        elif "user" in pkl and "name" in pkl:
                            templated[pk] = "{{ account.username }}"
                        elif any(x in pkl for x in ("phone", "mobile", "msisdn")):
                            templated[pk] = "{{ account.phone }}"
                        elif "first" in pkl and "name" in pkl:
                            templated[pk] = "{{ account.first_name }}"
                        elif "last" in pkl and "name" in pkl:
                            templated[pk] = "{{ account.last_name }}"
                        else:
                            templated[pk] = pv
                    step["json"] = templated
                else:
                    step["body"] = post
            except Exception:  # noqa: BLE001
                step["body"] = post
        step["save_as"] = f"api_{i}_response"
        steps.append(step)
    return steps
