"""Field sensitivity probing: omit/mutate JSON fields and classify required vs optional."""

from __future__ import annotations

import copy
import json
import logging
from typing import Any

from easy_rev.platforms.web.re.http_client import HttpClient, HttpResult

logger = logging.getLogger(__name__)

# Keys never mutated as "omit for account" — we still probe them but label credential
CREDENTIAL_KEYS = frozenset(
    {
        "email",
        "password",
        "passwd",
        "pass",
        "username",
        "user",
        "phone",
        "mobile",
        "first_name",
        "firstname",
        "last_name",
        "lastname",
    }
)


def _is_success_status(status: int, baseline: int) -> bool:
    if status == baseline:
        return True
    # treat same class 2xx as soft success if baseline was 2xx
    if 200 <= baseline < 300 and 200 <= status < 300:
        return True
    return False


def _body_error_signal(result: HttpResult) -> str:
    text = (result.text or "")[:500].lower()
    for key in (
        "required",
        "missing",
        "invalid",
        "must ",
        "cannot be empty",
        "validation",
        "bad request",
        "unauthorized",
        "forbidden",
    ):
        if key in text:
            return key
    if result.json_data and isinstance(result.json_data, dict):
        for k in ("error", "message", "msg", "code"):
            if k in result.json_data:
                return f"{k}={result.json_data[k]!r}"[:120]
    return ""


async def probe_json_fields(
    *,
    method: str,
    url: str,
    json_body: dict[str, Any],
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    proxy: str | None = None,
    impersonate: str | None = None,
    timeout_s: float = 25.0,
    max_fields: int = 24,
    also_null: bool = True,
    also_empty_string: bool = True,
) -> dict[str, Any]:
    """Replay baseline then omit each top-level field; classify required/optional/unknown.

    Commercial use: discover minimal body for protocol packs.
    """
    if not isinstance(json_body, dict):
        raise ValueError("json_body must be an object for field probing")

    client = HttpClient(
        proxy=proxy,
        timeout_s=timeout_s,
        impersonate=impersonate,
    )
    try:
        if cookies:
            client.set_cookies(cookies)

        baseline = await client.request(
            method,
            url,
            headers=headers,
            json_body=json_body,
        )
        base_ok = baseline.ok or 200 <= baseline.status < 300
        fields = list(json_body.keys())[:max_fields]
        results: list[dict[str, Any]] = []

        for key in fields:
            # omit field
            omitted = {k: v for k, v in json_body.items() if k != key}
            r_omit = await client.request(
                method, url, headers=headers, json_body=omitted
            )
            omit_ok = _is_success_status(r_omit.status, baseline.status) and (
                r_omit.ok or base_ok is False
            )
            # if baseline failed, compare status equality only
            if not base_ok:
                omit_same = r_omit.status == baseline.status
                classification = "unknown_baseline_failed"
                if not omit_same and r_omit.status != baseline.status:
                    classification = "affects_error"  # field changes error shape
            else:
                if omit_ok and r_omit.status == baseline.status:
                    classification = "optional"
                elif not omit_ok or not _is_success_status(r_omit.status, baseline.status):
                    classification = "required"
                else:
                    classification = "soft_optional"

            entry: dict[str, Any] = {
                "field": key,
                "probe": "omit",
                "classification": classification,
                "status": r_omit.status,
                "baseline_status": baseline.status,
                "error_signal": _body_error_signal(r_omit),
                "credential_like": key.lower() in CREDENTIAL_KEYS
                or any(c in key.lower() for c in CREDENTIAL_KEYS),
            }

            # extra probes for required-looking fields
            if also_null and classification in {"required", "soft_optional", "unknown_baseline_failed"}:
                nulled = copy.deepcopy(json_body)
                nulled[key] = None
                r_null = await client.request(method, url, headers=headers, json_body=nulled)
                entry["null_status"] = r_null.status
                entry["null_ok"] = _is_success_status(r_null.status, baseline.status)

            if also_empty_string and isinstance(json_body.get(key), str):
                emptied = copy.deepcopy(json_body)
                emptied[key] = ""
                r_empty = await client.request(method, url, headers=headers, json_body=emptied)
                entry["empty_status"] = r_empty.status
                entry["empty_ok"] = _is_success_status(r_empty.status, baseline.status)

            results.append(entry)

        required = [r["field"] for r in results if r["classification"] == "required"]
        optional = [r["field"] for r in results if r["classification"] in {"optional", "soft_optional"}]
        unknown = [r["field"] for r in results if r["classification"] not in {"required", "optional", "soft_optional"}]

        minimal = {k: json_body[k] for k in required if k in json_body}
        # always keep credentials if present even if misclassified
        for k, v in json_body.items():
            kl = k.lower()
            if kl in CREDENTIAL_KEYS or any(c in kl for c in ("email", "pass", "phone")):
                minimal[k] = v

        return {
            "url": url,
            "method": method.upper(),
            "baseline": {
                "status": baseline.status,
                "ok": baseline.ok,
                "error": baseline.error,
                "body_preview": (baseline.text or "")[:400],
            },
            "fields": results,
            "summary": {
                "required": required,
                "optional": optional,
                "unknown": unknown,
                "minimal_body_keys": list(minimal.keys()),
            },
            "minimal_json": minimal,
            "suggestions": _suggestions(required, optional, baseline),
        }
    finally:
        await client.close()


def _suggestions(
    required: list[str],
    optional: list[str],
    baseline: HttpResult,
) -> list[str]:
    tips = []
    if not baseline.ok and baseline.status == 0:
        tips.append("Baseline request failed to connect — check proxy/URL/TLS (try impersonate=chrome120)")
    elif not baseline.ok:
        tips.append(
            f"Baseline status={baseline.status} not success — classifications are relative; "
            "fix cookies/CSRF first (http.from_browser) then re-probe"
        )
    if required:
        tips.append(f"Keep required fields in protocol pack: {', '.join(required[:12])}")
    if optional:
        tips.append(f"Safe to drop optional fields for minimal body: {', '.join(optional[:12])}")
    tips.append("Wire minimal_json into flow http.request json: with account templates")
    return tips


def flatten_json_keys(obj: Any, prefix: str = "") -> list[str]:
    """Dot-paths for nested dicts (commercial nested field probe)."""
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                keys.extend(flatten_json_keys(v, path))
            else:
                keys.append(path)
    return keys


def omit_path(obj: Any, path: str) -> Any:
    parts = path.split(".")
    if not parts:
        return obj
    if len(parts) == 1:
        if isinstance(obj, dict):
            return {k: v for k, v in obj.items() if k != parts[0]}
        return obj
    if not isinstance(obj, dict) or parts[0] not in obj:
        return copy.deepcopy(obj)
    out = copy.deepcopy(obj)
    cur = out
    for p in parts[:-1]:
        if not isinstance(cur.get(p), dict):
            return out
        cur = cur[p]
    cur.pop(parts[-1], None)
    return out


async def probe_json_fields_nested(
    *,
    method: str,
    url: str,
    json_body: dict[str, Any],
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    proxy: str | None = None,
    impersonate: str | None = None,
    timeout_s: float = 25.0,
    max_fields: int = 40,
) -> dict[str, Any]:
    """Probe nested JSON paths (dot notation)."""
    paths = flatten_json_keys(json_body)[:max_fields]
    # reuse top-level by expanding omit via path
    client = HttpClient(proxy=proxy, timeout_s=timeout_s, impersonate=impersonate)
    try:
        if cookies:
            client.set_cookies(cookies)
        baseline = await client.request(method, url, headers=headers, json_body=json_body)
        results = []
        for path in paths:
            body2 = omit_path(json_body, path)
            r = await client.request(method, url, headers=headers, json_body=body2)
            if baseline.ok or 200 <= baseline.status < 300:
                if _is_success_status(r.status, baseline.status) and r.status == baseline.status:
                    cls = "optional"
                else:
                    cls = "required"
            else:
                cls = "unknown_baseline_failed"
            results.append(
                {
                    "field": path,
                    "probe": "omit_path",
                    "classification": cls,
                    "status": r.status,
                    "baseline_status": baseline.status,
                    "error_signal": _body_error_signal(r),
                }
            )
        required = [r["field"] for r in results if r["classification"] == "required"]
        optional = [r["field"] for r in results if r["classification"] == "optional"]
        return {
            "mode": "nested",
            "baseline": {"status": baseline.status, "ok": baseline.ok},
            "fields": results,
            "summary": {"required": required, "optional": optional},
            "suggestions": _suggestions(required, optional, baseline),
        }
    finally:
        await client.close()


def probe_from_api_candidate(
    api: dict[str, Any],
    **kwargs: Any,
) -> Any:
    """Helper: build probe coroutine args from capture api entry."""
    post = api.get("post_data")
    if not post:
        raise ValueError("api has no post_data")
    body = json.loads(post) if isinstance(post, str) else post
    if not isinstance(body, dict):
        raise ValueError("post_data is not a JSON object")
    headers = {}
    for k, v in (api.get("request_headers") or {}).items():
        kl = str(k).lower()
        if kl in {"content-type", "accept", "origin", "referer", "x-csrf-token", "x-xsrf-token", "authorization"}:
            headers[str(k)] = str(v)
    return {
        "method": str(api.get("method") or "POST"),
        "url": str(api.get("url") or ""),
        "json_body": body,
        "headers": headers,
        **kwargs,
    }
