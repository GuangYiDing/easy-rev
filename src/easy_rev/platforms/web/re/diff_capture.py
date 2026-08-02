"""Diff two capture/API snapshots for commercial RE iteration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _load(path_or_data: str | Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(path_or_data, dict):
        return path_or_data
    return json.loads(Path(path_or_data).read_text(encoding="utf-8"))


def _api_key(api: dict[str, Any]) -> str:
    method = str(api.get("method") or "GET").upper()
    url = str(api.get("url") or "")
    try:
        p = urlparse(url)
        path = p.path
    except Exception:  # noqa: BLE001
        path = url
    return f"{method} {path}"


def _normalize_body(post: Any) -> Any:
    if post is None:
        return None
    if isinstance(post, (dict, list)):
        return post
    try:
        return json.loads(str(post))
    except Exception:  # noqa: BLE001
        return str(post)[:500]


def diff_captures(
    a: str | Path | dict[str, Any],
    b: str | Path | dict[str, Any],
    *,
    focus: str | None = None,
) -> dict[str, Any]:
    """Compare two captures: APIs added/removed, header/body deltas, signing risk change."""
    ca, cb = _load(a), _load(b)
    apis_a = { _api_key(x): x for x in (ca.get("apis") or []) if isinstance(x, dict) }
    apis_b = { _api_key(x): x for x in (cb.get("apis") or []) if isinstance(x, dict) }

    keys_a, keys_b = set(apis_a), set(apis_b)
    added = sorted(keys_b - keys_a)
    removed = sorted(keys_a - keys_b)
    common = sorted(keys_a & keys_b)

    changed: list[dict[str, Any]] = []
    for k in common:
        aa, bb = apis_a[k], apis_b[k]
        delta: dict[str, Any] = {"api": k}
        if aa.get("status") != bb.get("status"):
            delta["status"] = {"a": aa.get("status"), "b": bb.get("status")}
        ha = {str(x).lower(): v for x, v in (aa.get("request_headers") or {}).items()}
        hb = {str(x).lower(): v for x, v in (bb.get("request_headers") or {}).items()}
        hdr_only_a = sorted(set(ha) - set(hb))
        hdr_only_b = sorted(set(hb) - set(ha))
        hdr_val = []
        for hk in set(ha) & set(hb):
            if ha[hk] != hb[hk] and hk not in {"cookie", "content-length"}:
                hdr_val.append({"header": hk, "a_len": len(str(ha[hk])), "b_len": len(str(hb[hk]))})
        if hdr_only_a or hdr_only_b or hdr_val:
            delta["headers"] = {
                "only_a": hdr_only_a[:20],
                "only_b": hdr_only_b[:20],
                "value_changed": hdr_val[:20],
            }
        ba, bbod = _normalize_body(aa.get("post_data")), _normalize_body(bb.get("post_data"))
        if ba != bbod:
            if isinstance(ba, dict) and isinstance(bbod, dict):
                delta["body"] = {
                    "keys_only_a": sorted(set(ba) - set(bbod))[:30],
                    "keys_only_b": sorted(set(bbod) - set(ba))[:30],
                    "keys_changed": [
                        kk
                        for kk in set(ba) & set(bbod)
                        if ba.get(kk) != bbod.get(kk)
                    ][:30],
                }
            else:
                delta["body"] = {"changed": True}
        if len(delta) > 1:
            changed.append(delta)

    if focus:
        fl = focus.lower()
        changed = [c for c in changed if fl in c.get("api", "").lower()]
        added = [k for k in added if fl in k.lower()]
        removed = [k for k in removed if fl in k.lower()]

    sa = (ca.get("signing") or {}).get("sig_headers") or {}
    sb = (cb.get("signing") or {}).get("sig_headers") or {}
    ja = (ca.get("js_analysis") or {}).get("risk")
    jb = (cb.get("js_analysis") or {}).get("risk")

    return {
        "a_url": ca.get("url") or ca.get("started_url"),
        "b_url": cb.get("url") or cb.get("started_url"),
        "apis": {
            "added": added,
            "removed": removed,
            "changed": changed[:50],
            "count_a": len(apis_a),
            "count_b": len(apis_b),
        },
        "signing_headers": {
            "only_a": sorted(set(sa) - set(sb)),
            "only_b": sorted(set(sb) - set(sa)),
        },
        "js_risk": {"a": ja, "b": jb},
        "suggestions": _diff_tips(added, removed, changed, ja, jb),
    }


def _diff_tips(
    added: list[str],
    removed: list[str],
    changed: list[dict[str, Any]],
    risk_a: Any,
    risk_b: Any,
) -> list[str]:
    tips = []
    if added:
        tips.append(f"New APIs in B ({len(added)}): re-run pack.from_capture or merge into flow")
    if removed:
        tips.append(f"APIs missing in B ({len(removed)}): may be conditional or blocked")
    body_ch = [c for c in changed if "body" in c]
    if body_ch:
        tips.append(
            "Body key deltas often = nonce/timestamp/sign — do not hardcode; use extract or hooks"
        )
    if risk_a != risk_b:
        tips.append(f"JS risk changed {risk_a} → {risk_b}")
    if not tips:
        tips.append("Captures similar — protocol flow likely stable")
    return tips
