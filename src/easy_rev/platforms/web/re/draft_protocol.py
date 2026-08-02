"""Build protocol / hybrid flow.yaml + pack from capture APIs (auto-sign aware)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from easy_rev.pack.template import init_pack
from easy_rev.platforms.web.re.dependency_graph import smart_suggest_http_steps


def load_apis_from_capture(
    capture_path: str | Path | None = None,
    apis: list[dict[str, Any]] | None = None,
    *,
    min_score: int = 4,
    max_apis: int = 8,
) -> list[dict[str, Any]]:
    if apis is not None:
        ranked = sorted(apis, key=lambda a: -int(a.get("score") or 0))
        return ranked[: max_apis * 2]
    if not capture_path:
        raise ValueError("capture_path or apis required")
    data = json.loads(Path(capture_path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and data.get("apis"):
        ranked = sorted(data["apis"], key=lambda a: -int(a.get("score") or 0))
        return [a for a in ranked if int(a.get("score") or 0) >= min_score][: max_apis * 2]
    return []


def extract_auto_sign_hints(
    capture_path: str | Path | None = None,
    capture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Pull best_signer / mode / confidence from a capture document or auto_sign dict."""
    data = capture
    if data is None and capture_path:
        try:
            data = json.loads(Path(capture_path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            data = {}
    data = data or {}
    # Accept either full capture {auto_sign: {...}} or compact auto_sign itself
    if "auto_sign" in data:
        auto = data.get("auto_sign") or {}
        ja = data.get("js_analysis") or {}
        signing = data.get("signing") or {}
    elif any(k in data for k in ("best_signer", "mode", "crypto_analysis", "signers_working")):
        auto = data
        ja = {}
        signing = {}
    else:
        auto = {}
        ja = data.get("js_analysis") or {}
        signing = data.get("signing") or {}

    best = auto.get("best_signer")
    mode = auto.get("mode") or ""
    conf = (auto.get("crypto_analysis") or {}).get("confidence") or auto.get(
        "crypto_confidence"
    )
    working = auto.get("signers_working") or []
    if not best and working:
        first = working[0]
        best = first if isinstance(first, str) else (first or {}).get("path")
    need_oracle = bool(
        best
        or mode in {"browser_oracle", "pure_python_with_oracle_fallback"}
        or conf == "oracle_only"
        or ja.get("risk") in {"medium", "high"}
        or signing.get("sig_headers")
    )
    pure_ok = mode == "pure_python" and conf == "high"
    return {
        "best_signer": best,
        "mode": mode,
        "crypto_confidence": conf,
        "need_oracle": need_oracle and not pure_ok,
        "pure_python": pure_ok,
        "js_risk": ja.get("risk"),
        "signers_working": working,
    }


def build_protocol_flow(
    *,
    apis: list[dict[str, Any]],
    signup_url: str | None = None,
    max_apis: int = 8,
    hybrid: bool = False,
    impersonate: str | None = None,
    sign_via_browser: bool = False,
    signer_path: str | None = None,
) -> dict[str, Any]:
    smart = smart_suggest_http_steps(
        apis,
        max_steps=max_apis,
        use_browser_cookies=hybrid,
        min_score=3,
        sign_via_browser=sign_via_browser,
        signer_path=signer_path,
    )
    steps = list(smart.get("steps") or [])

    # Pure protocol: drop http.from_browser / sign_via_browser
    if not hybrid:
        steps = [s for s in steps if s.get("action") != "http.from_browser"]
        for s in steps:
            if isinstance(s, dict):
                s.pop("use_browser_cookies", None)
                if not sign_via_browser:
                    s.pop("sign_via_browser", None)
                    s.pop("signer_path", None)

    # Ensure every mutating http.request has signer when oracle mode
    if sign_via_browser and hybrid:
        for s in steps:
            if not isinstance(s, dict) or s.get("action") != "http.request":
                continue
            method = str(s.get("method") or "GET").upper()
            if method in {"POST", "PUT", "PATCH"}:
                s["sign_via_browser"] = True
                if signer_path:
                    s["signer_path"] = signer_path

    if not steps:
        steps = [
            {
                "id": "placeholder",
                "action": "http.request",
                "method": "GET",
                "url": signup_url or "https://example.com/",
                "assert_status": 200,
                "save_as": "home",
            },
            {
                "id": "ok",
                "action": "assert",
                "any": [{"extract_exists": "home"}, {"http_status": 200}],
            },
        ]

    if not any(s.get("action") == "assert" for s in steps):
        last_save = None
        for s in steps:
            if s.get("save_as"):
                last_save = s["save_as"]
        steps.append(
            {
                "id": "ok",
                "action": "assert",
                "any": (
                    [{"extract_exists": last_save}, {"http_status": 200}]
                    if last_save
                    else [{"http_status": 200}]
                ),
            }
        )

    vars_: dict[str, Any] = {}
    if signup_url:
        vars_["signup_url"] = signup_url
        try:
            p = urlparse(signup_url)
            if p.scheme and p.netloc:
                vars_["origin"] = f"{p.scheme}://{p.netloc}"
        except Exception:  # noqa: BLE001
            pass
    if impersonate:
        vars_["http_impersonate"] = impersonate
    if signer_path:
        vars_["signer_path"] = signer_path
    if sign_via_browser:
        vars_["sign_via_browser"] = True

    return {
        "schema": "easy-rev.flow/v1",
        "vars": vars_,
        "steps": steps,
        "_graph": smart.get("graph"),
        "_sign": {
            "sign_via_browser": sign_via_browser,
            "signer_path": signer_path,
        },
    }


def write_protocol_pack(
    *,
    pack_path: Path,
    pack_id: str | None = None,
    name: str | None = None,
    description: str = "protocol pack from capture",
    signup_url: str | None = None,
    apis: list[dict[str, Any]] | None = None,
    capture_path: str | Path | None = None,
    max_apis: int = 8,
    min_score: int = 4,
    hybrid: bool = False,
    impersonate: str | None = "chrome120",
    sign_via_browser: bool | None = None,
    signer_path: str | None = None,
    auto_sign: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pack_path = Path(pack_path)
    pack_path.mkdir(parents=True, exist_ok=True)
    pid = pack_id or pack_path.name

    if not (pack_path / "pack.yaml").exists():
        init_pack(
            pack_path,
            pack_id=pid,
            name=name or pid,
            description=description,
            platform="web",
            with_hooks=bool(hybrid or sign_via_browser),
        )

    loaded_apis = load_apis_from_capture(
        capture_path, apis, min_score=min_score, max_apis=max_apis
    )
    signing_notes: list[str] = []
    capture_raw: dict[str, Any] | None = None
    if capture_path:
        try:
            capture_raw = json.loads(Path(capture_path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            capture_raw = None

    hints = extract_auto_sign_hints(capture_path=capture_path, capture=auto_sign or capture_raw)
    if auto_sign:
        # allow passing compact auto_sign dict directly
        if auto_sign.get("best_signer") and not hints.get("best_signer"):
            hints["best_signer"] = auto_sign["best_signer"]
        if auto_sign.get("mode"):
            hints["mode"] = auto_sign["mode"]
            if auto_sign["mode"] in {"browser_oracle", "pure_python_with_oracle_fallback"}:
                hints["need_oracle"] = True
            if auto_sign["mode"] == "pure_python":
                hints["pure_python"] = True
                hints["need_oracle"] = False

    if not signup_url and capture_raw:
        signup_url = capture_raw.get("url") or capture_raw.get("started_url")
        sig = capture_raw.get("signing") or {}
        if sig.get("recommendations"):
            signing_notes.extend(sig["recommendations"][:5])

    # Auto hybrid + oracle when capture says so
    if hints.get("need_oracle"):
        if not hybrid:
            hybrid = True
            signing_notes.append(
                f"Auto hybrid+oracle: mode={hints.get('mode')} signer={hints.get('best_signer')}"
            )
        if sign_via_browser is None:
            sign_via_browser = True
        if not signer_path:
            signer_path = hints.get("best_signer")
    elif hints.get("pure_python"):
        signing_notes.append("auto_sign pure_python — use synthesized hooks, engine=http")
        if sign_via_browser is None:
            sign_via_browser = False
    else:
        if sign_via_browser is None:
            sign_via_browser = False
        ja_risk = hints.get("js_risk")
        if ja_risk in {"medium", "high"} and not hybrid:
            hybrid = True
            signing_notes.append(f"Auto-enabled hybrid because js_analysis.risk={ja_risk}")

    # Explicit signer from caller wins
    if signer_path is None:
        signer_path = hints.get("best_signer")

    flow_doc = build_protocol_flow(
        apis=loaded_apis,
        signup_url=signup_url,
        max_apis=max_apis,
        hybrid=hybrid,
        impersonate=impersonate,
        sign_via_browser=bool(sign_via_browser),
        signer_path=signer_path,
    )
    graph = flow_doc.pop("_graph", None)
    sign_meta = flow_doc.pop("_sign", None)
    flow_file = pack_path / "flow.yaml"
    flow_file.write_text(
        yaml.safe_dump(flow_doc, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )

    pack_yaml = pack_path / "pack.yaml"
    manifest = yaml.safe_load(pack_yaml.read_text(encoding="utf-8")) or {}
    requires = manifest.get("requires") or {}
    requires["engine"] = "camoufox" if hybrid else "http"
    requires.setdefault("proxy", "recommended")
    manifest["requires"] = requires
    tags = list(manifest.get("tags") or [])
    for t in ("protocol", "reverse-engineered"):
        if t not in tags:
            tags.append(t)
    if hybrid and "hybrid" not in tags:
        tags.append("hybrid")
    if sign_via_browser and "auto-sign" not in tags:
        tags.append("auto-sign")
    if signer_path and "oracle" not in tags:
        tags.append("oracle")
    manifest["tags"] = tags
    warnings = list(manifest.get("warnings") or [])
    warn = "Generated from network capture with dependency graph — verify signing/CSRF before bulk."
    if warn not in warnings:
        warnings.append(warn)
    if capture_path:
        note = f"Source capture: {capture_path}"
        if note not in warnings:
            warnings.append(note)
    if signer_path:
        warnings.append(f"signer_path={signer_path} (http.request sign_via_browser on POST)")
    for sn in signing_notes:
        if sn not in warnings:
            warnings.append(sn)
    if impersonate and not hybrid:
        warnings.append(
            f"http_impersonate={impersonate} (install curl_cffi for Chrome TLS fingerprint)"
        )
    if hybrid and sign_via_browser:
        warnings.append(
            "Bulk oracle: keep engine=camoufox; each account reuses page for sign_via_browser. "
            "Or re.session.sign_batch for external batch."
        )
    manifest["warnings"] = warnings
    if description and not manifest.get("description"):
        manifest["description"] = description
    pack_yaml.write_text(
        yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )

    readme = pack_path / "README.md"
    if not readme.exists():
        eng = "camoufox (hybrid+oracle)" if (hybrid and sign_via_browser) else (
            "camoufox (hybrid)" if hybrid else "http"
        )
        readme.write_text(
            f"""# {pid}

Site Pack from capture (dependency graph + auto-sign).

## Mode

- Engine: `{eng}`
- Hybrid: `{hybrid}`
- sign_via_browser: `{bool(sign_via_browser)}`
- signer_path: `{signer_path}`
- TLS impersonate: `{impersonate}`

## Run

```bash
easy-rev pack install {pack_path} --trust
easy-rev run {pid} -n 1 --engine {"camoufox" if hybrid else "http"} --dry-run
easy-rev run {pid} -n 5 --engine {"camoufox" if hybrid else "http"}
```

### Oracle bulk (same browser session)

```bash
easy-rev ai call re.session.start -i '{{"url":"{signup_url or ""}"}}'
easy-rev ai call re.session.sign_batch -i '{{"session_id":"…","items":[{{"url":"…","json":{{}}}}]}}'
```

Capture: `{capture_path or "inline apis"}`
""",
            encoding="utf-8",
        )

    return {
        "pack_path": str(pack_path.resolve()),
        "pack_id": pid,
        "flow_path": str(flow_file.resolve()),
        "mode": (
            "hybrid_oracle"
            if hybrid and sign_via_browser
            else ("hybrid" if hybrid else "protocol")
        ),
        "steps": len(flow_doc["steps"]),
        "apis_used": len(loaded_apis),
        "engine": "camoufox" if hybrid else "http",
        "signup_url": signup_url,
        "dependency_graph": graph,
        "hybrid": hybrid,
        "sign_via_browser": bool(sign_via_browser),
        "signer_path": signer_path,
        "auto_sign_hints": hints,
        "sign_meta": sign_meta,
        "impersonate": impersonate,
    }
