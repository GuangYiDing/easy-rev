"""Generate commercial-ready hooks.py scaffolds from signing / capture analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

HOOKS_SIGNING_TEMPLATE = '''\
"""Site Pack hooks — signing / hybrid helpers (requires --trust).

Auto-scaffolded by easy-rev re.scaffold_hooks from capture signing analysis.
Customize `sign_request` before bulk production runs.

Detected signals:
{signals_comment}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any


# Files frequently seen on call stacks (from runtime hooks):
STACK_FILES = {stack_files!r}

# Headers that looked like signatures in runtime traces:
SIG_HEADERS = {sig_headers!r}

# Body keys that looked signed:
SIG_BODY_KEYS = {sig_body_keys!r}


def sign_request(method: str, url: str, body: dict[str, Any] | str | None, secret: str) -> dict[str, str]:
    """Return extra headers to attach to protocol requests.

    TODO: reverse the real algorithm from STACK_FILES / browser hooks.
    Placeholder: HMAC-SHA256 over method + path + body + timestamp (replace me).
    """
    from urllib.parse import urlparse

    path = urlparse(url).path
    ts = str(int(time.time()))
    if isinstance(body, dict):
        payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    else:
        payload = body or ""
    msg = f"{{method.upper()}}\\n{{path}}\\n{{payload}}\\n{{ts}}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    headers = {{
        "X-Timestamp": ts,
        "X-Signature": sig,
    }}
    # Common alternates — uncomment what the capture used:
    # headers["Authorization"] = f"Bearer {{sig}}"
    # headers["X-Sign"] = sig
    return headers


async def before_run(ctx: Any) -> None:
    """Optional: seed vars used by http.request templates."""
    secret = (ctx.vars or {{}}).get("api_sign_secret") or (ctx.meta or {{}}).get("api_sign_secret")
    if secret:
        ctx.vars["api_sign_secret"] = secret
    ctx.vars.setdefault("sign_ts", str(int(time.time())))


async def before_http_request(ctx: Any, params: dict[str, Any]) -> dict[str, Any] | None:
    """If runtime supports this hook, mutate headers before send.

    Current easy-rev core calls before_submit for browser submits; for pure HTTP
    packs, call sign_request from a thin wrapper step or extend runtime.
    This function is ready for runtime integration / manual use in custom flows.
    """
    secret = (ctx.vars or {{}}).get("api_sign_secret")
    if not secret:
        return None
    body = params.get("json") or params.get("body")
    extra = sign_request(
        str(params.get("method") or "POST"),
        str(params.get("url") or ""),
        body,
        str(secret),
    )
    headers = dict(params.get("headers") or {{}})
    headers.update(extra)
    params["headers"] = headers
    return params


async def is_success(ctx: Any) -> bool | None:
    """Protocol success override based on last HTTP status / extract."""
    status = (ctx.meta or {{}}).get("last_http_status")
    if status is not None and int(status) in {{200, 201}}:
        return True
    if (ctx.extract or {{}}).get("user_id"):
        return True
    return None
'''


def build_hooks_source(
    *,
    signing: dict[str, Any] | None = None,
    js_analysis: dict[str, Any] | None = None,
    notes: list[str] | None = None,
) -> str:
    signing = signing or {}
    js_analysis = js_analysis or {}
    stack_files = list((signing.get("stack_files") or {}).keys())[:12]
    if not stack_files:
        stack_files = list(js_analysis.get("sign_function_candidates") or [])[:12]
    sig_headers = list((signing.get("sig_headers") or {}).keys())[:20]
    sig_body = list((signing.get("sig_body_keys") or {}).keys())[:20]
    recs = list(signing.get("recommendations") or []) + list(
        js_analysis.get("recommendations") or []
    )
    if notes:
        recs.extend(notes)
    signals = "\n".join(f"- {r}" for r in recs[:12]) or "- (no strong signals; fill in manually)"

    return HOOKS_SIGNING_TEMPLATE.format(
        signals_comment=signals,
        stack_files=stack_files,
        sig_headers=sig_headers,
        sig_body_keys=sig_body,
    )


def scaffold_hooks_for_pack(
    pack_path: str | Path,
    *,
    capture_path: str | Path | None = None,
    signing: dict[str, Any] | None = None,
    js_analysis: dict[str, Any] | None = None,
    force: bool = False,
    update_manifest: bool = True,
) -> dict[str, Any]:
    """Write hooks.py into pack and set entry.hooks + trust warning."""
    pack_path = Path(pack_path)
    pack_path.mkdir(parents=True, exist_ok=True)

    if capture_path:
        data = json.loads(Path(capture_path).read_text(encoding="utf-8"))
        signing = signing or data.get("signing")
        js_analysis = js_analysis or data.get("js_analysis")

    source = build_hooks_source(signing=signing, js_analysis=js_analysis)
    hooks_file = pack_path / "hooks.py"
    if hooks_file.exists() and not force:
        return {
            "ok": False,
            "error": "hooks.py already exists; pass force=true to overwrite",
            "path": str(hooks_file),
        }
    hooks_file.write_text(source, encoding="utf-8")

    pack_yaml = pack_path / "pack.yaml"
    if update_manifest and pack_yaml.exists():
        import yaml

        manifest = yaml.safe_load(pack_yaml.read_text(encoding="utf-8")) or {}
        entry = manifest.get("entry") or {}
        entry["hooks"] = "hooks.py"
        if entry.get("kind") == "declarative":
            entry["kind"] = "hybrid"
        manifest["entry"] = entry
        warnings = list(manifest.get("warnings") or [])
        w = "hooks.py signing scaffold — review before production; install/run with trust"
        if w not in warnings:
            warnings.append(w)
        manifest["warnings"] = warnings
        tags = list(manifest.get("tags") or [])
        if "hooks" not in tags:
            tags.append("hooks")
        if "signing" not in tags:
            tags.append("signing")
        manifest["tags"] = tags
        pack_yaml.write_text(
            yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )

    return {
        "ok": True,
        "path": str(hooks_file.resolve()),
        "pack_path": str(pack_path.resolve()),
        "trust_required": True,
        "next": [
            "Set vars.api_sign_secret or implement real sign_request()",
            "easy-rev pack validate <path> --trust",
            "easy-rev pack install <path> --trust",
        ],
    }


def scaffold_hooks_standalone(
    out_path: str | Path,
    *,
    capture_path: str | Path | None = None,
    signing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out_path = Path(out_path)
    if capture_path:
        data = json.loads(Path(capture_path).read_text(encoding="utf-8"))
        signing = signing or data.get("signing")
        js = data.get("js_analysis")
    else:
        js = None
    source = build_hooks_source(signing=signing, js_analysis=js)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(source, encoding="utf-8")
    return {"ok": True, "path": str(out_path.resolve())}
