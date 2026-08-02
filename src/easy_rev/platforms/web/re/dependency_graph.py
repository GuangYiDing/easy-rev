"""Build API call dependency graphs and smart protocol flow steps."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

NOISE_HOST_PARTS = (
    "google-analytics",
    "googletagmanager",
    "facebook",
    "doubleclick",
    "hotjar",
    "clarity.ms",
    "sentry.io",
    "segment.io",
    "amplitude",
    "mixpanel",
    "newrelic",
)

TOKENISH_KEYS = re.compile(
    r"(token|csrf|xsrf|nonce|session|sid|auth|jwt|request[_-]?id|timestamp|sign|signature)",
    re.I,
)


@dataclass
class GraphNode:
    id: int
    method: str
    url: str
    score: int = 0
    tags: list[str] = field(default_factory=list)
    role: str = "api"  # bootstrap|csrf|register|verify|auth|api|noise
    post_data: str | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_body: str | None = None
    status: int | None = None
    depends_on: list[int] = field(default_factory=list)
    provides: dict[str, str] = field(default_factory=dict)  # name -> source description
    raw: dict[str, Any] = field(default_factory=dict)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:  # noqa: BLE001
        return ""


def _is_noise(api: dict[str, Any]) -> bool:
    url = str(api.get("url") or "").lower()
    method = str(api.get("method") or "GET").upper()
    if method == "OPTIONS":
        return True
    if any(n in url for n in NOISE_HOST_PARTS):
        return True
    if any(n in url for n in ("/collect", "/beacon", "/telemetry", "/pixel", "analytics")):
        return True
    score = int(api.get("score") or 0)
    tags = set(api.get("tags") or api.get("why") or [])
    if score < 3 and "register_keyword" not in tags and "credential_fields" not in tags:
        # low-score GETs to static often noise
        if method == "GET" and not any(x in url for x in ("/api", "csrf", "auth", "session")):
            return True
    return False


def _infer_role(api: dict[str, Any]) -> str:
    url = str(api.get("url") or "").lower()
    method = str(api.get("method") or "GET").upper()
    body = str(api.get("post_data") or "").lower()
    tags = set(api.get("tags") or api.get("why") or [])

    if "credential_fields" in tags or re.search(r"register|signup|sign-up|create.?account", url + body):
        return "register"
    if re.search(r"verify|otp|confirm|activate|sms.?code", url + body):
        return "verify"
    if re.search(r"csrf|xsrf|nonce", url) or method == "GET" and "csrf" in url:
        return "csrf"
    if re.search(r"login|oauth|token|session|auth", url) and method in {"POST", "GET"}:
        if method == "GET" and "csrf" not in url:
            return "bootstrap"
        return "auth"
    if method == "GET" and any(x in url for x in ("/api", "init", "config", "bootstrap", "session")):
        return "bootstrap"
    return "api"


def _extract_provided_values(api: dict[str, Any]) -> dict[str, str]:
    """Map logical name -> value string found in response (for dependency linking)."""
    out: dict[str, str] = {}
    body = api.get("response_body")
    if not body or not isinstance(body, str):
        return out
    # set-cookie names from headers if present
    headers = api.get("response_headers") or {}
    for k, v in headers.items():
        if str(k).lower() == "set-cookie":
            m = re.match(r"([^=]+)=([^;]+)", str(v))
            if m:
                out[f"cookie:{m.group(1)}"] = m.group(2)

    try:
        data = json.loads(body)
    except Exception:  # noqa: BLE001
        # regex tokens in text
        for m in re.finditer(
            r"(?i)(?:csrf|token|nonce|session)[\"'\s:=]+([A-Za-z0-9_\-.=]{8,})",
            body,
        ):
            out[f"text_token_{len(out)}"] = m.group(1)[:200]
        return out

    def walk(obj: Any, path: str = "$") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = f"{path}.{k}"
                kl = str(k).lower()
                if isinstance(v, (str, int, float)) and TOKENISH_KEYS.search(kl):
                    out[p] = str(v)
                elif isinstance(v, (dict, list)):
                    walk(v, p)
                elif isinstance(v, str) and len(v) >= 16 and kl in {"id", "key", "code"}:
                    out[p] = v
        elif isinstance(obj, list) and obj:
            walk(obj[0], path + ".0")

    walk(data)
    return out


def _values_used_in_request(api: dict[str, Any]) -> set[str]:
    """Collect string literals from body/headers/url that might come from prior responses."""
    used: set[str] = set()
    for source in (
        str(api.get("post_data") or ""),
        str(api.get("url") or ""),
        json.dumps(api.get("request_headers") or {}, ensure_ascii=False),
    ):
        # long tokens
        for m in re.finditer(r"[A-Za-z0-9_\-.=]{12,}", source):
            used.add(m.group(0))
    return used


def build_dependency_graph(
    apis: list[dict[str, Any]],
    *,
    min_score: int = 3,
    max_nodes: int = 20,
) -> list[GraphNode]:
    """Order APIs and link depends_on when a later request uses an earlier response value."""
    cleaned: list[dict[str, Any]] = []
    for a in apis:
        if not isinstance(a, dict):
            continue
        if _is_noise(a):
            continue
        if int(a.get("score") or 0) < min_score and _infer_role(a) == "api":
            continue
        cleaned.append(a)

    # chronological if id present else keep score order then reverse for chain
    cleaned.sort(key=lambda a: (int(a.get("id") or 0) or 0, -int(a.get("score") or 0)))

    nodes: list[GraphNode] = []
    provided_index: list[tuple[int, str, str]] = []  # node_id, path, value

    for i, api in enumerate(cleaned[: max_nodes * 2]):
        if len(nodes) >= max_nodes:
            break
        role = _infer_role(api)
        node = GraphNode(
            id=int(api.get("id") or i + 1),
            method=str(api.get("method") or "GET").upper(),
            url=str(api.get("url") or ""),
            score=int(api.get("score") or 0),
            tags=list(api.get("tags") or api.get("why") or []),
            role=role,
            post_data=api.get("post_data"),
            request_headers=dict(api.get("request_headers") or {}),
            response_body=api.get("response_body"),
            status=api.get("status"),
            raw=api,
        )
        provides = _extract_provided_values(api)
        node.provides = provides
        for path, val in provides.items():
            if val and len(str(val)) >= 6:
                provided_index.append((node.id, path, str(val)))

        used = _values_used_in_request(api)
        deps: set[int] = set()
        for pid, _path, val in provided_index:
            if pid == node.id:
                continue
            if val in used and len(val) >= 8:
                deps.add(pid)
        node.depends_on = sorted(deps)
        nodes.append(node)

    # Prefer include register + its deps
    register_ids = {n.id for n in nodes if n.role == "register"}
    if register_ids:
        keep: set[int] = set(register_ids)
        for n in nodes:
            if n.id in register_ids:
                keep.update(n.depends_on)
            if n.role in {"csrf", "bootstrap", "auth", "verify"}:
                keep.add(n.id)
        # always keep high score
        for n in nodes:
            if n.score >= 10:
                keep.add(n.id)
        nodes = [n for n in nodes if n.id in keep]

    # topological-ish: deps first
    by_id = {n.id: n for n in nodes}
    ordered: list[GraphNode] = []
    seen: set[int] = set()

    def visit(n: GraphNode) -> None:
        if n.id in seen:
            return
        for d in n.depends_on:
            if d in by_id:
                visit(by_id[d])
        seen.add(n.id)
        ordered.append(n)

    for n in nodes:
        visit(n)
    return ordered


def _template_value(key: str, value: Any, *, provided_lookup: dict[str, tuple[int, str]]) -> Any:
    """Replace credentials and known prior values with templates."""
    if not isinstance(value, str):
        # nested handled by caller
        return value
    kl = key.lower() if key else ""
    if "email" in kl:
        return "{{ account.email }}"
    if "pass" in kl:
        return "{{ account.password }}"
    if "user" in kl and "name" in kl:
        return "{{ account.username }}"
    if any(x in kl for x in ("phone", "mobile", "msisdn")):
        return "{{ account.phone }}"
    if "first" in kl and "name" in kl:
        return "{{ account.first_name }}"
    if "last" in kl and "name" in kl:
        return "{{ account.last_name }}"

    # if value was provided by earlier node
    if value in provided_lookup:
        nid, path = provided_lookup[value]
        safe = re.sub(r"[^a-zA-Z0-9_]+", "_", path.strip("$.")).strip("_")[:40]
        return f"{{{{ extract.n{nid}_{safe} }}}}"
    return value


def _template_json(
    obj: Any,
    *,
    provided_lookup: dict[str, tuple[int, str]],
    key: str = "",
) -> Any:
    if isinstance(obj, dict):
        return {
            k: _template_json(v, provided_lookup=provided_lookup, key=str(k))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_template_json(v, provided_lookup=provided_lookup, key=key) for v in obj]
    return _template_value(key, obj, provided_lookup=provided_lookup)


def graph_to_flow_steps(
    nodes: list[GraphNode],
    *,
    use_browser_cookies: bool = True,
    max_steps: int = 12,
    sign_via_browser: bool = False,
    signer_path: str | None = None,
) -> list[dict[str, Any]]:
    """Convert dependency-ordered nodes into flow.yaml steps."""
    steps: list[dict[str, Any]] = []
    if use_browser_cookies:
        steps.append(
            {
                "id": "import_browser",
                "action": "http.from_browser",
                "include_storage_tokens": True,
            }
        )

    # Build value -> (node_id, path) for later responses we plan to extract
    # First pass: plan extract names per node provides
    extract_plan: dict[int, list[dict[str, str]]] = {}
    provided_lookup: dict[str, tuple[int, str]] = {}

    for n in nodes:
        extracts = []
        for path, val in list(n.provides.items())[:8]:
            if not val or len(str(val)) < 6:
                continue
            safe = re.sub(r"[^a-zA-Z0-9_]+", "_", path.strip("$.")).strip("_")[:40] or "val"
            name = f"n{n.id}_{safe}"
            if path.startswith("cookie:"):
                extracts.append({"name": name, "cookie": path.split(":", 1)[1]})
            elif path.startswith("$"):
                extracts.append({"name": name, "json_path": path})
            else:
                extracts.append({"name": name, "regex": re.escape(str(val)[:80])})
            provided_lookup[str(val)] = (n.id, path)
        extract_plan[n.id] = extracts

    for i, n in enumerate(nodes[:max_steps]):
        step: dict[str, Any] = {
            "id": f"{n.role}_{n.id}",
            "action": "http.request",
            "method": n.method,
            "url": n.url,
            "headers": {},
            "use_browser_cookies": True if i == 0 and not use_browser_cookies else False,
            "meta_role": n.role,
        }
        # useful headers; template CSRF if matches provided
        for k, v in n.request_headers.items():
            kl = str(k).lower()
            if kl in {
                "content-type",
                "accept",
                "origin",
                "referer",
                "x-requested-with",
                "x-csrf-token",
                "x-xsrf-token",
                "authorization",
            }:
                tv = _template_value(k, v, provided_lookup=provided_lookup)
                step["headers"][k] = tv

        if n.post_data:
            try:
                parsed = json.loads(n.post_data)
                if isinstance(parsed, (dict, list)):
                    step["json"] = _template_json(parsed, provided_lookup=provided_lookup)
                else:
                    step["body"] = n.post_data
            except Exception:  # noqa: BLE001
                # form-urlencoded?
                if "=" in n.post_data and "&" in n.post_data:
                    form = {}
                    for k, vs in parse_qs(n.post_data, keep_blank_values=True).items():
                        form[k] = _template_value(
                            k, vs[0] if vs else "", provided_lookup=provided_lookup
                        )
                    step["form"] = form
                else:
                    step["body"] = n.post_data

        extracts = extract_plan.get(n.id) or []
        if extracts:
            step["extract"] = extracts
        step["save_as"] = f"resp_{n.id}"
        if n.role == "register":
            step["assert_status"] = [200, 201]
            if sign_via_browser:
                step["sign_via_browser"] = True
                if signer_path:
                    step["signer_path"] = signer_path
        elif n.method == "GET":
            step["assert_status"] = 200
            step["allow_error"] = False
        else:
            step["assert_status"] = [200, 201, 204]
            if sign_via_browser and n.method in {"POST", "PUT", "PATCH"}:
                step["sign_via_browser"] = True
                if signer_path:
                    step["signer_path"] = signer_path

        steps.append(step)

    # success assert
    reg = next((n for n in nodes if n.role == "register"), None)
    if reg:
        steps.append(
            {
                "id": "ok",
                "action": "assert",
                "any": [
                    {"extract_exists": f"resp_{reg.id}"},
                    {"http_status": 200},
                ],
            }
        )
    else:
        last = nodes[-1] if nodes else None
        if last:
            steps.append(
                {
                    "id": "ok",
                    "action": "assert",
                    "any": [{"extract_exists": f"resp_{last.id}"}, {"http_status": 200}],
                }
            )
    return steps


def graph_summary(nodes: list[GraphNode]) -> dict[str, Any]:
    return {
        "nodes": [
            {
                "id": n.id,
                "role": n.role,
                "method": n.method,
                "url": n.url[:200],
                "score": n.score,
                "depends_on": n.depends_on,
                "provides": list(n.provides.keys())[:8],
            }
            for n in nodes
        ],
        "roles": sorted({n.role for n in nodes}),
        "count": len(nodes),
    }


def smart_suggest_http_steps(
    apis: list[dict[str, Any]],
    *,
    max_steps: int = 10,
    use_browser_cookies: bool = True,
    min_score: int = 3,
    sign_via_browser: bool = False,
    signer_path: str | None = None,
) -> dict[str, Any]:
    nodes = build_dependency_graph(apis, min_score=min_score, max_nodes=max_steps + 4)
    steps = graph_to_flow_steps(
        nodes,
        use_browser_cookies=use_browser_cookies,
        max_steps=max_steps,
        sign_via_browser=sign_via_browser,
        signer_path=signer_path,
    )
    return {
        "steps": steps,
        "graph": graph_summary(nodes),
        "mode": "dependency_graph",
        "sign_via_browser": sign_via_browser,
        "signer_path": signer_path,
    }
