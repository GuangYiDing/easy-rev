"""page.route experiments: mutate requests/responses to learn required fields (commercial RE)."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def mutate_and_observe(
    page: Any,
    *,
    url_includes: str,
    mutations: list[dict[str, Any]],
    trigger: dict[str, Any] | None = None,
    timeout_ms: int = 15000,
) -> dict[str, Any]:
    """Install a route that applies mutations to matching requests; return observed responses.

    mutations examples:
      [{"op": "omit_json_key", "key": "nonce"}]
      [{"op": "set_json_key", "key": "email", "value": "x@y.z"}]
      [{"op": "drop_header", "name": "x-signature"}]
    trigger: {click: selector} or {eval: js} to fire the request
    """
    if not page or not hasattr(page, "route"):
        return {"ok": False, "error": "page.route not available"}

    observed: list[dict[str, Any]] = []
    pattern = f"**/*{url_includes}*" if not url_includes.startswith("*") else url_includes

    async def handler(route: Any) -> None:
        req = route.request
        try:
            headers = dict(req.headers)
            post = req.post_data
            body_obj = None
            if post:
                try:
                    body_obj = json.loads(post)
                except Exception:  # noqa: BLE001
                    body_obj = None
            for m in mutations:
                op = m.get("op")
                if op == "omit_json_key" and isinstance(body_obj, dict):
                    body_obj.pop(m.get("key"), None)
                elif op == "set_json_key" and isinstance(body_obj, dict):
                    body_obj[m["key"]] = m.get("value")
                elif op == "drop_header":
                    headers.pop(str(m.get("name") or "").lower(), None)
                    # playwright headers may be cased
                    for k in list(headers.keys()):
                        if k.lower() == str(m.get("name") or "").lower():
                            headers.pop(k, None)
                elif op == "set_header":
                    headers[str(m.get("name"))] = str(m.get("value"))
            new_post = json.dumps(body_obj, ensure_ascii=False) if body_obj is not None else post
            response = await route.fetch(headers=headers, post_data=new_post)
            status = response.status
            text = ""
            try:
                text = await response.text()
            except Exception:  # noqa: BLE001
                pass
            observed.append(
                {
                    "url": req.url,
                    "method": req.method,
                    "status": status,
                    "body_preview": text[:500],
                    "mutations": mutations,
                }
            )
            await route.fulfill(response=response)
        except Exception as e:  # noqa: BLE001
            observed.append({"error": str(e)})
            try:
                await route.continue_()
            except Exception:  # noqa: BLE001
                pass

    await page.route(pattern, handler)
    try:
        if trigger:
            if trigger.get("click"):
                await page.click(str(trigger["click"]), timeout=timeout_ms)
            elif trigger.get("eval"):
                await page.evaluate(str(trigger["eval"]))
            elif trigger.get("wait_ms"):
                import asyncio

                await asyncio.sleep(int(trigger["wait_ms"]) / 1000)
        else:
            import asyncio

            await asyncio.sleep(1.5)
        # wait a bit for request
        import asyncio

        await asyncio.sleep(1.0)
    finally:
        try:
            await page.unroute(pattern, handler)
        except Exception:  # noqa: BLE001
            try:
                await page.unroute(pattern)
            except Exception:  # noqa: BLE001
                pass

    return {
        "ok": True,
        "pattern": pattern,
        "observed": observed,
        "count": len(observed),
    }
