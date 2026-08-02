"""Collect and search page JavaScript for reverse-engineering hints."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# Patterns that often reveal API surface / tokens / anti-bot
DEFAULT_SEARCH_PATTERNS = [
    r"/api/[A-Za-z0-9_./?&=-]+",
    r"https?://[A-Za-z0-9._:-]+/api/[A-Za-z0-9_./?&=-]+",
    r"/graphql",
    r"register|signup|signUp|createAccount|create_account",
    r"Authorization|X-CSRF|csrfToken|csrf_token|xsrf",
    r"sitekey|site_key|data-sitekey|turnstile|hcaptcha|recaptcha",
    r"Bearer\s+[A-Za-z0-9._-]+",
    r"client[_-]?id|client[_-]?secret|app[_-]?key",
]


LIST_SCRIPTS_JS = r"""() => {
  const out = [];
  for (const s of document.querySelectorAll('script')) {
    const src = s.getAttribute('src') || '';
    const id = s.id || '';
    const type = s.getAttribute('type') || '';
    const inline_len = src ? 0 : (s.textContent || '').length;
    out.push({
      src: src || null,
      id: id || null,
      type: type || null,
      inline: !src,
      inline_len,
      async: !!s.async,
      defer: !!s.defer,
    });
  }
  return out;
}"""


INLINE_SCRIPTS_JS = r"""(maxChars) => {
  const out = [];
  let budget = maxChars || 200000;
  for (const s of document.querySelectorAll('script')) {
    if (s.getAttribute('src')) continue;
    const text = s.textContent || '';
    if (!text.trim()) continue;
    const slice = text.slice(0, Math.min(text.length, budget));
    budget -= slice.length;
    out.push({
      id: s.id || null,
      length: text.length,
      truncated: slice.length < text.length,
      content: slice,
    });
    if (budget <= 0) break;
  }
  return out;
}"""


async def list_page_scripts(page: Any) -> list[dict[str, Any]]:
    try:
        data = await page.evaluate(LIST_SCRIPTS_JS)
        return data if isinstance(data, list) else []
    except Exception as e:  # noqa: BLE001
        logger.warning("list scripts failed: %s", e)
        return []


async def dump_inline_scripts(page: Any, *, max_chars: int = 200_000) -> list[dict[str, Any]]:
    try:
        data = await page.evaluate(INLINE_SCRIPTS_JS, max_chars)
        return data if isinstance(data, list) else []
    except Exception as e:  # noqa: BLE001
        logger.warning("inline scripts failed: %s", e)
        return []


async def download_scripts(
    script_urls: list[str],
    *,
    base_url: str | None = None,
    max_scripts: int = 20,
    max_bytes: int = 500_000,
    timeout_s: float = 20.0,
    proxy: str | None = None,
) -> list[dict[str, Any]]:
    """Download external scripts with httpx."""
    import httpx

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    client_kwargs: dict[str, Any] = {"timeout": timeout_s, "follow_redirects": True}
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        for raw in script_urls:
            if len(results) >= max_scripts:
                break
            if not raw:
                continue
            url = urljoin(base_url or "", raw) if base_url else raw
            if not url.startswith("http"):
                continue
            if url in seen:
                continue
            seen.add(url)
            entry: dict[str, Any] = {"url": url, "ok": False}
            try:
                resp = await client.get(url)
                entry["status"] = resp.status_code
                entry["content_type"] = resp.headers.get("content-type", "")
                raw_bytes = resp.content[:max_bytes]
                entry["bytes"] = len(resp.content)
                entry["truncated"] = len(resp.content) > max_bytes
                entry["content"] = raw_bytes.decode("utf-8", errors="replace")
                entry["ok"] = resp.is_success
            except Exception as e:  # noqa: BLE001
                entry["error"] = str(e)
            results.append(entry)
    return results


def search_in_text(
    text: str,
    patterns: list[str],
    *,
    source: str,
    max_matches_per_pattern: int = 15,
    context: int = 80,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for pat in patterns:
        try:
            cre = re.compile(pat, re.I | re.M)
        except re.error as e:
            hits.append({"source": source, "pattern": pat, "error": f"bad regex: {e}"})
            continue
        count = 0
        for m in cre.finditer(text):
            if count >= max_matches_per_pattern:
                break
            start = max(0, m.start() - context)
            end = min(len(text), m.end() + context)
            hits.append(
                {
                    "source": source,
                    "pattern": pat,
                    "match": m.group(0)[:300],
                    "context": text[start:end].replace("\n", " ")[:400],
                    "offset": m.start(),
                }
            )
            count += 1
    return hits


def search_scripts(
    scripts: list[dict[str, Any]],
    patterns: list[str] | None = None,
    *,
    max_matches_per_pattern: int = 12,
) -> list[dict[str, Any]]:
    patterns = patterns or DEFAULT_SEARCH_PATTERNS
    all_hits: list[dict[str, Any]] = []
    for s in scripts:
        content = s.get("content") or ""
        if not content:
            continue
        source = s.get("url") or s.get("id") or ("inline:" + str(s.get("length", 0)))
        all_hits.extend(
            search_in_text(
                content,
                patterns,
                source=str(source),
                max_matches_per_pattern=max_matches_per_pattern,
            )
        )
    return all_hits


def absolute_script_urls(scripts: list[dict[str, Any]], page_url: str) -> list[str]:
    out: list[str] = []
    for s in scripts:
        src = s.get("src")
        if not src:
            continue
        abs_url = urljoin(page_url, str(src))
        if abs_url.startswith("http"):
            out.append(abs_url)
    return out


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc
    except Exception:  # noqa: BLE001
        return ""
