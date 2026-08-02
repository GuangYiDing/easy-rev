"""Web reverse-engineering helpers: network capture, script analysis, HTTP replay."""

from __future__ import annotations

from easy_rev.platforms.web.re.classify import classify_entry, rank_api_candidates
from easy_rev.platforms.web.re.http_client import HttpClient, HttpResult
from easy_rev.platforms.web.re.network import NetworkCapture, NetworkEntry
from easy_rev.platforms.web.re.protocol import flow_needs_browser, is_protocol_engine

__all__ = [
    "NetworkCapture",
    "NetworkEntry",
    "classify_entry",
    "rank_api_candidates",
    "HttpClient",
    "HttpResult",
    "flow_needs_browser",
    "is_protocol_engine",
]
