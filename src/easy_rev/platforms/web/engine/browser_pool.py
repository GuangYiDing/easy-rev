"""Warm browser session pool for bulk farm throughput.

Proxy is part of the launch fingerprint (Camoufox sets proxy at process start),
so workers are keyed by ``(engine, headless, locale, humanize, proxy)``. After
each task the page is recycled (new page + cookie clear) for account isolation
without a full browser relaunch.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from easy_rev.core.types import BrowserProfile, ProxyEndpoint
from easy_rev.platforms.web.engine.base import BrowserEngine, BrowserSession

logger = logging.getLogger(__name__)


def proxy_fingerprint(proxy: ProxyEndpoint | None) -> str:
    if proxy is None:
        return "direct"
    return f"{proxy.server}|{proxy.username or ''}|{proxy.password or ''}"


def launch_key(profile: BrowserProfile, *, engine_name: str = "") -> str:
    return "|".join(
        [
            engine_name or "engine",
            "h1" if profile.headless else "h0",
            profile.locale or "en-US",
            "hum1" if profile.humanize else "hum0",
            "geo1" if profile.geoip else "geo0",
            profile.timezone_id or "-",
            proxy_fingerprint(profile.proxy),
        ]
    )


async def recycle_session(session: BrowserSession) -> None:
    """Best-effort isolate next account: new page + clear cookies/storage."""
    if hasattr(session, "recycle") and callable(session.recycle):
        await session.recycle()  # type: ignore[misc]
        return

    page = getattr(session, "page", None)
    browser = getattr(session, "_browser", None)

    context = None
    if page is not None:
        context = getattr(page, "context", None)
        try:
            await page.close()
        except Exception:  # noqa: BLE001
            pass

    if context is not None:
        try:
            if hasattr(context, "clear_cookies"):
                await context.clear_cookies()
        except Exception:  # noqa: BLE001
            pass

    if browser is not None and hasattr(browser, "new_page"):
        session.page = await browser.new_page()
        return

    if page is not None and hasattr(page, "goto"):
        try:
            await page.goto("about:blank")
        except Exception:  # noqa: BLE001
            pass


@dataclass
class _Worker:
    key: str
    session: BrowserSession
    profile: BrowserProfile
    in_use: bool = False
    uses: int = 0
    created_at: float = field(default_factory=time.monotonic)
    last_used_at: float = field(default_factory=time.monotonic)
    recycled: int = 0  # successful recycle count


class PooledSession(BrowserSession):
    """Wrapper exposing ``.page``; release goes through the pool."""

    def __init__(self, pool: BrowserPool, worker: _Worker, *, from_pool: bool) -> None:
        self._pool = pool
        self._worker = worker
        self.page = worker.session.page
        self.from_pool = from_pool
        self.launch_key = worker.key
        self._released = False

    async def close(self) -> None:
        if self._released:
            return
        self._released = True
        await self._pool.release(self._worker, destroy=False)

    async def destroy(self) -> None:
        if self._released:
            return
        self._released = True
        await self._pool.release(self._worker, destroy=True)


class BrowserPool:
    """Bounded pool of warm browser sessions."""

    def __init__(
        self,
        engine: BrowserEngine,
        *,
        max_size: int = 4,
        max_uses: int = 25,
        acquire_timeout_s: float = 120.0,
    ) -> None:
        self.engine = engine
        self.engine_name = getattr(engine, "name", "engine")
        self.max_size = max(1, max_size)
        self.max_uses = max(1, max_uses)
        self.acquire_timeout_s = max(1.0, acquire_timeout_s)
        self._workers: list[_Worker] = []
        self._lock = asyncio.Lock()
        self._cond = asyncio.Condition(self._lock)
        self._closed = False
        self._stats = {
            "created": 0,
            "reused": 0,
            "destroyed": 0,
            "acquire_waits": 0,
            "recycle_errors": 0,
        }

    def stats(self) -> dict[str, Any]:
        return {
            **self._stats,
            "size": len(self._workers),
            "in_use": sum(1 for w in self._workers if w.in_use),
            "max_size": self.max_size,
            "max_uses": self.max_uses,
            "engine": self.engine_name,
        }

    async def acquire(self, profile: BrowserProfile) -> PooledSession:
        if self._closed:
            raise RuntimeError("BrowserPool is closed")
        key = launch_key(profile, engine_name=self.engine_name)
        deadline = time.monotonic() + self.acquire_timeout_s

        while True:
            need_recycle = False
            async with self._cond:
                if self._closed:
                    raise RuntimeError("BrowserPool is closed")

                worker = self._take_matching_unlocked(key)
                from_pool = False
                if worker is not None:
                    from_pool = True
                    need_recycle = True
                    self._stats["reused"] += 1
                elif len(self._workers) < self.max_size:
                    worker = await self._create_worker_unlocked(key, profile)
                    from_pool = False
                else:
                    idle = next((w for w in self._workers if not w.in_use), None)
                    if idle is not None:
                        await self._destroy_worker_unlocked(idle)
                        worker = await self._create_worker_unlocked(key, profile)
                        from_pool = False
                    else:
                        self._stats["acquire_waits"] += 1
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError(
                                f"BrowserPool acquire timeout key={key[:80]} "
                                f"size={len(self._workers)}"
                            )
                        try:
                            await asyncio.wait_for(self._cond.wait(), timeout=remaining)
                        except TimeoutError as e:
                            raise TimeoutError(
                                f"BrowserPool acquire timeout key={key[:80]}"
                            ) from e
                        continue

            assert worker is not None
            if need_recycle:
                try:
                    await recycle_session(worker.session)
                    worker.recycled += 1
                except Exception as e:  # noqa: BLE001
                    self._stats["recycle_errors"] += 1
                    logger.warning("browser recycle failed, recreating: %s", e)
                    async with self._cond:
                        await self._destroy_worker_unlocked(worker)
                        worker = await self._create_worker_unlocked(key, profile)
                        from_pool = False
            return PooledSession(self, worker, from_pool=from_pool)

    def _take_matching_unlocked(self, key: str) -> _Worker | None:
        for w in self._workers:
            if not w.in_use and w.key == key:
                w.in_use = True
                w.uses += 1
                w.last_used_at = time.monotonic()
                return w
        return None

    async def _create_worker_unlocked(self, key: str, profile: BrowserProfile) -> _Worker:
        session = await self.engine.launch_session(profile)
        w = _Worker(key=key, session=session, profile=profile, in_use=True, uses=1)
        self._workers.append(w)
        self._stats["created"] += 1
        logger.debug(
            "browser pool create key=%s size=%s/%s",
            key[:60],
            len(self._workers),
            self.max_size,
        )
        return w

    async def _destroy_worker_unlocked(self, worker: _Worker) -> None:
        if worker in self._workers:
            self._workers.remove(worker)
        try:
            await worker.session.close()
        except Exception:  # noqa: BLE001
            logger.exception("failed destroying pooled browser")
        self._stats["destroyed"] += 1
        worker.in_use = False

    async def release(self, worker: _Worker, *, destroy: bool = False) -> None:
        async with self._cond:
            if worker not in self._workers:
                return
            if destroy or worker.uses >= self.max_uses:
                await self._destroy_worker_unlocked(worker)
            else:
                worker.in_use = False
                worker.last_used_at = time.monotonic()
            self._cond.notify_all()

    @asynccontextmanager
    async def session(
        self,
        profile: BrowserProfile,
        *,
        destroy_on_error: bool = True,
        destroy_always: bool = False,
    ) -> AsyncIterator[PooledSession]:
        lease = await self.acquire(profile)
        failed = False
        try:
            yield lease
        except Exception:
            failed = True
            raise
        finally:
            if not lease._released:
                lease._released = True
                destroy = destroy_always or (destroy_on_error and failed)
                try:
                    await self.release(lease._worker, destroy=destroy)
                except Exception:  # noqa: BLE001
                    logger.exception("browser pool release failed")

    async def close(self) -> None:
        async with self._cond:
            self._closed = True
            workers = list(self._workers)
            self._workers.clear()
            self._cond.notify_all()
        for w in workers:
            try:
                await w.session.close()
            except Exception:  # noqa: BLE001
                pass
            self._stats["destroyed"] += 1
