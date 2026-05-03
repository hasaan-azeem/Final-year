import aiohttp
import asyncio
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser
import logging
from typing import Dict

logger = logging.getLogger("webxguard.robots")

# -----------------------------
# GLOBAL STATE
# -----------------------------
robots_cache: Dict[str, RobotFileParser] = {}
robots_lock = asyncio.Lock()

session_lock = asyncio.Lock()
_shared_session: aiohttp.ClientSession | None = None

# -----------------------------
# SHARED SESSION (SAFE)
# -----------------------------
async def get_session() -> aiohttp.ClientSession:
    """
    Returns a shared aiohttp session.
    Thread-safe + prevents session explosion.
    """
    global _shared_session

    async with session_lock:
        if _shared_session is None or _shared_session.closed:
            timeout = aiohttp.ClientTimeout(
                total=10,
                connect=5,
                sock_read=5,
            )
            connector = aiohttp.TCPConnector(
                limit=100,              # concurrent connections
                limit_per_host=20,
                ssl=False,              # avoid SSL crashes (optional)
            )
            _shared_session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": "WebXGuardBot/1.0"},
            )
            logger.info("[Robots] Created shared session")

    return _shared_session


async def close_session():
    """
    Gracefully close shared session.
    """
    global _shared_session
    async with session_lock:
        if _shared_session and not _shared_session.closed:
            await _shared_session.close()
            logger.info("[Robots] Shared session closed")


# -----------------------------
# ROBOTS FETCH
# -----------------------------
async def fetch_robots_txt(url: str) -> RobotFileParser:
    """
    Fetch and cache robots.txt safely.
    Never crashes scanner.
    Fail-open policy.
    """

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            logger.warning(f"[Robots] Invalid URL: {url}")
            return RobotFileParser()  # allow by default

        base = f"{parsed.scheme}://{parsed.netloc}"

        # Fast path: cached
        async with robots_lock:
            if base in robots_cache:
                return robots_cache[base]

        rp = RobotFileParser()
        rp.set_url(f"{base}/robots.txt")

        try:
            session = await get_session()

            async with session.get(rp.url, allow_redirects=True) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    await asyncio.to_thread(rp.parse, text.splitlines())
                    logger.debug(f"[Robots] Parsed robots.txt for {base}")
                else:
                    logger.debug(f"[Robots] No robots.txt ({resp.status}) at {base}")
                    await asyncio.to_thread(rp.parse, [])  # fail-open

        except asyncio.TimeoutError:
            logger.warning(f"[Robots] Timeout fetching {rp.url}")
            await asyncio.to_thread(rp.parse, [])

        except aiohttp.ClientError as e:
            logger.warning(f"[Robots] Client error fetching {rp.url}: {e}")
            await asyncio.to_thread(rp.parse, [])

        except Exception as e:
            logger.exception(f"[Robots] Unexpected error fetching {rp.url}: {e}")
            await asyncio.to_thread(rp.parse, [])

        # Cache safely
        async with robots_lock:
            robots_cache[base] = rp

        return rp

    except Exception as fatal:
        logger.exception(f"[Robots] Fatal error in fetch_robots_txt: {fatal}")
        return RobotFileParser()  # never crash scanner


# -----------------------------
# CAN FETCH (SAFE)
# -----------------------------
async def can_fetch(url: str, user_agent: str = "*") -> bool:
    """
    Safe robots check.
    Never crashes.
    Defaults to allow on failure.
    """

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return True

        base = f"{parsed.scheme}://{parsed.netloc}"

        if base not in robots_cache:
            await fetch_robots_txt(url)

        rp = robots_cache.get(base)

        if not rp:
            return True

        allowed = await asyncio.to_thread(rp.can_fetch, user_agent, url)

        logger.debug(f"[Robots] can_fetch({url}) = {allowed}")
        return allowed

    except Exception as e:
        logger.exception(f"[Robots] Error in can_fetch for {url}: {e}")
        return True  # fail-open policy