import aiohttp
import asyncio
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import logging
from typing import List, Set

from .utils import normalize_url, deduplicate
from ..config import USER_AGENT

logger = logging.getLogger("webxguard.sitemap")

# -----------------------------
# CONFIG
# -----------------------------
MAX_RETRIES = 3
MAX_SITEMAP_DEPTH = 2        # prevent infinite sitemap recursion
PER_HOST_LIMIT = 5           # concurrency control


# -----------------------------
# MAIN ENTRY
# -----------------------------
async def fetch_sitemap(
    base_url: str,
    session: aiohttp.ClientSession | None = None
) -> List[str]:
    """
    Fetch sitemap URLs asynchronously.
    Supports sitemap index recursion.
    Fully crash-safe.
    """

    sitemap_urls: Set[str] = set()
    possible_paths = [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap-index.xml"
    ]

    own_session = False

    if session is None:
        timeout = aiohttp.ClientTimeout(
            total=15,
            connect=5,
            sock_connect=5,
            sock_read=10,
        )
        connector = aiohttp.TCPConnector(
            limit_per_host=PER_HOST_LIMIT,
            ssl=False
        )
        session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            connector=connector
        )
        own_session = True

    try:
        tasks = [
            _fetch_single_sitemap(
                urljoin(base_url, path),
                session,
                base_url,
                depth=0
            )
            for path in possible_paths
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, list):
                sitemap_urls.update(res)
            elif isinstance(res, Exception):
                logger.debug(f"[Sitemap] Task error: {res}")

    except Exception as e:
        logger.exception(f"[Sitemap] Fatal error in fetch_sitemap: {e}")

    finally:
        if own_session:
            await session.close()

    return deduplicate(list(sitemap_urls))


# -----------------------------
# SINGLE SITEMAP FETCH
# -----------------------------
async def _fetch_single_sitemap(
    url: str,
    session: aiohttp.ClientSession,
    base_url: str,
    depth: int = 0
) -> List[str]:
    """
    Fetch a single sitemap (supports sitemap index recursion).
    """

    if depth > MAX_SITEMAP_DEPTH:
        logger.debug(f"[Sitemap] Max depth reached at {url}")
        return []

    urls: Set[str] = set()

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status != 200:
                    logger.debug(f"[Sitemap] {url} returned {resp.status}")
                    return []

                content_type = resp.headers.get("Content-Type", "").lower()
                if "xml" not in content_type:
                    logger.debug(f"[Sitemap] {url} not XML ({content_type})")
                    return []

                text = await resp.text(errors="ignore")
                soup = BeautifulSoup(text, "xml")

                # -------------------------
                # Handle Sitemap Index
                # -------------------------
                sitemap_tags = soup.find_all("sitemap")
                if sitemap_tags:
                    logger.info(f"[Sitemap] Found sitemap index at {url}")

                    tasks = []
                    for sm in sitemap_tags:
                        loc = sm.find("loc")
                        if loc and loc.text:
                            child_url = loc.text.strip()
                            tasks.append(
                                _fetch_single_sitemap(
                                    child_url,
                                    session,
                                    base_url,
                                    depth + 1
                                )
                            )

                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    for r in results:
                        if isinstance(r, list):
                            urls.update(r)

                    return list(urls)

                # -------------------------
                # Handle Normal URL Sitemap
                # -------------------------
                loc_tags = soup.find_all("loc")
                for loc in loc_tags:
                    try:
                        normalized = normalize_url(base_url, loc.text.strip())
                        if normalized:
                            urls.add(normalized)
                    except Exception:
                        continue

                logger.info(f"[Sitemap] Extracted {len(urls)} URLs from {url}")
                return list(urls)

        except asyncio.TimeoutError:
            logger.warning(f"[Sitemap] Timeout {url} attempt {attempt}/{MAX_RETRIES}")
            await asyncio.sleep(1)

        except aiohttp.ClientError as e:
            logger.warning(f"[Sitemap] Client error {url} attempt {attempt}: {e}")
            await asyncio.sleep(1)

        except Exception as e:
            logger.exception(f"[Sitemap] Unexpected error at {url}: {e}")
            return []

    return []