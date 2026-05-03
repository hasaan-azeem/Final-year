import re
import hashlib
import logging
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from .utils import normalize_url

logger = logging.getLogger("webxguard.parser")

# ==================================================
# SAFE HTML PARSER
# ==================================================
def _safe_soup(html: str) -> Optional[BeautifulSoup]:
    try:
        if not html:
            return None
        return BeautifulSoup(html, "lxml")
    except Exception as e:
        logger.debug(f"Soup parsing failed: {e}")
        return None


# ==================================================
# SPA DETECTION
# ==================================================
def detect_spa_shell(html: str) -> bool:
    try:
        if not html:
            return False
        html_lower = html.lower()
        return (
            '<div id="root"' in html_lower
            or '<div id="app"' in html_lower
            or "window.__nuxt__" in html_lower
            or "data-reactroot" in html_lower
            or "ng-version" in html_lower
        )
    except Exception:
        return False


# ==================================================
# JS FALLBACK DECISION
# ==================================================
def should_js_fallback(
    links: List[str],
    forms: List[Dict],
    js_routes: List[str],
    html: str
) -> bool:
    try:
        if detect_spa_shell(html):
            return True
        if not links and (js_routes or "script" in html.lower()):
            return True
        if not links and not forms:
            return True
        return False
    except Exception:
        return False


# ==================================================
# DOM FINGERPRINT
# ==================================================
def dom_fingerprint(html: str) -> str:
    try:
        soup = _safe_soup(html)
        if not soup:
            return ""
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
    except Exception as e:
        logger.debug(f"DOM fingerprint failed: {e}")
        return ""


# ==================================================
# LINK EXTRACTION
# ==================================================
def extract_links(
    base_url: str,
    html: str,
    allowed_domains: Optional[List[str]] = None
) -> List[str]:

    try:
        soup = _safe_soup(html)
        if not soup:
            return []

        discovered = set()
        allowed_domains = allowed_domains or []

        for a in soup.find_all("a", href=True):
            url = normalize_url(base_url, a.get("href"))
            if not url:
                continue

            if not allowed_domains:
                discovered.add(url)
            else:
                try:
                    netloc = urlparse(url).netloc
                    if any(netloc.endswith(d) for d in allowed_domains):
                        discovered.add(url)
                except Exception:
                    continue

        return list(discovered)

    except Exception as e:
        logger.debug(f"Link extraction failed: {e}")
        return []


# ==================================================
# FORM EXTRACTION
# ==================================================
def extract_forms(base_url: str, html: str) -> List[Dict]:

    try:
        soup = _safe_soup(html)
        if not soup:
            return []

        forms = []

        for form in soup.find_all("form"):
            try:
                action = normalize_url(base_url, form.get("action", ""))
                method = form.get("method", "GET").upper()

                inputs = []
                for tag in form.find_all(["input", "textarea", "select"]):
                    name = tag.get("name")
                    if not name:
                        continue

                    inputs.append({
                        "name": name,
                        "type": tag.get("type", tag.name),
                        "id": tag.get("id"),
                        "placeholder": tag.get("placeholder"),
                    })

                forms.append({
                    "action": action,
                    "method": method,
                    "inputs": inputs
                })

            except Exception:
                continue

        return forms

    except Exception as e:
        logger.debug(f"Form extraction failed: {e}")
        return []

# ==================================================
# JS ENDPOINT EXTRACTION
# ==================================================
API_REGEX = re.compile(
    r"""(?:
        fetch\s*\(\s*["']([^"']+)["']|
        axios\.(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']|
        XMLHttpRequest.*?open\(["'](?:GET|POST)["'],\s*["']([^"']+)["']|
        ["'](https?:\/\/[^"']+)["']
    )""",
    re.VERBOSE,
)


def extract_js_endpoints(base_url: str, html: str) -> List[str]:

    try:
        if not html:
            return []

        endpoints = set()

        for match in API_REGEX.findall(html):
            for group in match:
                if not group:
                    continue
                try:
                    url = urljoin(base_url, group) if group.startswith("/") else group
                    normalized = normalize_url(base_url, url)
                    if normalized:
                        endpoints.add(normalized)
                except Exception:
                    continue

        return list(endpoints)

    except Exception as e:
        logger.debug(f"JS endpoint extraction failed: {e}")
        return []


# ==================================================
# JS BUNDLE ROUTES
# ==================================================
def extract_js_bundle_routes(base_url: str, html: str) -> List[str]:

    try:
        soup = _safe_soup(html)
        if not soup:
            return []

        routes = set()

        # Script src
        for s in soup.find_all("script", src=True):
            try:
                normalized = normalize_url(base_url, s.get("src"))
                if normalized:
                    routes.add(normalized)
            except Exception:
                continue

        # Inline route patterns
        inline_routes = re.findall(r'["\'](/[\w\-/]+)["\']', html)
        for r in inline_routes:
            try:
                normalized = normalize_url(base_url, r)
                if normalized:
                    routes.add(normalized)
            except Exception:
                continue

        return list(routes)

    except Exception as e:
        logger.debug(f"JS bundle route extraction failed: {e}")
        return []


# ==================================================
# WEBSOCKET DISCOVERY
# ==================================================
WS_REGEX = re.compile(r"(wss?:\/\/[^\s'\"<>]+)")

def extract_websockets(html: str) -> List[str]:
    try:
        if not html:
            return []
        return list(set(WS_REGEX.findall(html)))
    except Exception:
        return []


# ==================================================
# PAGINATION DETECTION
# ==================================================
PAGINATION_PATTERNS = [
    r"[?&]page=\d+",
    r"/page/\d+",
    r"[?&]p=\d+",
    r"[?&]start=\d+"
]

def detect_pagination_links(base_url: str, html: str) -> List[str]:

    try:
        links = set()

        for pattern in PAGINATION_PATTERNS:
            for m in re.findall(pattern, html or ""):
                try:
                    full_url = urljoin(base_url, m)
                    normalized = normalize_url(base_url, full_url)
                    if normalized:
                        links.add(normalized)
                except Exception:
                    continue

        soup = _safe_soup(html)
        if soup:
            for a in soup.find_all("a", href=True):
                text = a.get_text(strip=True).lower()
                if "next" in text or "load more" in text:
                    try:
                        url = normalize_url(base_url, a.get("href"))
                        if url:
                            links.add(url)
                    except Exception:
                        continue

        return list(links)

    except Exception as e:
        logger.debug(f"Pagination detection failed: {e}")
        return []


# ==================================================
# MAIN PARSER
# ==================================================
def parse_page(
    base_url: str,
    html: str,
    allowed_domains: Optional[List[str]] = None
) -> Tuple[List[str], List[Dict], List[str], List[str], List[str]]:

    try:
        allowed_domains = allowed_domains or []

        links = extract_links(base_url, html, allowed_domains)
        pagination_links = detect_pagination_links(base_url, html)

        # Deduplicated + ordered
        all_links = list(dict.fromkeys(links + pagination_links))

        forms = extract_forms(base_url, html)
        js_endpoints = extract_js_endpoints(base_url, html)
        js_routes = extract_js_bundle_routes(base_url, html)
        ws_endpoints = extract_websockets(html)

        return all_links, forms, js_endpoints, js_routes, ws_endpoints

    except Exception as e:
        logger.error(f"parse_page crashed: {e}")
        return [], [], [], [], []