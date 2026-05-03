import aiohttp
import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("AuthManager")


# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM SIGNATURES
# ─────────────────────────────────────────────────────────────────────────────

PLATFORM_SIGNATURES: Dict[str, List[str]] = {
    "wordpress": ["wp-login", "wp-content", "wordpress", "wp-admin", "wp-json"],
    "moodle":    ["moodledata", "sesskey", "moodlesession", "moodle", "logintoken"],
    "joomla":    ["joomla", "com_users", "mod_login", "joomla.org"],
    "drupal":    ["drupal", "drupal.settings", "sites/default/files"],
    "django":    ["csrfmiddlewaretoken", "django", "__admin_media_prefix__"],
    "laravel":   ["laravel_session", "_token", "illuminate"],
    "rails":     ["authenticity_token", "rails-ujs"],
    "asp_net":   ["__viewstate", "__eventvalidation", "aspnetform"],
}

PLATFORM_SUCCESS: Dict[str, List[str]] = {
    "wordpress": ["wp-admin", "howdy", "dashboard", "my sites", "new post", "site-title"],
    "moodle":    [
        "my/", "moodledata", "logout", "skip to main",
        "my courses", "course overview", "dashboard",
    ],
    "joomla":    ["administrator", "component/content", "joomla.debug.console"],
    "drupal":    ["user/logout", "admin/content", "admin/structure"],
    "django":    ["logout", "admin/", "object-tools", "django-admin"],
    "laravel":   ["dashboard", "logout", "home", "csrf-token"],
    "rails":     ["sign_out", "dashboard", "edit_user"],
    "asp_net":   ["logoff", "account/manage", "dashboard"],
    "generic":   [
        "logout", "log out", "sign out", "signout",
        "dashboard", "profile", "account", "my account",
        "welcome back", "my profile", "user panel",
        "admin panel", "control panel",
        "logged in as", "hello,", "hi,",
        "your account", "settings", "preferences",
        "student courses", "my courses", "enrolled",
    ],
}

PLATFORM_FAILURE: Dict[str, List[str]] = {
    "wordpress": ["incorrect password", "unknown email", "error", "invalid username"],
    "moodle":    ["invalid login", "too many failed", "login error", "invalid username or password"],
    "joomla":    ["com_users&view=login", "invalid", "login failed"],
    "drupal":    ["unrecognized username", "have not specified a password", "too many failed"],
    "django":    ["please enter a correct", "required field", "this field is required"],
    "laravel":   ["these credentials do not match", "too many login attempts"],
    "rails":     ["invalid email or password", "account locked"],
    "asp_net":   ["login failed", "invalid credentials", "username or password"],
    "generic":   [
        "invalid password", "incorrect password", "wrong password",
        "invalid credentials", "login failed", "authentication failed",
        "invalid email", "account not found", "no account",
        "too many attempts", "captcha", "invalid username",
        "username or password is incorrect",
        "the username or password you entered",
        "غلط پاس ورڈ", "غلط",
        "لاگ ان ناکام",
    ],
}

COMMON_LOGIN_PATHS: List[str] = [
    "/login",
    "/login/index.php",
    "/wp-login.php",
    "/user/login",
    "/accounts/login",
    "/admin/login",
    "/admin",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/portal/login",
    "/student/login",
    "/Student/",
    "/index.php?option=com_users&view=login",
    "/login.php",
    "/panel/login",
    "/dashboard/login",
    "/index.php/login",
]


class AuthManager:
    """
    🔧 FIXED: Multi-platform authentication manager with:
    • Better session expiration detection (requires BOTH login form + failure keywords)
    • Returns authenticated URL for enqueuing
    • No false positives on sites with persistent login forms
    """

    def __init__(self):
        self.domains:      Dict[str, dict] = {}
        self.lock          = asyncio.Lock()
        self._login_urls:  Dict[str, str]  = {}
        self._platforms:   Dict[str, str]  = {}

    # ─────────────────────────────────────────────────────────────────────────
    # DOMAIN STATE
    # ─────────────────────────────────────────────────────────────────────────

    def init_domain(self, domain: str):
        if not domain:
            return
        if domain not in self.domains:
            self.domains[domain] = {
                "authenticated": False,
                "auth_type":     "guest",
                "expired":       False,
                "authenticated_url": None,  # 🔧 FIX-8: Store auth landing page
            }

    def phase(self, domain: str) -> str:
        return "auth" if self.domains.get(domain, {}).get("authenticated") else "guest"

    # ─────────────────────────────────────────────────────────────────────────
    # PLATFORM DETECTION
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_platform(self, html: str) -> str:
        """Detect CMS/framework from HTML. Returns a platform key or 'generic'."""
        if not html:
            return "generic"
        html_lower = html.lower()
        for platform, signals in PLATFORM_SIGNATURES.items():
            if any(sig in html_lower for sig in signals):
                logger.debug(f"[Auth] Detected platform: {platform}")
                return platform
        return "generic"

    def _get_success_keywords(self, platform: str) -> List[str]:
        platform_kws = PLATFORM_SUCCESS.get(platform, [])
        generic_kws  = PLATFORM_SUCCESS.get("generic", [])
        return list(dict.fromkeys(platform_kws + generic_kws))

    def _get_failure_keywords(self, platform: str) -> List[str]:
        platform_kws = PLATFORM_FAILURE.get(platform, [])
        generic_kws  = PLATFORM_FAILURE.get("generic", [])
        return list(dict.fromkeys(platform_kws + generic_kws))

    # ─────────────────────────────────────────────────────────────────────────
    # LOGIN URL AUTO-DISCOVERY
    # ─────────────────────────────────────────────────────────────────────────

    async def discover_login_url(
        self,
        session:        aiohttp.ClientSession,
        base_url:       str,
        configured_url: Optional[str] = None,
        timeout:        Optional[aiohttp.ClientTimeout] = None,
    ) -> Tuple[Optional[str], str]:
        """
        Auto-discover the actual login URL for a domain.

        Strategy:
          1. Return cached result if already discovered for this domain
          2. Try the configured login URL first
          3. Probe COMMON_LOGIN_PATHS in order
          4. Return the first URL whose response contains <input type="password">

        Returns: (login_url | None, platform)
        """
        timeout = timeout or aiohttp.ClientTimeout(total=12)
        parsed  = urlparse(base_url)
        base    = f"{parsed.scheme}://{parsed.netloc}"
        domain  = parsed.netloc

        # Return cached result
        if domain in self._login_urls:
            return self._login_urls[domain], self._platforms.get(domain, "generic")

        candidates: List[str] = []
        if configured_url:
            candidates.append(configured_url)
        candidates.extend(urljoin(base, path) for path in COMMON_LOGIN_PATHS)

        for candidate in candidates:
            try:
                async with session.get(
                    candidate, timeout=timeout, allow_redirects=True
                ) as r:
                    if r.status != 200:
                        continue
                    html = await r.text(errors="ignore")
                    soup = BeautifulSoup(html, "html.parser")
                    if soup.find("input", {"type": "password"}):
                        platform = self._detect_platform(html)
                        self._login_urls[domain] = candidate
                        self._platforms[domain]  = platform
                        logger.info(
                            f"[Auth] Discovered login URL for {domain}: "
                            f"{candidate} (platform={platform})"
                        )
                        return candidate, platform
            except Exception as e:
                logger.debug(f"[Auth] Probe failed for {candidate}: {e}")
                continue

        logger.warning(f"[Auth] Could not discover login URL for {domain}")
        return None, "generic"

    # ─────────────────────────────────────────────────────────────────────────
    # CREDENTIAL LOGIN
    # ─────────────────────────────────────────────────────────────────────────

    async def credential_login(
        self,
        session:          aiohttp.ClientSession,
        domain:           str,
        login_url:        str,
        username:         str,
        password:         str,
        user_field:       str,
        pass_field:       str,
        success_keywords: Optional[List[str]] = None,
    ) -> bool:
        self.init_domain(domain)
        timeout  = aiohttp.ClientTimeout(total=20)
        base_url = f"https://{domain}"

        # ── Step 1: Discover actual login URL ─────────────────────────────
        actual_url, platform = await self.discover_login_url(
            session        = session,
            base_url       = base_url,
            configured_url = login_url,
            timeout        = timeout,
        )

        if not actual_url:
            logger.warning(
                f"[{domain}] Discovery failed — "
                f"falling back to configured URL: {login_url}"
            )
            actual_url = login_url
            platform   = "generic"

        # ── Step 2: GET the login page ────────────────────────────────────
        try:
            async with session.get(actual_url, timeout=timeout) as r:
                html = await r.text(errors="ignore")
        except Exception as e:
            logger.error(f"[{domain}] GET login page failed: {e}")
            return False

        # Re-detect platform from live HTML (more accurate than URL alone)
        platform                = self._detect_platform(html)
        self._platforms[domain] = platform
        logger.info(f"[{domain}] Platform: {platform}  Login URL: {actual_url}")

        # ── Step 3: Build keyword sets ────────────────────────────────────
        effective_success = success_keywords or self._get_success_keywords(platform)
        effective_failure = self._get_failure_keywords(platform)

        # ── Step 4: Extract form ──────────────────────────────────────────
        form_data, action_url = self._extract_login_form(html, actual_url, pass_field)

        if not form_data or not action_url:
            logger.warning(
                f"[{domain}] No login form found — trying JSON login"
            )
            return await self._json_login(
                session, domain, actual_url,
                username, password, user_field, pass_field,
                effective_success, effective_failure, timeout,
            )

        form_data[user_field] = username
        form_data[pass_field] = password

        logger.info(
            f"[{domain}] POSTing form → action={action_url} "
            f"fields={list(form_data.keys())}"
        )

        # ── Step 5: POST ──────────────────────────────────────────────────
        try:
            async with session.post(
                action_url,
                data=form_data,
                timeout=timeout,
                allow_redirects=True,
            ) as r:
                body      = await r.text(errors="ignore")
                final_url = str(r.url)
                status    = r.status
        except Exception as e:
            logger.error(f"[{domain}] POST login failed: {e}")
            return False

        # ── Step 6: Validate ──────────────────────────────────────────────
        success = self._validate_login(
            body, final_url, status,
            effective_success, effective_failure,
        )
        self.domains[domain].update({
            "authenticated": success,
            "auth_type":     "credential" if success else "guest",
            "expired":       False,
            "authenticated_url": final_url if success else None,  # 🔧 FIX-8
        })
        logger.info(
            f"[{domain}] Login success={success} "
            f"status={status} final_url={final_url}"
        )
        return success

    # ─────────────────────────────────────────────────────────────────────────
    # JSON LOGIN FALLBACK  (SPA / API-based auth)
    # ─────────────────────────────────────────────────────────────────────────

    async def _json_login(
        self,
        session:          aiohttp.ClientSession,
        domain:           str,
        login_url:        str,
        username:         str,
        password:         str,
        user_field:       str,
        pass_field:       str,
        success_keywords: List[str],
        failure_keywords: List[str],
        timeout:          aiohttp.ClientTimeout,
    ) -> bool:
        payload = {user_field: username, pass_field: password}
        try:
            async with session.post(
                login_url,
                json=payload,
                timeout=timeout,
                allow_redirects=True,
            ) as r:
                body      = await r.text(errors="ignore")
                final_url = str(r.url)
                status    = r.status
        except Exception as e:
            logger.error(f"[{domain}] JSON login POST failed: {e}")
            return False

        success = self._validate_login(
            body, final_url, status,
            success_keywords, failure_keywords,
        )
        self.domains[domain].update({
            "authenticated": success,
            "auth_type":     "credential" if success else "guest",
            "expired":       False,
            "authenticated_url": final_url if success else None,  # 🔧 FIX-8
        })
        logger.info(f"[{domain}] JSON login success={success} status={status}")
        return success

    # ─────────────────────────────────────────────────────────────────────────
    # SESSION EXPIRATION DETECTION (FIXED)
    # ─────────────────────────────────────────────────────────────────────────

    def detect_expiration(
        self,
        domain:   str,
        response: aiohttp.ClientResponse,
        body:     str,
    ):
        self.init_domain(domain)
        expired = False
    
        LOGIN_PATH_INDICATORS = (
            "/login", "/signin", "/sign-in", "/auth/login",
            "wp-login.php", "com_users", "user/login",
            "accounts/login", "/login/index.php",
        )
    
        if response and response.status in (401, 403):
            expired = True
            logger.warning(f"[{domain}] Session expired via HTTP {response.status}")
    
        elif body and self.domains[domain].get("authenticated"):
            soup = BeautifulSoup(body, "html.parser")
            has_login_form = bool(soup.find("input", {"type": "password"}))
    
            # FIX: check the actual response URL — silent redirects to /login
            # produce no failure keywords, so the old check missed them entirely
            response_url = str(response.url).lower() if response else ""
            redirected_to_login = any(
                ind in response_url for ind in LOGIN_PATH_INDICATORS
            )
    
            platform = self._platforms.get(domain, "generic")
            failure_kws = self._get_failure_keywords(platform)
            has_failure_kw = any(kw.lower() in body.lower() for kw in failure_kws)
    
            # Expired if: silently redirected to login page
            # OR: login form is showing AND failure keywords present
            if redirected_to_login or (has_login_form and has_failure_kw):
                expired = True
                logger.warning(
                    f"[{domain}] Session expired: "
                    f"redirected_to_login={redirected_to_login}, "
                    f"login_form={has_login_form}, failure_kw={has_failure_kw}"
                )
    
        if expired:
            self.domains[domain].update({
                "authenticated": False,
                "expired":       True,
                "auth_type":     "guest",
            })

    # ─────────────────────────────────────────────────────────────────────────
    # PLAYWRIGHT COOKIE SYNC
    # ─────────────────────────────────────────────────────────────────────────

    async def sync_cookies_to_playwright(
        self,
        session:            aiohttp.ClientSession,
        playwright_context,
        domain:             str,
    ):
        """
        Sync aiohttp session cookies to the Playwright browser context.

        Tries both https:// and http:// to maximise cookie capture.
        Respects the cookie's own httpOnly and secure flags.
        """
        try:
            for scheme in ("https", "http"):
                jar     = session.cookie_jar.filter_cookies(f"{scheme}://{domain}")
                cookies = []
                for name, morsel in jar.items():
                    cookie = {
                        "name":     name,
                        "value":    morsel.value,
                        "domain":   domain,
                        "path":     morsel.get("path") or "/",
                        "httpOnly": bool(morsel.get("httponly", False)),
                        "secure":   bool(morsel.get("secure", False)),
                        "sameSite": morsel.get("samesite") or "Lax",
                    }
                    cookies.append(cookie)

                if cookies:
                    await playwright_context.add_cookies(cookies)
                    logger.debug(
                        f"[{domain}] Synced {len(cookies)} cookies "
                        f"({scheme}) to Playwright"
                    )
                    break   # stop after first scheme that had cookies

        except Exception as e:
            logger.exception(f"[{domain}] Cookie sync failed: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_login_form(
        self,
        html:       str,
        login_url:  str,
        pass_field: str,
    ) -> Tuple[dict, Optional[str]]:
        """
        Locate the login form and extract all named inputs.

        Priority:
          1. Form containing <input type="password">
          2. Form containing a field whose name matches pass_field
          3. First form on the page

        All named inputs are extracted (captures CSRF tokens, logintoken,
        __RequestVerificationToken, hidden fields, etc.).
        """
        soup  = BeautifulSoup(html or "", "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return {}, None

        target_form = None

        for form in forms:
            if form.find("input", {"type": "password"}):
                target_form = form
                break

        if not target_form:
            for form in forms:
                if form.find("input", {"name": pass_field}):
                    target_form = form
                    break

        if not target_form:
            target_form = forms[0]

        payload: dict = {}
        for tag in target_form.find_all(["input", "select", "textarea"]):
            name = tag.get("name")
            if name and name not in payload:
                payload[name] = tag.get("value", "")

        raw_action = target_form.get("action", "")
        action_url = urljoin(login_url, raw_action) if raw_action else login_url

        return payload, action_url

    def _validate_login(
        self,
        html:             str,
        final_url:        str,
        status:           int,
        success_keywords: List[str],
        failure_keywords: Optional[List[str]] = None,
    ) -> bool:
        """
        Validate login success with ordered checks:

        1. Hard HTTP failures (401 / 403 / 429 / 500 / 503) → fail
        2. Failure keywords in body                          → fail
        3. Success keywords in body                          → pass
        4. Redirected away from all known login paths        → pass
        5. Default                                           → fail (never assume success)
        """
        failure_keywords = failure_keywords or PLATFORM_FAILURE.get("generic", [])
        html_lower = (html or "").lower()
        url_lower  = (final_url or "").lower()

        # 1. Hard HTTP failures
        if status in (401, 403, 429, 500, 503):
            logger.debug(f"[Validate] Failed — HTTP {status}")
            return False

        # 2. Explicit failure message
        if any(kw in html_lower for kw in failure_keywords):
            logger.debug("[Validate] Failed — failure keyword in body")
            return False

        # 3. Explicit success keyword
        if any(kw.lower() in html_lower for kw in success_keywords):
            logger.debug("[Validate] Success — success keyword in body")
            return True

        # 4. Redirected away from login page
        login_path_indicators = (
            "/login", "/signin", "/sign-in",
            "/auth/login", "/account/login",
            "wp-login.php", "com_users",
            "user/login", "accounts/login",
            "/login/index.php",
        )
        if not any(ind in url_lower for ind in login_path_indicators):
            logger.debug(
                f"[Validate] Success — redirected away from login: {final_url}"
            )
            return True

        logger.debug("[Validate] Failed — still on login page, no success signal")
        return False