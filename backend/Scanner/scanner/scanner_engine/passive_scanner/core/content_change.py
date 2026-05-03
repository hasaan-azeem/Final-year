import logging
from ....repositories.monitor_page_changes import fetch_recent_page_changes

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.content_change")

MAX_SNIPPET_LEN = 150

def _trunc(text: str) -> str:
    return text[:MAX_SNIPPET_LEN] if text else ""


async def analyze_page_changes(event: dict, reporter, page_id=None, endpoint_id=None, _seen: set = None):
    """
    Report new or changed pages detected by the monitor_page_changes repository.

    Dedup strategy: (url, title) scoped to the reporter's session — the DB
    UNIQUE(session_id, page_url, title) constraint is the ultimate backstop,
    but _seen prevents redundant round-trips within the same scan run.

    NOTE: This module ignores the incoming event entirely — it fetches its own
    data from the DB via fetch_recent_page_changes. The event parameter exists
    only to match the standard module signature expected by run_http_modules.
    """
    if _seen is None:
        _seen = set()

    session_id = getattr(reporter, "session_id", None)

    try:
        changes = await fetch_recent_page_changes(session_id=session_id)

        for change in changes:
            url      = change.get("url")
            old_hash = change.get("old_hash")
            new_hash = change.get("new_hash")

            if not url or not new_hash:
                continue

            is_new = not old_hash
            title  = "New Page Detected" if is_new else "Page Content Changed"

            seen_key = (url, title)
            if seen_key in _seen:
                continue
            _seen.add(seen_key)

            profile_key = "page_new_detected" if is_new else "page_content_changed"
            scores      = build_ai_scores(profile_key, url)
            meta        = scores.pop("_meta")

            await reporter.report(
                page_url=url,
                title=title,
                category="content_change",
                confidence="medium",
                evidence={
                    "old_hash": (old_hash[:12] + "…") if old_hash else None,
                    "new_hash": new_hash[:12] + "…",
                },
                raw_data=meta,
                cwe="CWE-118",
                wasc="WASC-15",
                reference="https://owasp.org/www-project-top-ten/",
                page_id=page_id,
                endpoint_id=endpoint_id,
                **scores,
            )

    except Exception as e:
        logger.error(f"[ContentChange] Failed: {_trunc(str(e))}", exc_info=True)