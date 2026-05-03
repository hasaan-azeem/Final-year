"""
scanner.py (PRODUCTION v5 — FIXED)

CHANGES vs v4 — OWASP-Style Timeout & Concurrency Fixes:
  Concurrency (REDUCED)
  ──────────────────────
  • MAX_CONCURRENCY: 20 → 5.
    OWASP ZAP defaults to 5 concurrent threads. Going beyond 5-8 on public
    test sites triggers rate-limiting and bot-detection blocks instantly.

  Request Delay (INCREASED)
  ──────────────────────────
  • min_delay_ms: 25ms → 500ms.
    ZAP uses 100-500ms between requests by default. 25ms is indistinguishable
    from a DoS flood at the server level.

  RequestSender Tuned
  ────────────────────
  • max_retries: 2 → 3 (one extra chance after exponential backoff).
  • rotate_agents=True: passes new User-Agent per request (v5 sender feature).

  Task Timeout (INCREASED)
  ─────────────────────────
  • TASK_TIMEOUT: 180s → 240s.
    With 3 retries and 1s+2s+4s backoff, a single module on a slow host
    can legitimately take 180s+ before giving up. 240s gives real headroom.

  Batch Size (REDUCED)
  ─────────────────────
  • BATCH_SIZE: 50 → 20.
    Smaller batches flush findings to DB faster so results appear sooner
    when the scanner slows down against rate-limiting targets.

  CONFIDENCE_LEVELS FIX (NEW)
  ────────────────────────────
  • Added "firm" to CONFIDENCE_LEVELS: ["tentative", "probable", "firm", "certain"]
    Previously, sql_injection.py's boolean and time-based findings (confidence="firm")
    were silently filtered out in _process_finding() because "firm" was unrecognized.
    This caused zero database saves for blind SQLi detections.

  All other logic (producer, consumer, dedup, progress, ML scoring) is
  unchanged from v4.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from collections import defaultdict
from typing import Any, Coroutine

from ...db import fetch, execute
from .request_sender import RequestSender
from .utils.reporters import save_vulnerability, save_vulnerabilities_batch
from .cve.cve_lookup import CVELookup
from .scoring.severity_engine import SeverityEngine
from .modules import ALL_MODULES

logger = logging.getLogger("webxguard.active_scanner.scanner")

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION  ← primary tuning knobs
# ═══════════════════════════════════════════════════════════════════════════════

REQUEST_TIMEOUT  = 15       # ✅ v5: 12s → 15s (matches new request_sender default)
TASK_TIMEOUT     = 600      # ✅ v6: 240s → 600s (SQLi time-based tests need real headroom)
MAX_CONCURRENCY  = 5        # ✅ v5: 20 → 5  (OWASP ZAP default thread count)
QUEUE_CAPACITY   = MAX_CONCURRENCY * 8   # slightly bigger buffer for slow producers
BATCH_SIZE       = 20       # ✅ v5: 50 → 20 (faster partial results on slow scans)
MIN_DELAY_MS     = 100      # ✅ v6: 500ms → 100ms (SQLi was too slow with long delays)

# ✅ FIXED: Added "firm" to confidence levels (was missing, breaking blind SQLi saves)
CONFIDENCE_LEVELS = ["tentative", "probable", "firm", "certain"]
MIN_CONFIDENCE    = "probable"

OOB_HOST:   str  = os.getenv("WEBXGUARD_OOB_HOST", "")
DEBUG_MODE: bool = os.getenv("WEBXGUARD_DEBUG", "false").lower() == "true"

# Environment overrides (unchanged from v4)
try:
    MAX_CONCURRENCY = int(os.getenv("WEBXGUARD_CONCURRENCY", MAX_CONCURRENCY))
except (ValueError, TypeError):
    pass

try:
    REQUEST_TIMEOUT = int(os.getenv("WEBXGUARD_REQUEST_TIMEOUT", REQUEST_TIMEOUT))
except (ValueError, TypeError):
    pass

try:
    MIN_DELAY_MS = float(os.getenv("WEBXGUARD_DELAY_MS", MIN_DELAY_MS))
except (ValueError, TypeError):
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# Utility helpers  (unchanged from v4)
# ═══════════════════════════════════════════════════════════════════════════════

def _confidence_rank(confidence: str) -> int:
    try:
        return CONFIDENCE_LEVELS.index(confidence.lower())
    except (ValueError, AttributeError):
        return 0


def _is_target_url(url: str, target_hosts: set[str]) -> bool:
    from urllib.parse import urlparse
    try:
        return urlparse(url).netloc.lower() in target_hosts
    except Exception:
        return False


def _category_key(category: str) -> str:
    return category.lower().replace(" ", "_").replace("-", "_")


def _normalize_payload(payload: Any) -> str:
    if not payload:
        return ""
    if isinstance(payload, dict):
        for key in ("value", "payload", "data", "param",
                    "injected_payload", "injection_payload"):
            val = payload.get(key)
            if isinstance(val, str) and val:
                return val
        return json.dumps(payload, default=str)
    return str(payload)


async def _append_payload(vid: int, payload: str) -> None:
    payload = _normalize_payload(payload)
    if not payload:
        return
    await execute(
        """
        UPDATE vulnerabilities
        SET payload = COALESCE(payload, '[]'::jsonb) || to_jsonb($2::text)
        WHERE id = $1
          AND NOT (payload @> to_jsonb($2::text))
        """,
        vid, payload,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Module management  (unchanged from v4)
# ═══════════════════════════════════════════════════════════════════════════════

def _instantiate(ModuleClass, sender: RequestSender) -> Any:
    try:
        return ModuleClass(sender=sender, oob_host=OOB_HOST)
    except TypeError:
        return ModuleClass(sender=sender)


def _instantiate_all_modules(sender: RequestSender) -> dict[str, Any]:
    cache: dict[str, Any] = {}
    for Cls in ALL_MODULES:
        try:
            cache[Cls.__name__] = _instantiate(Cls, sender)
        except Exception as exc:
            logger.error("[ActiveScanner] Failed to instantiate %s: %s", Cls.__name__, exc)
    logger.info("[ActiveScanner] Pre-instantiated %d modules", len(cache))
    return cache


# ═══════════════════════════════════════════════════════════════════════════════
# Task runner  (unchanged from v4)
# ═══════════════════════════════════════════════════════════════════════════════

async def _run_task(
    semaphore:   asyncio.Semaphore,
    coro_fn,
    *args:       Any,
    module_name: str,
    target_type: str,
    target_obj:  dict,
) -> tuple[list[dict], str, dict, str, bool]:
    async with semaphore:
        try:
            findings = await asyncio.wait_for(
                coro_fn(*args), timeout=TASK_TIMEOUT
            ) or []
            return findings, target_type, target_obj, module_name, False

        except asyncio.TimeoutError:
            logger.warning(
                "[ActiveScanner] Task timeout (%ds) — module=%s url=%s",
                TASK_TIMEOUT, module_name, target_obj.get("url", "?"),
            )
            return [], target_type, target_obj, f"TIMEOUT:{module_name}", True

        except Exception as exc:
            logger.warning(
                "[ActiveScanner] Module error — module=%s url=%s: %s",
                module_name, target_obj.get("url", "?"), exc,
            )
            return [], target_type, target_obj, module_name, True


# ═══════════════════════════════════════════════════════════════════════════════
# Producer  (unchanged from v4)
# ═══════════════════════════════════════════════════════════════════════════════

_SENTINEL = object()


async def _producer(
    queue:          asyncio.Queue,
    task_counter:   list,
    semaphore:      asyncio.Semaphore,
    module_cache:   dict[str, Any],
    session_id:     str,
    pages:          list[dict],
    endpoints:      list[dict],
    forms:          list[tuple[dict, list[dict]]],
) -> None:
    from urllib.parse import urlparse
    target_hosts = {urlparse(p.get("url", "")).netloc.lower() for p in pages}

    async def _enqueue(coro_fn, *args, module_name, target_type, target_obj) -> None:
        coro: Coroutine = _run_task(
            semaphore, coro_fn, *args,
            module_name=module_name,
            target_type=target_type,
            target_obj=target_obj,
        )
        await queue.put(coro)
        task_counter[0] += 1

    try:
        for module_name, module in module_cache.items():
            if hasattr(module, 'scan_page') and callable(module.scan_page):
                for page in pages:
                    await _enqueue(module.scan_page, page, session_id, page["domain_id"],
                                   module_name=module_name,
                                   target_type="page", target_obj=page)

            if hasattr(module, 'scan_endpoint') and callable(module.scan_endpoint):
                for ep in endpoints:
                    if not _is_target_url(ep.get("url", ""), target_hosts):
                        continue
                    await _enqueue(module.scan_endpoint, ep, session_id, ep["domain_id"],
                                   module_name=module_name,
                                   target_type="endpoint", target_obj=ep)

            if hasattr(module, 'scan_form') and callable(module.scan_form):
                for form, inputs in forms:
                    await _enqueue(module.scan_form, form, inputs, session_id, form["domain_id"],
                                   module_name=module_name,
                                   target_type="form", target_obj=form)

    finally:
        await queue.put(_SENTINEL)


# ═══════════════════════════════════════════════════════════════════════════════
# DB fetchers  (unchanged from v4)
# ═══════════════════════════════════════════════════════════════════════════════

async def _fetch_pages(session_id: str) -> list[dict]:
    rows = await fetch(
        """
        SELECT DISTINCT p.id, p.url, p.phase, p.domain_id, d.domain_name
        FROM pages p
        JOIN domains d ON d.id = p.domain_id
        JOIN page_endpoints pe ON pe.page_id = p.id
        WHERE pe.session_id = $1
        ORDER BY p.id
        """,
        session_id,
    )
    return [dict(r) for r in rows]


async def _fetch_endpoints(session_id: str) -> list[dict]:
    rows = await fetch(
        """
        SELECT DISTINCT e.id, e.url, e.type, e.js_only,
               p.domain_id, p.phase, d.domain_name
        FROM endpoints e
        JOIN page_endpoints pe ON pe.endpoint_id = e.id
        JOIN pages p ON p.id = pe.page_id
        JOIN domains d ON d.id = p.domain_id
        WHERE pe.session_id = $1
        ORDER BY e.id
        """,
        session_id,
    )
    return [dict(r) for r in rows]


async def _fetch_forms_with_inputs(session_id: str) -> list[tuple[dict, list[dict]]]:
    form_rows = await fetch(
        """
        SELECT f.id, f.page_id, f.action_url, f.method, f.phase, f.js_only,
               p.url AS page_url, p.domain_id, d.domain_name
        FROM forms f
        JOIN pages p ON p.id = f.page_id
        JOIN domains d ON d.id = p.domain_id
        WHERE f.session_id = $1
        ORDER BY f.id
        """,
        session_id,
    )
    if not form_rows:
        return []

    forms    = [dict(r) for r in form_rows]
    form_ids = [f["id"] for f in forms]

    input_rows = await fetch(
        """
        SELECT form_id, name, type, input_id, placeholder
        FROM form_inputs
        WHERE form_id = ANY($1::int[])
        ORDER BY form_id
        """,
        form_ids,
    )

    inputs_by_form: dict[int, list[dict]] = defaultdict(list)
    for row in input_rows:
        inputs_by_form[row["form_id"]].append(dict(row))

    return [(form, inputs_by_form[form["id"]]) for form in forms]


# ═══════════════════════════════════════════════════════════════════════════════
# Finding processor  (unchanged from v4)
# ═══════════════════════════════════════════════════════════════════════════════

async def _process_finding(
    finding:     dict,
    target_type: str,
    target_obj:  dict,
    module_name: str,
    session_id:  str,
    seen_vulns:  dict,
    engine:      Any,
) -> dict | None:
    confidence = finding.get("confidence", "tentative")
    if _confidence_rank(confidence) < _confidence_rank(MIN_CONFIDENCE):
        return None

    evidence = finding.get("evidence") or {}
    payload  = _normalize_payload(
        finding.get("payload")
        or evidence.get("payload")
        or evidence.get("injected_payload")
        or ""
    )

    dedup_key = (
        finding.get("vuln_type", ""),
        finding.get("url", ""),
        finding.get("parameter") or finding.get("parameter_name", ""),
    )

    if dedup_key in seen_vulns:
        existing_vid = seen_vulns[dedup_key]
        if existing_vid and payload:
            await _append_payload(existing_vid, payload)
        return None

    seen_vulns[dedup_key] = None

    scores = await engine.score(
        category    = _category_key(finding.get("category", "")),
        confidence  = confidence,
        target_type = target_type,
        **{target_type: target_obj},
    ) or {}

    enriched = {
        **finding,
        "session_id":        session_id,
        "severity":          scores.get("severity"),
        "likelihood":        scores.get("likelihood"),
        "impact":            scores.get("impact"),
        "cvss_score":        scores.get("cvss_score"),
        "exploit_available": scores.get("exploit_available"),
        "page_criticality":  scores.get("page_criticality"),
        "severity_level":    scores.get("severity_level"),
        "target_priority":   scores.get("target_priority"),
        "priority_category": scores.get("priority_category"),
        "payload":           json.dumps([payload]) if payload else json.dumps([]),
    }

    cve_evidence = dict(enriched.get("evidence") or {})
    cve_evidence["cve_data"] = {
        "matched_cves":     scores.get("matched_cves"),
        "best_cve_id":      scores.get("best_cve_id"),
        "source":           scores.get("cve_source"),
        "adjusted_cvss":    scores.get("cvss_score"),
        "multiplier":       scores.get("criticality_multiplier"),
        "page_criticality": scores.get("page_criticality"),
    }
    enriched["evidence"] = cve_evidence

    return enriched


async def _flush_batch(
    batch:      list[dict],
    seen_vulns: dict,
) -> int:
    if not batch:
        return 0

    inserted_keys = await save_vulnerabilities_batch(batch)
    saved = len(inserted_keys)

    for finding in batch:
        dedup_key = (
            finding.get("vuln_type", ""),
            finding.get("url", ""),
            finding.get("parameter") or finding.get("parameter_name", ""),
        )
        # ✅ FIXED: Use page_url (what's in database), not url (has injected payload)
        db_key = (
            finding.get("session_id", ""),
            finding.get("page_url", ""),
            finding.get("title", ""),
        )
        if db_key in inserted_keys:
            seen_vulns[dedup_key] = True

    return saved


# ═══════════════════════════════════════════════════════════════════════════════
# Main orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

async def run_active_scan(session_id: str) -> int:
    """
    Main active scanning orchestrator (v5 + FIX).

    Key changes from v4:
    ────────────────────
    • MAX_CONCURRENCY=5, MIN_DELAY_MS=500 — OWASP ZAP-equivalent throttling.
    • rotate_agents=True — per-request User-Agent rotation.
    • max_retries=3, TASK_TIMEOUT=240s — more forgiving on slow hosts.
    • BATCH_SIZE=20 — faster partial flush when scan slows down.
    • CONFIDENCE_LEVELS now includes "firm" — fixes silent filtering of blind SQLi.
    """
    logger.info("[ActiveScanner] v5 starting session %s", session_id)
    logger.info(
        "[ActiveScanner] Config → concurrency=%d delay=%.0fms timeout=%ds task_timeout=%ds",
        MAX_CONCURRENCY, MIN_DELAY_MS, REQUEST_TIMEOUT, TASK_TIMEOUT,
    )

    pages     = await _fetch_pages(session_id)
    endpoints = await _fetch_endpoints(session_id)
    forms     = await _fetch_forms_with_inputs(session_id)

    logger.info(
        "[ActiveScanner] Targets → pages=%d endpoints=%d forms=%d",
        len(pages), len(endpoints), len(forms),
    )

    sender = RequestSender(
        timeout      = REQUEST_TIMEOUT,
        max_retries  = 3,              # ✅ v5: 2 → 3
        min_delay_ms = MIN_DELAY_MS,   # ✅ v5: 500ms base inter-request delay
        concurrency  = MAX_CONCURRENCY,
        cache_get    = True,
        rotate_agents= True,           # ✅ v5: User-Agent rotation enabled
    )
    cve_lookup = CVELookup(use_cache=True)
    engine     = SeverityEngine(cve_lookup=cve_lookup)

    await sender.start()

    semaphore     = asyncio.Semaphore(MAX_CONCURRENCY)
    total_saved   = 0
    seen_vulns:  dict           = {}
    error_counts: dict[str,int] = defaultdict(int)
    batch:        list[dict]    = []
    done_count    = 0

    module_cache = _instantiate_all_modules(sender)

    task_counter: list[int] = [0]
    queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_CAPACITY)
    in_flight: set[asyncio.Task] = set()

    producer_task = asyncio.ensure_future(
        _producer(queue, task_counter, semaphore, module_cache, session_id,
                  pages, endpoints, forms)
    )

    producer_done = False
    last_log_time = time.monotonic()

    try:
        while not producer_done or in_flight:
            wait_futs: set[asyncio.Future] = set(in_flight)
            get_fut: asyncio.Future | None = None

            if not producer_done:
                get_fut = asyncio.ensure_future(queue.get())
                wait_futs.add(get_fut)

            if not wait_futs:
                break

            done_set, _ = await asyncio.wait(
                wait_futs, return_when=asyncio.FIRST_COMPLETED
            )

            for fut in done_set:
                if fut is get_fut:
                    item = fut.result()
                    if item is _SENTINEL:
                        producer_done = True
                        if get_fut and not get_fut.done():
                            get_fut.cancel()
                        continue
                    task = asyncio.ensure_future(item)
                    in_flight.add(task)
                    continue

                in_flight.discard(fut)
                done_count += 1

                try:
                    result = fut.result()
                except Exception as exc:
                    logger.warning("[ActiveScanner] Task raised: %s", exc)
                    continue

                findings, target_type, target_obj, module_name, had_error = result
                if had_error:
                    error_counts[module_name] += 1

                for finding in findings:
                    try:
                        enriched = await _process_finding(
                            finding, target_type, target_obj,
                            module_name, session_id, seen_vulns, engine,
                        )
                        if enriched:
                            batch.append(enriched)
                    except Exception as exc:
                        logger.warning(
                            "[ActiveScanner] Skipping finding — module=%s url=%s: %s",
                            module_name, finding.get("url", "?"), exc,
                        )

                if len(batch) >= BATCH_SIZE:
                    saved       = await _flush_batch(batch, seen_vulns)
                    total_saved += saved
                    batch       = []

            if get_fut and get_fut not in done_set and not get_fut.done():
                get_fut.cancel()
                try:
                    await get_fut
                except (asyncio.CancelledError, Exception):
                    pass

            # Progress logging: every 10 tasks or 30s
            total_tasks = task_counter[0]
            now = time.monotonic()
            should_log = (
                (done_count % 10 == 0 and done_count > 0)
                or (now - last_log_time > 30)
            )
            if should_log and total_tasks:
                percent      = 100 * done_count / total_tasks
                total_errors = sum(error_counts.values())
                logger.info(
                    "[ActiveScanner] Progress %d/%d (%.1f%%) | saved=%d | batch=%d | errors=%d",
                    done_count, total_tasks, percent, total_saved, len(batch), total_errors,
                )
                last_log_time = now

        if batch:
            saved       = await _flush_batch(batch, seen_vulns)
            total_saved += saved

    except Exception:
        for t in in_flight:
            t.cancel()
        producer_task.cancel()
        raise

    finally:
        await sender.close()

    if error_counts:
        for name, count in error_counts.items():
            logger.warning("[ActiveScanner] Module '%s' had %d errors", name, count)

    logger.info("[ActiveScanner] Complete — %d vulnerabilities saved.", total_saved)
    return total_saved