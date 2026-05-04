from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

logger = logging.getLogger("webxguard.ai_remediation.ai_client")

# Lazy Gemini client
_gemini_client = None


# ─────────────────────────────────────────────────────────────────────────────
# Client
# ─────────────────────────────────────────────────────────────────────────────

def _get_client():
    """Lazy-init Gemini client. Returns None if API key missing."""
    global _gemini_client

    if _gemini_client is not None:
        return _gemini_client

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        logger.warning("[AI Remediation] GEMINI_API_KEY not set — LLM disabled")
        return None

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        _gemini_client = genai
        return _gemini_client

    except ImportError:
        logger.error(
            "[AI Remediation] google-generativeai not installed. "
            "Run: pip install google-generativeai"
        )
        return None
    except Exception as e:
        logger.error("[AI Remediation] Gemini init failed: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Prompt
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a senior application security engineer. Given a single web "
    "vulnerability finding, return a strict JSON object with these keys: "
    '"summary" (1-2 sentences explaining the vulnerability), "fix_steps" '
    "(array of 3 to 6 short, actionable, imperative sentences), "
    '"code_example" (one short secure-code snippet, or null if not '
    'applicable), "references" (array of 1-3 objects with "title" and '
    '"url" keys, pointing to OWASP / MITRE / official docs). '
    "Do NOT include any text outside the JSON. Do NOT wrap the JSON in "
    "markdown fences."
)


def _build_user_prompt(
    title: str,
    category: str | None,
    page_url: str | None,
    cwe: str | None,
    severity: str | None,
) -> str:
    parts = [f"Vulnerability title: {title}"]

    if category:
        parts.append(f"Category: {category}")
    if cwe:
        parts.append(f"CWE: {cwe}")
    if severity:
        parts.append(f"Severity: {severity}")
    if page_url:
        parts.append(f"Affected page: {page_url}")

    parts.append("Return only JSON. No explanations.")

    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# JSON extraction
# ─────────────────────────────────────────────────────────────────────────────

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_json(text: str) -> dict | None:
    if not text:
        return None

    text = text.strip()

    try:
        return json.loads(text)
    except:
        pass

    m = _JSON_FENCE_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except:
            pass

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except:
            pass

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────

def _validate_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None

    summary = str(payload.get("summary") or "").strip()
    if not summary:
        return None

    fix_steps = payload.get("fix_steps") or []
    if isinstance(fix_steps, str):
        fix_steps = [s.strip() for s in fix_steps.split("\n") if s.strip()]

    if not isinstance(fix_steps, list) or not fix_steps:
        return None

    fix_steps = [str(s).strip() for s in fix_steps][:6]

    code_example = payload.get("code_example")
    if code_example and not isinstance(code_example, str):
        code_example = None

    refs = payload.get("references") or []
    cleaned_refs = []

    if isinstance(refs, list):
        for r in refs[:3]:
            if isinstance(r, dict) and r.get("url"):
                cleaned_refs.append({
                    "title": str(r.get("title") or r["url"]),
                    "url": r["url"]
                })

    return {
        "summary": summary,
        "fix_steps": fix_steps,
        "code_example": code_example,
        "references": cleaned_refs,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main AI call
# ─────────────────────────────────────────────────────────────────────────────

def generate_ai_remediation(
    *,
    title: str,
    category: str | None = None,
    page_url: str | None = None,
    cwe: str | None = None,
    severity: str | None = None,
    timeout: float = 8.0,
) -> dict | None:

    client = _get_client()
    if client is None:
        return None

    user_prompt = _build_user_prompt(title, category, page_url, cwe, severity)

    try:
        model = client.GenerativeModel("gemini-1.5-flash")

        response = model.generate_content(
            _SYSTEM_PROMPT + "\n\n" + user_prompt
        )

        raw = response.text or ""

    except Exception as e:
        logger.warning("[AI Remediation] Gemini call failed: %s", e)
        return None

    payload = _extract_json(raw)
    if payload is None:
        logger.warning("[AI Remediation] JSON parse failed")
        return None

    cleaned = _validate_payload(payload)
    if cleaned is None:
        logger.warning("[AI Remediation] Validation failed")
        return None

    cleaned["source"] = "ai"
    cleaned["model"] = "gemini-1.5-flash"

    return cleaned


# ─────────────────────────────────────────────────────────────────────────────
# Fallback
# ─────────────────────────────────────────────────────────────────────────────

def generic_stub(title: str) -> dict:
    return {
        "summary": f"A {title} vulnerability was detected.",
        "fix_steps": [
            "Identify user-controlled input",
            "Apply validation and sanitization",
            "Use secure coding practices",
            "Re-test after fixing"
        ],
        "code_example": None,
        "references": [
            {"title": "OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/"}
        ],
        "source": "fallback",
        "model": "stub",
    }