"""
Scanner/scanner/ai_remediation
==============================
AI-powered remediation suggestions for vulnerability findings.

Public API:
    get_remediation_for_vuln(vuln_dict)           → dict
    get_remediations_for_session_async(sess_id)   → list[dict]

Falls through:
    DB cache → static knowledge base → Groq LLM → generic stub
"""
from .manager import (
    get_remediation_for_vuln,
    get_remediations_for_session_async,
    _vuln_signature,
)
from .knowledge_base import lookup_kb, KNOWLEDGE_BASE
from .ai_client       import generate_ai_remediation, generic_stub

__all__ = [
    "get_remediation_for_vuln",
    "get_remediations_for_session_async",
    "lookup_kb",
    "KNOWLEDGE_BASE",
    "generate_ai_remediation",
    "generic_stub",
]