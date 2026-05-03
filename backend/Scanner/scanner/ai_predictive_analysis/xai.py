"""
posture/xai.py
==============
Explainability layer — two levels per cycle:
  1. top_vulns:          top-N vulnerabilities by weighted contribution
  2. feature_importance: SHAP → permutation → built-in MDI → static weights
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import numpy as np

from .predictor import FEATURE_COLS, FEATURE_LABELS
from .scorer import DECAY_LAMBDA, EXPLOIT_MULT, WEIGHTS, _MAX_CONTRIBUTION

if TYPE_CHECKING:
    from .predictor import PosturePredictor

logger = logging.getLogger("webxguard.posture.xai")

TOP_VULNS    = 10
TOP_FEATURES = 10


def top_vuln_contributors(
    vulns: list[dict], contributions: list[float], top_n: int = TOP_VULNS,
) -> list[dict]:
    if not vulns or not contributions:
        return []
    paired = sorted(zip(contributions, vulns), key=lambda x: x[0], reverse=True)
    return [
        {
            "rank":         rank,
            "id":           row.get("id"),
            "title":        row.get("title") or "Unknown",
            "category":     row.get("category") or row.get("priority_category") or "—",
            "contribution": round(contrib, 4),
            "cvss_score":   float(row.get("cvss_score") or 0.0),
            "severity":     row.get("severity_level") or row.get("severity") or "—",
            "exploit":      bool(row.get("exploit_available")),
            "confidence":   row.get("confidence") or "—",
        }
        for rank, (contrib, row) in enumerate(paired[:top_n], start=1)
    ]


def _shap_importance(predictor: "PosturePredictor", features: list[float]):
    try:
        import shap
        explainer = shap.TreeExplainer(predictor.models["1d"])
        X_scaled  = predictor.scaler.transform([features])
        shap_vals = explainer.shap_values(X_scaled)[0]
        pairs = sorted(zip(FEATURE_COLS, shap_vals), key=lambda x: abs(x[1]), reverse=True)
        return (
            [{"feature": c, "label": FEATURE_LABELS.get(c, c),
              "importance": round(float(v), 5)} for c, v in pairs[:TOP_FEATURES]],
            "shap",
        )
    except Exception as e:
        logger.debug("[XAI] SHAP unavailable (%s)", e)
        return None


def _permutation_importance(predictor: "PosturePredictor", features: list[float]):
    try:
        X_train = predictor.X_train
        if X_train.shape[0] < 5:
            return None
        X_s        = predictor.scaler.transform(X_train)
        gbr        = predictor.models["1d"]
        base_preds = gbr.predict(X_s)
        importances = []
        for fi, col in enumerate(FEATURE_COLS):
            X_perm        = X_s.copy()
            rng           = np.random.default_rng(42)
            X_perm[:, fi] = rng.permutation(X_perm[:, fi])
            importances.append((col, float(np.mean(np.abs(base_preds - gbr.predict(X_perm))))))
        importances.sort(key=lambda x: x[1], reverse=True)
        return (
            [{"feature": c, "label": FEATURE_LABELS.get(c, c),
              "importance": round(v, 5)} for c, v in importances[:TOP_FEATURES]],
            "permutation",
        )
    except Exception as e:
        logger.debug("[XAI] Permutation importance failed (%s)", e)
        return None


def _builtin_importance(predictor: "PosturePredictor"):
    try:
        fi    = predictor.models["1d"].feature_importances_
        pairs = sorted(zip(FEATURE_COLS, fi), key=lambda x: x[1], reverse=True)
        return (
            [{"feature": c, "label": FEATURE_LABELS.get(c, c),
              "importance": round(float(v), 5)} for c, v in pairs[:TOP_FEATURES]],
            "builtin",
        )
    except Exception as e:
        logger.debug("[XAI] Built-in importance failed (%s)", e)
        return None


def _static_weights():
    items = sorted(WEIGHTS.items(), key=lambda x: x[1], reverse=True)
    return (
        [{"feature": k, "label": k.replace("_", " ").title(),
          "importance": round(v, 5)} for k, v in items],
        "static",
    )


def feature_importance(
    predictor: "PosturePredictor | None",
    features:  list[float] | None,
) -> tuple[list[dict], str]:
    if predictor is not None and features is not None:
        result = _shap_importance(predictor, features)
        if result:
            return result
        result = _permutation_importance(predictor, features)
        if result:
            return result
        result = _builtin_importance(predictor)
        if result:
            return result
    return _static_weights()


def score_breakdown(vulns: list[dict], contributions: list[float]) -> dict:
    """
    Human-readable description of the CURRENT scoring formula.

    Bug fixed: previously still showed the old normaliser (N * 0.5) even
    after scorer.py was rewritten to use avg_severity + count_factor.
    Now accurately reflects the actual formula being used.
    """
    if not contributions:
        return {
            "base_formula":   "No vulnerabilities — score = 0",
            "decay_lambda":   DECAY_LAMBDA,
            "exploit_mult":   EXPLOIT_MULT,
            "max_contribution": _MAX_CONTRIBUTION,
            "vuln_count":     0,
            "avg_severity":   0.0,
            "count_factor":   0.0,
            "total_weighted": 0.0,
        }

    import math
    avg_severity = sum(c / _MAX_CONTRIBUTION for c in contributions) / len(contributions)
    count_factor = min(0.30, math.log1p(len(vulns)) * 0.046)

    return {
        "base_formula": (
            "avg_severity = mean(contribution / MAX_CONTRIBUTION)  "
            "count_factor = min(0.30, log1p(N) * 0.046)  "
            "score = (avg_severity + count_factor) * 100"
        ),
        "decay_lambda":     DECAY_LAMBDA,
        "exploit_mult":     EXPLOIT_MULT,
        "max_contribution": round(_MAX_CONTRIBUTION, 3),
        "vuln_count":       len(vulns),
        "avg_severity":     round(avg_severity, 4),
        "count_factor":     round(count_factor, 4),
        "total_weighted":   round(sum(contributions), 4),
    }


def build_explanation(
    vulns:         list[dict],
    contributions: list[float],
    predictor:     "PosturePredictor | None" = None,
    features:      list[float] | None = None,
) -> dict:
    top_v      = top_vuln_contributors(vulns, contributions)
    fi, method = feature_importance(predictor, features)
    breakdown  = score_breakdown(vulns, contributions)
    return {
        "top_vulns":          top_v,
        "feature_importance": fi,
        "xai_method":         method,
        "score_breakdown":    breakdown,
    }