"""
AI Risk Analysis / priority_model.py

Predicts target_priority (0-10) for WebXGuard vulnerabilities.

Features engineered (12 total):
    Numeric  : cvss_score, severity, likelihood, impact,
               page_criticality, severity_level, confidence_num
    Boolean  : exploit_available, is_active_vuln
    Encoded  : category_encoded, cwe_family_encoded, vuln_type_encoded
"""

import logging
import os
import pickle
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ── Paths (anchored to this file so they work from any cwd) ──────────────────

_HERE        = Path(__file__).parent
MODEL_PATH   = str(_HERE / "priority_model.pkl")
DATASET_PATH = str(_HERE / "data" / "dataset.csv")


# ── DB config ─────────────────────────────────────────────────────────────────

def _db_config_from_url(url: str) -> dict:
    p = urlparse(url)
    return {
        "host":     p.hostname,
        "port":     p.port or 5432,
        "database": p.path.lstrip("/"),
        "user":     p.username,
        "password": p.password,
    }

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:5353@127.0.0.1:5432/Webxguard",
)
DB_CONFIG = _db_config_from_url(DATABASE_URL)


# ── Scanner constants ─────────────────────────────────────────────────────────

CONFIDENCE_NUM = {"certain": 0.9, "firm": 0.7, "tentative": 0.35}

ACTIVE_CATEGORIES = {
    "SQL Injection", "XSS", "CSRF", "Command Injection",
    "Path Traversal", "XXE", "SSTI", "SSRF", "IDOR",
    "Open Redirect", "Injection",
}

ACTIVE_TITLE_KEYWORDS = (
    "sql injection", "union-based", "boolean-based", "time-based blind",
    "cross-site scripting", "xss", "csrf", "anti-csrf",
    "command injection", "os command", "path traversal", "directory traversal",
    "xml external entity", "xxe", "server-side template", "ssti",
    "server-side request forgery", "ssrf", "insecure direct object", "idor",
    "open redirect",
)

CWE_FAMILIES = {
    "CWE-89":   "injection",
    "CWE-78":   "injection",
    "CWE-94":   "injection",
    "CWE-611":  "injection",
    "CWE-918":  "injection",
    "CWE-79":   "xss",
    "CWE-352":  "csrf",
    "CWE-22":   "traversal",
    "CWE-639":  "access",
    "CWE-284":  "access",
    "CWE-601":  "access",
    "CWE-200":  "disclosure",
    "CWE-209":  "disclosure",
    "CWE-615":  "disclosure",
    "CWE-326":  "crypto",
    "CWE-311":  "crypto",
    "CWE-312":  "crypto",
    "CWE-693":  "headers",
    "CWE-942":  "headers",
    "CWE-524":  "cache",
    "CWE-1004": "cookies",
}

# All vuln_type values from your dataset — encoder is pre-seeded with these
# so it never sees "unknown" keys even across retrains on subsets.
KNOWN_VULN_TYPES = {
    "sqli", "cache", "xss", "cookies", "comments", "headers", "versioning",
    "csp", "access_control", "cmdi", "robots", "cms", "csrf", "ssl_tls",
    "sitemap", "javascript", "path_traversal", "page_content_change",
    "secrets", "xxe", "ssrf", "ssti", "cors", "sensitive_inputs",
    "open_redirect", "external_links", "idor", "storage", "error_status",
    "mixed_content", "forms", "unknown",
}


# ── Feature helpers ───────────────────────────────────────────────────────────

def _confidence_num(series: pd.Series) -> pd.Series:
    return series.map(CONFIDENCE_NUM).fillna(0.5)


def _is_active_vuln(category_series: pd.Series, title_series: pd.Series) -> pd.Series:
    cat_flag    = category_series.str.strip().isin(ACTIVE_CATEGORIES)
    title_lower = title_series.str.lower().fillna("")
    title_flag  = title_lower.apply(
        lambda t: any(kw in t for kw in ACTIVE_TITLE_KEYWORDS)
    )
    return (cat_flag | title_flag).astype(int)


def _cwe_family(cwe_series: pd.Series) -> pd.Series:
    return cwe_series.apply(lambda c: CWE_FAMILIES.get(str(c).strip(), "other"))


def _safe_label_encode(series: pd.Series, le: LabelEncoder,
                        fallback: str = "unknown") -> pd.Series:
    def _t(v):
        s = str(v) if v is not None else fallback
        return int(le.transform([s])[0]) if s in le.classes_ \
               else int(le.transform([fallback])[0])
    return series.apply(_t)


# ── Model ─────────────────────────────────────────────────────────────────────

class PriorityPredictor:
    """
    GradientBoosting regressor — predicts target_priority (0-10).

    Training sources:
      1. CSV file  (train_from_csv)  — used for first-time seeding & retraining
      2. DataFrame (train_model)     — used when called with DB data directly

    vuln_type is the 12th feature:
      - From CSV  : direct column in dataset.csv
      - From DB   : extracted from raw_data JSON (raw_data->>'vuln_type')
      - From dict : passed via predict(vuln) or defaults to "unknown"
    """

    FEATURE_COLS = [
        "cvss_score",
        "severity",
        "likelihood",
        "impact",
        "page_criticality",
        "severity_level",
        "confidence_num",
        "exploit_available",
        "is_active_vuln",
        "category_encoded",
        "cwe_family_encoded",
        "vuln_type_encoded",
    ]

    def __init__(self):
        self.model         = None
        self.scaler        = StandardScaler()
        self.le_category   = LabelEncoder()
        self.le_cwe_fam    = LabelEncoder()
        self.le_vuln_type  = LabelEncoder()
        self._fitted       = False

    # ── Train from CSV ────────────────────────────────────────────────────────

    def train_from_csv(self, csv_path: str = DATASET_PATH) -> bool:
        """
        Load the dataset CSV and train the model on it.
        This is the primary entry point — used for both first-time seeding
        and periodic retraining on the accumulated CSV.
        """
        path = Path(csv_path)
        if not path.exists():
            logger.error("CSV not found at %s", csv_path)
            return False
        try:
            df = pd.read_csv(csv_path, low_memory=False)
        except Exception as e:
            logger.error("Failed to read CSV: %s", e)
            return False

        logger.info("Loaded %d rows from %s", len(df), csv_path)
        return self.train_model(df)

    # ── Train from DataFrame ──────────────────────────────────────────────────

    def train_model(self, df: pd.DataFrame) -> bool:
        """
        Train from any DataFrame that has the required columns.
        Works for both CSV rows and DB rows (both have vuln_type after our SQL).
        """
        logger.info("Training on %d records…", len(df))
        if len(df) < 20:
            logger.warning("Need >= 20 labelled rows, got %d", len(df))
            return False

        X, y = self._build_features(df, fit=True)
        if len(X) < 20:
            logger.warning("After cleaning, only %d usable rows", len(X))
            return False

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        X_tr_s = self.scaler.fit_transform(X_tr)
        X_te_s = self.scaler.transform(X_te)

        self.model = GradientBoostingRegressor(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.8,
            random_state=42,
        )
        self.model.fit(X_tr_s, y_tr)
        self._fitted = True

        y_pred = self.model.predict(X_te_s)
        r2   = r2_score(y_te, y_pred)
        mae  = mean_absolute_error(y_te, y_pred)
        rmse = float(np.sqrt(mean_squared_error(y_te, y_pred)))
        cv   = cross_val_score(
            self.model, self.scaler.transform(X), y, cv=5, scoring="r2"
        )

        logger.info("Model ready  R²=%.4f  MAE=%.4f  RMSE=%.4f", r2, mae, rmse)
        logger.info("5-fold CV    R²=%.4f ± %.4f", cv.mean(), cv.std())

        importances = sorted(
            zip(self.FEATURE_COLS, self.model.feature_importances_),
            key=lambda x: -x[1],
        )
        logger.info("Feature importance:")
        for name, imp in importances:
            logger.info("  %-24s %.4f", name, imp)

        return True

    # ── Predict ───────────────────────────────────────────────────────────────

    def predict(self, vuln: dict) -> float:
        """Predict target_priority for one vulnerability dict."""
        if not self._fitted:
            logger.error("Model not trained")
            return 5.0

        row = {
            "cvss_score":        vuln.get("cvss_score")        or 5.0,
            "severity":          vuln.get("severity")          or 5.0,
            "likelihood":        vuln.get("likelihood")        or 0.5,
            "impact":            vuln.get("impact")            or 5.0,
            "page_criticality":  vuln.get("page_criticality")  or 5.0,
            "severity_level":    vuln.get("severity_level")    or 3.0,
            "confidence":        str(vuln.get("confidence")    or "firm"),
            "exploit_available": bool(vuln.get("exploit_available", False)),
            "category":          str(vuln.get("category")      or ""),
            "title":             str(vuln.get("title")         or ""),
            "cwe":               str(vuln.get("cwe")           or ""),
            "vuln_type":         str(vuln.get("vuln_type")     or "unknown"),
        }
        df_row = pd.DataFrame([row])
        X, _  = self._build_features(df_row, fit=False)
        X_s   = self.scaler.transform(X)
        return round(float(np.clip(self.model.predict(X_s)[0], 0.0, 10.0)), 2)

    # ── Feature builder ───────────────────────────────────────────────────────

    def _build_features(self, df: pd.DataFrame, fit: bool = True):
        df = df.copy()

        # Numeric
        for col, default in [
            ("cvss_score", 5.0), ("severity", 5.0), ("likelihood", 0.5),
            ("impact", 5.0), ("page_criticality", 5.0), ("severity_level", 3.0),
        ]:
            if col not in df.columns:
                df[col] = default
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(default)

        # confidence → float
        conf_col = (
            df["confidence"] if "confidence" in df.columns
            else pd.Series(["firm"] * len(df), index=df.index)
        )
        df["confidence_num"] = _confidence_num(conf_col.fillna("firm"))

        # exploit_available (safe when column absent)
        if "exploit_available" in df.columns:
            df["exploit_available"] = df["exploit_available"].fillna(False).astype(int)
        else:
            df["exploit_available"] = 0

        # is_active_vuln
        cat_col = (
            df["category"] if "category" in df.columns
            else pd.Series([""] * len(df), index=df.index)
        )
        title_col = (
            df["title"] if "title" in df.columns
            else pd.Series([""] * len(df), index=df.index)
        )
        df["is_active_vuln"] = _is_active_vuln(
            cat_col.fillna(""), title_col.fillna("")
        )

        # category encoding
        cat_str = cat_col.fillna("unknown").astype(str)
        if fit:
            self.le_category.fit(sorted(cat_str.unique().tolist() + ["unknown"]))
        df["category_encoded"] = _safe_label_encode(cat_str, self.le_category, "unknown")

        # CWE family encoding
        cwe_col = (
            df["cwe"] if "cwe" in df.columns
            else pd.Series([""] * len(df), index=df.index)
        )
        families = _cwe_family(cwe_col.fillna(""))
        if fit:
            self.le_cwe_fam.fit(sorted(set(CWE_FAMILIES.values()) | {"other"}))
        df["cwe_family_encoded"] = _safe_label_encode(families, self.le_cwe_fam, "other")

        # vuln_type encoding  ← 12th feature
        vuln_type_col = (
            df["vuln_type"] if "vuln_type" in df.columns
            else pd.Series(["unknown"] * len(df), index=df.index)
        )
        vuln_type_str = vuln_type_col.fillna("unknown").astype(str)
        if fit:
            # Pre-seed with all known types → encoder stays stable across retrains
            all_types = sorted(set(vuln_type_str.unique().tolist()) | KNOWN_VULN_TYPES)
            self.le_vuln_type.fit(all_types)
        df["vuln_type_encoded"] = _safe_label_encode(
            vuln_type_str, self.le_vuln_type, "unknown"
        )

        X = df[self.FEATURE_COLS].copy()
        y = (
            pd.to_numeric(df["target_priority"], errors="coerce")
            if "target_priority" in df.columns
            else pd.Series([5.0] * len(df), index=df.index)
        )
        mask = y.notna()
        return X[mask], y[mask]

    # ── Persistence ───────────────────────────────────────────────────────────

    def save_model(self, path: str = MODEL_PATH) -> bool:
        if not self._fitted:
            logger.error("Nothing to save")
            return False
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                pickle.dump({
                    "model":        self.model,
                    "scaler":       self.scaler,
                    "le_category":  self.le_category,
                    "le_cwe_fam":   self.le_cwe_fam,
                    "le_vuln_type": self.le_vuln_type,
                    "fitted":       True,
                }, f)
            logger.info("Model saved → %s", path)
            return True
        except Exception as e:
            logger.error("Save failed: %s", e)
            return False

    def load_model(self, path: str = MODEL_PATH) -> bool:
        try:
            with open(path, "rb") as f:
                d = pickle.load(f)
            self.model         = d["model"]
            self.scaler        = d["scaler"]
            self.le_category   = d["le_category"]
            self.le_cwe_fam    = d.get("le_cwe_fam",   LabelEncoder())
            self.le_vuln_type  = d.get("le_vuln_type", LabelEncoder())
            self._fitted       = d.get("fitted", True)
            logger.info("Model loaded ← %s", path)
            return True
        except FileNotFoundError:
            logger.warning("No model file at %s", path)
            return False
        except Exception as e:
            logger.error("Load failed: %s", e)
            return False


# ── Database manager ──────────────────────────────────────────────────────────

class DatabaseManager:
    """
    Read / write the vulnerabilities table via psycopg2 (synchronous).
    Extracts vuln_type from raw_data JSON — no schema changes required.
    """

    def __init__(self, db_config: dict):
        self.db_config = db_config
        self.conn      = None

    def connect(self) -> bool:
        try:
            self.conn = psycopg2.connect(**self.db_config)
            logger.info("DB connected")
            return True
        except Exception as e:
            logger.error("DB connect failed: %s", e)
            return False

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def fetch_training_data(self) -> pd.DataFrame:
        """Fetch all labelled rows including vuln_type from raw_data JSON."""
        if not self.conn:
            return pd.DataFrame()
        query = """
            SELECT
                id,
                session_id::text   AS session_id,
                domain_id,
                page_url,
                title,
                category,
                confidence,
                parameter_name,
                cwe,
                wasc,
                page_id,
                endpoint_id,
                form_id,
                created_at,
                severity,
                likelihood,
                impact,
                cvss_score,
                exploit_available,
                page_criticality,
                severity_level,
                target_priority,
                priority_category,
                COALESCE(raw_data::json->>'vuln_type', 'unknown') AS vuln_type
            FROM vulnerabilities
            WHERE target_priority IS NOT NULL
              AND cvss_score       IS NOT NULL
            ORDER BY created_at DESC
        """
        try:
            df = pd.read_sql(query, self.conn)
            logger.info("Fetched %d training records from DB", len(df))
            return df
        except Exception as e:
            logger.error("fetch_training_data: %s", e)
            return pd.DataFrame()

    def fetch_unprioritized(self, limit: int = 500) -> list[dict]:
        """Rows with target_priority IS NULL including vuln_type."""
        if not self.conn:
            return []
        try:
            cur = self.conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT
                    id,
                    title,
                    category,
                    confidence,
                    cwe,
                    cvss_score,
                    severity,
                    likelihood,
                    impact,
                    page_criticality,
                    exploit_available,
                    severity_level,
                    session_id::text AS session_id,
                    COALESCE(raw_data::json->>'vuln_type', 'unknown') AS vuln_type
                FROM vulnerabilities
                WHERE target_priority IS NULL
                ORDER BY created_at DESC
                LIMIT %s
            """, (limit,))
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()
            logger.info("Found %d unprioritized vulnerabilities", len(rows))
            return rows
        except Exception as e:
            logger.error("fetch_unprioritized: %s", e)
            return []

    def batch_update_priorities(self, updates: list[tuple]) -> bool:
        """updates: list of (id, target_priority, priority_category)"""
        if not self.conn or not updates:
            return False
        try:
            cur = self.conn.cursor()
            for vuln_id, priority, category in updates:
                cur.execute("""
                    UPDATE vulnerabilities
                    SET    target_priority   = %s,
                           priority_category = %s
                    WHERE  id = %s
                      AND  target_priority IS NULL
                """, (priority, category, vuln_id))
            self.conn.commit()
            cur.close()
            logger.info("Updated %d rows", len(updates))
            return True
        except Exception as e:
            logger.error("batch_update_priorities: %s", e)
            self.conn.rollback()
            return False

    def get_site_risk_score(self) -> dict | None:
        if not self.conn:
            return None
        try:
            cur = self.conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT
                    COUNT(*)                                                AS total,
                    COALESCE(AVG(target_priority), 0)                       AS avg_priority,
                    COALESCE(MAX(target_priority), 0)                       AS max_priority,
                    COUNT(*) FILTER (WHERE priority_category = 'Critical')  AS critical,
                    COUNT(*) FILTER (WHERE priority_category = 'High')      AS high,
                    COUNT(*) FILTER (WHERE priority_category = 'Medium')    AS medium,
                    COUNT(*) FILTER (WHERE priority_category = 'Low')       AS low
                FROM vulnerabilities
                WHERE target_priority IS NOT NULL
            """)
            r   = dict(cur.fetchone())
            cur.close()
            avg = float(r["avg_priority"])
            level = (
                "Critical" if r["critical"] > 0 else
                "High"     if r["high"] >= 3 or avg >= 6 else
                "Medium"   if avg >= 4 else "Low"
            )
            return {
                "site_risk_score": round(avg, 2),
                "site_risk_level": level,
                "total":    int(r["total"]),
                "critical": int(r["critical"]),
                "high":     int(r["high"]),
                "medium":   int(r["medium"]),
                "low":      int(r["low"]),
            }
        except Exception as e:
            logger.error("get_site_risk_score: %s", e)
            return None


# ── Priority helpers ──────────────────────────────────────────────────────────

def assign_priority_category(priority: float) -> str:
    if priority >= 8.5: return "Critical"
    if priority >= 6.5: return "High"
    if priority >= 4.5: return "Medium"
    return "Low"


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "csv"

    if cmd == "csv":
        p = PriorityPredictor()
        if p.train_from_csv(DATASET_PATH):
            p.save_model(MODEL_PATH)
            print(f"Trained from CSV → {MODEL_PATH}")
        else:
            print("Training failed")

    elif cmd == "db":
        db = DatabaseManager(DB_CONFIG)
        db.connect()
        df = db.fetch_training_data()
        db.close()
        p = PriorityPredictor()
        if p.train_model(df):
            p.save_model(MODEL_PATH)
            print(f"Trained from DB → {MODEL_PATH}")
        else:
            print(f"Training failed — only {len(df)} rows (need >= 20)")