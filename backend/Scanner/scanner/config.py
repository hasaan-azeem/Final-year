# config.py

# ----------------------------
# Start URLs
# ----------------------------
START_URLS = []

# =========================
# SCAN MODE
# =========================
SCAN_TYPE = "passive"  
# Options:
# "passive" → only passive scan
# "active"  → only active scan
# "full"    → passive + active

# ----------------------------
# JS settings
# ----------------------------
MAX_JS_BROWSERS = 2                  # Max JS browsers for heavy pages

# ----------------------------
# Robots.txt enforcement
# ----------------------------
OBEY_ROBOTS_TXT = False               # Whether to respect robots.txt

# ----------------------------
# Network & retry
# ----------------------------
REQUEST_TIMEOUT = 30                  # Seconds per HTTP request
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# =========================
# CRAWLER
# =========================
MAX_CONCURRENT_REQUESTS = 5
MAX_PAGES = 1000
MAX_DEPTH = 1
MAX_RETRIES_PER_URL = 3

# =========================
# AUTH
# =========================
# =========================
# AUTH
# =========================
LOGIN_ENABLED = False

AUTH_TYPE = None

# ---- FORM LOGIN ----
LOGIN_URL = None
LOGIN_USERNAME = None
LOGIN_PASSWORD = None
LOGIN_USER_FIELD = None
LOGIN_PASS_FIELD = None

# Request Sender ----------------------
DEFAULT_TIMEOUT         = 20      # total seconds per request
DEFAULT_CONNECT_TIMEOUT = 10       # seconds to establish TCP connection
DEFAULT_READ_TIMEOUT    = 15      # seconds to read response body after connection
DEFAULT_RETRIES         = 2
RETRY_BACKOFF           = 1.0     # seconds, multiplied by attempt number
DEFAULT_MAX_BODY_BYTES  = 5 * 1024 * 1024   # 5 MB — prevents OOM on huge responses
DEFAULT_MAX_REDIRECTS   = 10
DEFAULT_CONCURRENCY     = 50

# Active Scanner -------------------------
MAX_CONCURRENCY = 5
REQUEST_TIMEOUT = 20
TASK_TIMEOUT    = 120   # Max wall-clock time per module × target

CONFIDENCE_LEVELS = ("tentative", "firm", "certain")
MIN_CONFIDENCE    = "tentative"   # change to "firm" to filter noisy hits