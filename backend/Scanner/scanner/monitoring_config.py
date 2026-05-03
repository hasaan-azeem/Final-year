# monitoring_config.py

# -----------------------------
# Crawler limits
# -----------------------------
MAX_CONCURRENT_REQUESTS = 5
MAX_PAGES               = 200
MAX_DEPTH               = 0

# -----------------------------
# Monitoring intervals
# ---------------------------
MONITOR_INTERVAL_MINUTES = 1

# -----------------------------
# Target URLs
# -----------------------------
TARGET_URLS = [
    "https://uog.edu.pk/",
]

# -----------------------------
# JS wait per domain (ms)
# How long to wait after page load for JS to finish rendering.
# Default is 4000ms. Override per domain if a site is slow.
# -----------------------------
DOMAIN_JS_WAIT = {
    # "slow-spa.example.com": 8000,
    # "fast-site.example.com": 1500,
}

# -----------------------------
# JS Browser
# -----------------------------
MAX_JS_BROWSERS = 2

# -----------------------------
# User agent
# -----------------------------
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)