import os
import asyncpg
import logging
from contextlib import asynccontextmanager

log = logging.getLogger("webxguard.db")
logging.basicConfig(level=logging.INFO)

# --------------------------------------------------
# 1️⃣ DATABASE CONNECTION CONFIGURATION
# --------------------------------------------------
# Recommended: Use DATABASE_URL environment variable
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:5353@127.0.0.1:5432/Webxguard"
)

# Fallback: Individual credentials (optional)
if not DATABASE_URL:
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "admin123")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "WebXGaurd")

    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

_pool: asyncpg.Pool | None = None

# --------------------------------------------------
# 2️⃣ Pool lifecycle
# --------------------------------------------------
async def init_db(min_size: int = 5, max_size: int = 20, timeout: int = 60) -> None:
    """
    Initialize global asyncpg connection pool.
    Must be called once on application startup.
    """
    global _pool

    if _pool:
        return

    log.info(f"Initializing PostgreSQL connection pool: {DATABASE_URL}")
    try:
        _pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=min_size,
            max_size=max_size,
            command_timeout=timeout,
            statement_cache_size=0,  # safer for long-running workers
        )
        log.info("PostgreSQL pool initialized successfully")
    except Exception as e:
        log.exception("Failed to initialize PostgreSQL pool: %s", e)
        raise

async def close_db() -> None:
    """Close connection pool gracefully."""
    global _pool
    if _pool:
        log.info("Closing PostgreSQL connection pool")
        await _pool.close()
        _pool = None

# --------------------------------------------------
# 3️⃣ Connection helpers
# --------------------------------------------------
@asynccontextmanager
async def acquire():
    """Acquire a DB connection from the pool."""
    if not _pool:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    conn = await _pool.acquire()
    try:
        yield conn
    finally:
        await _pool.release(conn)

# --------------------------------------------------
# 4️⃣ Query helpers
# --------------------------------------------------
async def fetch(query: str, *args):
    """Return multiple rows."""
    async with acquire() as conn:
        return await conn.fetch(query, *args)

async def fetchrow(query: str, *args):
    """Return a single row."""
    async with acquire() as conn:
        return await conn.fetchrow(query, *args)

async def execute(query: str, *args) -> str:
    """Execute a query (INSERT, UPDATE, DELETE). Returns command tag."""
    async with acquire() as conn:
        return await conn.execute(query, *args)