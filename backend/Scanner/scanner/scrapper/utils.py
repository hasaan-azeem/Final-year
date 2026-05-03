from urllib.parse import urlparse, urljoin, urldefrag
from urllib.robotparser import RobotFileParser
from typing import Optional, List, Set, Dict
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

logger = logging.getLogger("webxguard.utils")

# ----------------------------
# GLOBAL CACHES (UNCHANGED)
# ----------------------------
robots_cache: dict[str, RobotFileParser] = {}
auth_tokens: dict[str, str] = {}  # For token replay per domain

# ----------------------------
# NEW GLOBAL STATE
# ----------------------------
crawl_cache: Dict[str, dict] = {}     # replay mode storage
fingerprint_cache: Dict[str, dict] = {}  # per-domain fingerprint
rate_limit_state: Dict[str, float] = {}  # last access timestamps


# ----------------------------
# URL UTILITIES (UNCHANGED)
# ----------------------------
def normalize_url(base_url: str, url: str) -> Optional[str]:
    if not url or url.startswith(("javascript:", "mailto:", "#")):
        return None
    absolute = urljoin(base_url, url)
    absolute, _ = urldefrag(absolute)
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return None
    return absolute.rstrip("/")


def deduplicate(urls: List[str]) -> List[str]:
    return list(dict.fromkeys(urls))

#========================================
# ENCRYPT & DECRYPT
#========================================
AES_KEY = os.environ.get("AES_KEY", "WebXGaurdSecKey0")  # 16 bytes for AES-128

if len(AES_KEY) not in (16, 24, 32):
    raise ValueError("AES_KEY must be 16, 24, or 32 bytes long")

def encrypt(text: str) -> str:
    """Encrypts a string and returns base64"""
    text_bytes = text.encode()
    iv = os.urandom(16)  # random IV
    cipher = Cipher(algorithms.AES(AES_KEY.encode()), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(text_bytes) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def decrypt(enc_text: str) -> str:
    """Decrypts a base64 string"""
    data = base64.b64decode(enc_text.encode())
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(AES_KEY.encode()), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    text_bytes = decryptor.update(ct) + decryptor.finalize()
    return text_bytes.decode()