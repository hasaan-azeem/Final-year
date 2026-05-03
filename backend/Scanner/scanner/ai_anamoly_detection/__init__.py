"""
ai_engine
=========
WebXGuard per-domain anomaly detection subsystem.

Usage
-----
>>> from ai_engine.main import run_anomaly_detection
>>> result = run_anomaly_detection("example.com")
"""
from .main import run_anomaly_detection

__all__ = ["run_anomaly_detection"]