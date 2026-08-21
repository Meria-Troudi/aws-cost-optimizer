"""
Application settings - loaded from environment variables with sensible defaults.
"""
import os

CE_REGION = os.getenv("AWS_CE_REGION", "us-east-1")

DEFAULT_START_DATE = os.getenv("DEFAULT_START_DATE", "2026-06-15")
DEFAULT_END_DATE = os.getenv("DEFAULT_END_DATE", "2026-08-17")

DEFAULT_COST_THRESHOLD = float(os.getenv("DEFAULT_COST_THRESHOLD", "0.0"))