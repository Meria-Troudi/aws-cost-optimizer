"""
Application settings - loaded from environment variables with sensible defaults.
"""
import os
# AWS Cost Explorer region
CE_REGION = os.getenv("AWS_CE_REGION", "us-east-1")
# Default scan date range (YYYY-MM-DD)
DEFAULT_START_DATE = os.getenv("DEFAULT_START_DATE", "2026-05-15")
DEFAULT_END_DATE = os.getenv("DEFAULT_END_DATE", "2026-08-15")
# Default cost threshold for collection planning
DEFAULT_COST_THRESHOLD = float(os.getenv("DEFAULT_COST_THRESHOLD", "0.0"))
