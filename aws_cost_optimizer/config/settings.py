"""
Application settings - loaded from environment variables with sensible defaults.
"""

import os
from datetime import date, timedelta

CE_REGION = os.getenv("AWS_CE_REGION", "us-east-1")

# Default analysis window: a trailing 60 days, computed at import time.
#
# These were previously hardcoded literal dates, which silently went
# stale -- a scan run without explicit dates analysed a fixed window
# receding further into the past with every day that passed, and
# eventually one outside Cost Explorer's retention entirely.
#
# The end date is yesterday rather than today because the current day
# is always partial in Cost Explorer, and a partial final day makes
# per-day figures look like a sudden drop in spend.
DEFAULT_ANALYSIS_WINDOW_DAYS = int(os.getenv("DEFAULT_ANALYSIS_WINDOW_DAYS", "30"))

_today = date.today()
_default_end = _today - timedelta(days=1)
_default_start = _default_end - timedelta(days=DEFAULT_ANALYSIS_WINDOW_DAYS)

# Explicit overrides still win, so a specific window can be pinned for
# reproducing a past scan.
DEFAULT_START_DATE = os.getenv("DEFAULT_START_DATE", "2026-07-31")
DEFAULT_END_DATE = os.getenv("DEFAULT_END_DATE", "2026-08-30")

DEFAULT_COST_THRESHOLD = float(os.getenv("DEFAULT_COST_THRESHOLD", "0.0"))
