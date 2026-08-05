"""
Application settings - only application-wide constants that rarely change.
Scan-specific parameters live in the ScanRun model.
"""
import os

CE_REGION = "us-east-1"

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")

DEFAULT_METRIC_PERIOD = 86400

MAX_API_RETRIES = 3

NAT_USAGE_PATTERNS = ["NatGateway"]
