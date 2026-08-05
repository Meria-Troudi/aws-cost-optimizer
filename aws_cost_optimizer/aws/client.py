"""
AWS client utilities.
 
"""

import boto3
from typing import Any
from functools import lru_cache


@lru_cache(maxsize=32)
def get_client(service: str, region: str = "us-east-1") -> Any:
     return boto3.client(service, region_name=region)
