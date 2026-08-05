"""
Base collector
"""

from abc import ABC, abstractmethod


class BaseCollector(ABC):
    key: str = None

    def __init__(self, scan, region: str = None):
        self.scan = scan
        # Use provided region, otherwise fall back to scan region
        self.region = region or scan.region

    @abstractmethod
    def collect(self) -> list:
        pass
