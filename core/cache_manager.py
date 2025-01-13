import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, Optional

from core.custom_logger.logger import setup_logger

setup_logger()
logger = logging.getLogger(__name__)


class DomainResultsCache:
    def __init__(self, cache_dir: str, cache_duration: timedelta = timedelta(days=1)):

        self.cache_dir = cache_dir
        self.cache_duration = cache_duration
        os.makedirs(cache_dir, exist_ok=True)

    def _get_cache_path(self, domain: str) -> str:
        sanitized_domain = domain.replace('/', '_').replace('\\', '_')
        return os.path.join(self.cache_dir, f"{sanitized_domain}_cache.json")

    def save_results(self, domain: str, results: Dict) -> None:
        cache_data = {
            "timestamp": datetime.now().isoformat(),
            "results": results
        }

        try:
            with open(self._get_cache_path(domain), 'w') as f:
                json.dump(cache_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache for {domain}: {e}")

    def get_results(self, domain: str, ignore_cache: bool = False) -> Optional[Dict]:
        if ignore_cache:
            return None

        cache_path = self._get_cache_path(domain)

        if not os.path.exists(cache_path):
            return None

        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)

            cache_time = datetime.fromisoformat(cache_data["timestamp"])
            if datetime.now() - cache_time > self.cache_duration:
                logger.info(f"Cache expired for {domain}")
                return None

            logger.info(f"Using cached results for {domain}")
            return cache_data["results"]

        except Exception as e:
            logger.error(f"Failed to read cache for {domain}: {e}")
            return None
