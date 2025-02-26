# core/cache_manager.py

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from core.custom_logger.logger import setup_logger

setup_logger()
logger = logging.getLogger(__name__)


class DomainResultsCache:
    def __init__(self, cache_dir: str, cache_duration: timedelta = timedelta(days=1)):
        self.cache_dir = cache_dir
        self.cache_duration = cache_duration
        os.makedirs(cache_dir, exist_ok=True)

    def _get_cache_path(self, domain: str) -> str:
        sanitized_domain = domain.replace("/", "_").replace("\\", "_")
        return os.path.join(self.cache_dir, f"{sanitized_domain}_cache.json")

    def save_results(self, domain: str, results: Dict) -> None:
        cache_data = {"timestamp": datetime.now().isoformat(), "results": results}

        try:
            with open(self._get_cache_path(domain), "w") as f:
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
            with open(cache_path, "r") as f:
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


class IPWhoisCache:
    """Caches IPWhois lookup results to reduce API calls and improve performance."""
    def __init__(self, cache_dir: str, cache_duration: timedelta = timedelta(days=30)):
        self.cache_dir = os.path.join(cache_dir, "ipwhois")
        self.cache_duration = cache_duration
        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_cache_path(self, ip: str) -> str:
        """Generate a file path for the IP cache entry."""
        # Sanitize the IP to use as a filename
        sanitized_ip = ip.replace(".", "_").replace(":", "_")
        return os.path.join(self.cache_dir, f"{sanitized_ip}_cache.json")

    def save_result(self, ip: str, asn: str, prefix: str) -> None:
        """Save IPWhois lookup result to cache."""
        cache_data = {
            "timestamp": datetime.now().isoformat(),
            "asn": asn,
            "prefix": prefix
        }

        try:
            with open(self._get_cache_path(ip), "w") as f:
                json.dump(cache_data, f, indent=2)
                logger.debug(f"Saved IPWhois cache for {ip}")
        except Exception as e:
            logger.error(f"Failed to save IPWhois cache for {ip}: {e}")

    def get_result(self, ip: str, ignore_cache: bool = False) -> Optional[Tuple[str, str]]:
        """Retrieve IPWhois result from cache if available and not expired."""
        if ignore_cache:
            return None

        cache_path = self._get_cache_path(ip)

        if not os.path.exists(cache_path):
            return None

        try:
            with open(cache_path, "r") as f:
                cache_data = json.load(f)

            cache_time = datetime.fromisoformat(cache_data["timestamp"])
            if datetime.now() - cache_time > self.cache_duration:
                logger.info(f"IPWhois cache expired for {ip}")
                return None

            logger.debug(f"Using cached IPWhois results for {ip}")
            return cache_data["asn"], cache_data["prefix"]

        except Exception as e:
            logger.error(f"Failed to read IPWhois cache for {ip}: {e}")
            return None
