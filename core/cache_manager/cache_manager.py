import json
import os
import gzip
from datetime import datetime, timedelta
from typing import Any

from core.logging.logger import setup_logger
from core.report.json_utils import convert_sets_to_lists, json_dumps


logger = setup_logger(__name__)


class SetEncoder(json.JSONEncoder):
    """Custom JSON encoder that converts sets to lists for serialization."""

    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


class DomainResultsCache:
    """
    Caches domain validation results to disk with configurable expiration.
    Enhanced to efficiently handle large nested structures from security assessments.
    """

    def __init__(self, cache_dir: str, cache_duration: timedelta = timedelta(days=1)):
        self.cache_dir = cache_dir
        self.cache_duration = cache_duration
        os.makedirs(cache_dir, exist_ok=True)

    def _get_cache_path(self, domain: str) -> str:
        sanitized_domain = domain.replace("/", "_").replace("\\", "_")
        return os.path.join(self.cache_dir, f"{sanitized_domain}_cache.json")

    def _get_compressed_cache_path(self, domain: str) -> str:
        sanitized_domain = domain.replace("/", "_").replace("\\", "_")
        return os.path.join(self.cache_dir, f"{sanitized_domain}_cache.json.gz")

    def save_results(self, domain: str, results: dict) -> None:
        serializable_results = convert_sets_to_lists(results)
        cache_data = {
            "timestamp": datetime.now().isoformat(),
            "results": serializable_results,
        }
        cache_path = self._get_cache_path(domain)

        try:
            json_data = json_dumps(cache_data, indent=2)

            if len(json_data) > 100 * 1024:
                compressed_path = self._get_compressed_cache_path(domain)
                with gzip.open(compressed_path, "wt", encoding="utf-8") as f:
                    f.write(json_data)
                logger.debug(
                    f"Saved compressed cache for {domain} ({len(json_data) / 1024:.1f}KB)"
                )

                if os.path.exists(cache_path):
                    os.remove(cache_path)
            else:
                with open(cache_path, "w", encoding="utf-8") as f:
                    f.write(json_data)

                compressed_path = self._get_compressed_cache_path(domain)
                if os.path.exists(compressed_path):
                    os.remove(compressed_path)
        except Exception as e:
            logger.error(f"Failed to save cache for {domain}: {e}")

    def get_results(
        self, domain: str, ignore_cache: bool = False
    ) -> dict[str, Any] | None:
        """
        Retrieve domain validation results from cache if valid.
        Handles both compressed and uncompressed cache formats.

        Args:
            domain: Domain name
            ignore_cache: If True, ignore cached results

        Returns:
            Cached validation results or None if not found/expired
        """
        if ignore_cache:
            return None

        cache_path = self._get_cache_path(domain)
        compressed_path = self._get_compressed_cache_path(domain)

        if os.path.exists(compressed_path):
            try:
                with gzip.open(compressed_path, "rt", encoding="utf-8") as f:
                    cache_data = json.loads(f.read())

                cache_time = datetime.fromisoformat(cache_data["timestamp"])
                if datetime.now() - cache_time > self.cache_duration:
                    logger.info(f"Compressed cache expired for {domain}")
                    return None

                logger.info(f"Using compressed cached results for {domain}")
                return cache_data["results"]
            except Exception as e:
                logger.error(f"Failed to read compressed cache for {domain}: {e}")
                return None

        elif os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as f:
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

        return None


class IPWhoisCache:
    """
    Caches IPWhois lookup results to reduce API calls and improve performance.
    """

    def __init__(self, cache_dir: str, cache_duration: timedelta = timedelta(days=30)):
        """
        Initialize the IPWhois cache.

        Args:
            cache_dir: Directory to store cache files
            cache_duration: How long cache entries remain valid
        """
        self.cache_dir = os.path.join(cache_dir, "ipwhois")
        self.cache_duration = cache_duration
        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_cache_path(self, ip: str) -> str:
        """
        Generate a file path for the IP cache entry.

        Args:
            ip: IP address to cache

        Returns:
            Path to the cache file
        """
        sanitized_ip = ip.replace(".", "_").replace(":", "_")
        return os.path.join(self.cache_dir, f"{sanitized_ip}_cache.json")

    def save_result(self, ip: str, asn: str, prefix: str) -> None:
        """
        Save IPWhois lookup result to cache.

        Args:
            ip: IP address
            asn: Autonomous System Number
            prefix: Network prefix
        """
        cache_data = {
            "timestamp": datetime.now().isoformat(),
            "asn": asn,
            "prefix": prefix,
        }

        try:
            with open(self._get_cache_path(ip), "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2)
                logger.debug(f"Saved IPWhois cache for {ip}")
        except Exception as e:
            logger.error(f"Failed to save IPWhois cache for {ip}: {e}")

    def get_result(self, ip: str, ignore_cache: bool = False) -> tuple[str, str] | None:
        """
        Retrieve IPWhois result from cache if available and not expired.

        Args:
            ip: IP address
            ignore_cache: If True, ignore cached results

        Returns:
            Tuple of (ASN, prefix) or None if not found/expired
        """
        if ignore_cache:
            return None

        cache_path = self._get_cache_path(ip)

        if not os.path.exists(cache_path):
            return None

        try:
            with open(cache_path, encoding="utf-8") as f:
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
