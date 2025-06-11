"""
IANA TLS parameter processing for cipher suite evaluation.

This module parses and maps IANA TLS parameters to OpenSSL cipher names.
"""

import asyncio
import csv
import logging
import os
import re
import subprocess
from pathlib import Path

from dotenv import load_dotenv

from bubo.core.tls.cipher_utils import get_cache_directory
from bubo.core.tls.iana_updater import (
    DEFAULT_CACHE_DURATION_DAYS,
    check_and_update_iana_csv,
)

logger = logging.getLogger(__name__)
load_dotenv()


class IANACipherManager:
    """Manages IANA cipher mappings and provides lookup functionality."""

    def __init__(self):
        self._iana_cipher_map: dict[str, dict[str, str]] = {}
        self._openssl_to_iana_map: dict[str, str] = {}
        self._initialized = False

    @staticmethod
    def _normalize_cipher_name(name: str) -> str:
        """
        Normalize cipher name for comparison between OpenSSL and IANA formats.

        Args:
            name: Cipher name (either OpenSSL or IANA format)

        Returns:
            Normalized cipher name for comparison
        """
        name = re.sub(r"^(TLS|SSL)_", "", name)
        name = name.replace("_WITH_", "_")
        name = name.replace("CHACHA20_POLY1305", "CHACHA20-POLY1305")
        name = name.replace("-", "_")
        name = name.replace("/", "_")
        return name.upper()

    def load_iana_ciphers(self, csv_path: str) -> dict[str, dict[str, str]]:
        """
        Load IANA TLS cipher information from CSV file.

        Args:
            csv_path: Path to IANA TLS parameters CSV file

        Returns:
            Dictionary mapping cipher value to cipher details
        """
        result = {}

        try:
            with open(csv_path, encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if "Unassigned" in row.get("Description", ""):
                        continue

                    value = row.get("Value", "")
                    description = row.get("Description", "")
                    dtls_ok = row.get("DTLS-OK", "N") == "Y"
                    recommended = row.get("Recommended", "N") == "Y"
                    reference = row.get("Reference", "")

                    result[value] = {
                        "value": value,
                        "name": description,
                        "dtls_ok": dtls_ok,
                        "recommended": recommended,
                        "reference": reference,
                        "normalized_name": self._normalize_cipher_name(description),
                    }
        except Exception as e:
            logger.error(f"Error loading IANA cipher CSV file: {e}")
            return {}

        self._iana_cipher_map = result
        return result

    def map_openssl_to_iana_ciphers(self) -> dict[str, str]:
        """
        Create mapping between OpenSSL cipher names and IANA cipher values.

        Returns:
            Dictionary mapping OpenSSL cipher names to IANA cipher values
        """
        if not self._iana_cipher_map:
            logger.warning("IANA ciphers not loaded, cannot create mapping")
            return {}

        result = {}

        # Special cases mapping - these are known mappings that don't follow standard patterns
        special_cases = {
            "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "DHE-RSA-AES128-GCM-SHA256": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "DHE-RSA-AES256-GCM-SHA384": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "DHE-RSA-CHACHA20-POLY1305": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256": "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384": "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
        }

        # First, map the special cases
        for openssl_name, iana_name in special_cases.items():
            for iana_value, cipher_data in self._iana_cipher_map.items():
                if cipher_data["name"] == iana_name:
                    result[openssl_name] = iana_value
                    break

        # Get all OpenSSL ciphers
        openssl_ciphers = self.get_all_openssl_ciphers()

        # Map remaining ciphers by normalized name comparison
        for openssl_name in openssl_ciphers:
            if openssl_name in result:
                continue

            normalized_openssl = self._normalize_cipher_name(openssl_name)

            for iana_value, cipher_data in self._iana_cipher_map.items():
                normalized_iana = cipher_data["normalized_name"]

                if normalized_openssl == normalized_iana:
                    result[openssl_name] = iana_value
                    break

        self._openssl_to_iana_map = result
        return result

    @staticmethod
    def get_all_openssl_ciphers() -> list[str]:
        """
        Get list of all OpenSSL cipher names.

        Returns:
            List of OpenSSL cipher names
        """
        try:
            result = subprocess.run(
                ["openssl", "ciphers", "ALL:COMPLEMENTOFALL"],
                capture_output=True,
                text=True,
                check=True,
            )
            return [cipher.strip() for cipher in result.stdout.split(":")]
        except Exception as e:
            logger.error(f"Error getting OpenSSL ciphers: {e}")
            return []

    def get_iana_cipher_info(self, openssl_name: str) -> dict[str, str] | None:
        """
        Get IANA cipher information for an OpenSSL cipher name.

        Args:
            openssl_name: OpenSSL cipher name

        Returns:
            Dictionary with IANA cipher information or None if not found
        """
        if not self._initialized:
            logger.warning("IANA mappings not initialized")
            return None

        iana_value = self._openssl_to_iana_map.get(openssl_name)
        if not iana_value:
            return None

        return self._iana_cipher_map.get(iana_value)

    def is_recommended_cipher(self, openssl_name: str) -> bool:
        """
        Check if a cipher is recommended by IANA.

        Args:
            openssl_name: OpenSSL cipher name

        Returns:
            True if the cipher is recommended, False otherwise
        """
        info = self.get_iana_cipher_info(openssl_name)
        return info is not None and info.get("recommended", False)

    def is_dtls_compatible(self, openssl_name: str) -> bool:
        """
        Check if a cipher is compatible with DTLS.

        Args:
            openssl_name: OpenSSL cipher name

        Returns:
            True if the cipher is DTLS compatible, False otherwise
        """
        info = self.get_iana_cipher_info(openssl_name)
        return info is not None and info.get("dtls_ok", False)

    def initialize(self, csv_path: str) -> bool:
        """
        Initialize IANA mappings from CSV file.

        Args:
            csv_path: Path to IANA TLS parameters CSV file

        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            cache_days = int(
                os.environ.get("IANA_UPDATE_CACHE_DAYS", DEFAULT_CACHE_DURATION_DAYS)
            )

            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            updated = loop.run_until_complete(
                check_and_update_iana_csv(csv_path, cache_days)
            )

            if not updated:
                logger.warning(
                    "Could not update IANA CSV file, using existing file if available"
                )

            self.load_iana_ciphers(csv_path)

            self.map_openssl_to_iana_ciphers()

            self._initialized = bool(self._iana_cipher_map) and bool(
                self._openssl_to_iana_map
            )

            if self._initialized:
                logger.debug(
                    f"Successfully initialized IANA cipher mappings "
                    f"({len(self._iana_cipher_map)} IANA ciphers, "
                    f"{len(self._openssl_to_iana_map)} OpenSSL mappings)"
                )

            return self._initialized

        except Exception as e:
            logger.error(f"Error initializing IANA mappings: {e}")
            return False

    @property
    def is_initialized(self) -> bool:
        """Check if the manager has been initialized."""
        return self._initialized


default_cipher_manager = IANACipherManager()


def initialize_iana_mappings(csv_path: str) -> bool:
    """
    Initialize IANA mappings using the default cipher manager.

    Args:
        csv_path: Path to IANA CSV file (will use default cache location if not absolute)

    Returns:
        True if initialization successful
    """
    csv_path = Path(csv_path)
    if not csv_path.is_absolute():
        csv_path = get_cache_directory() / "iana_tls_parameters.csv"

    return default_cipher_manager.initialize(str(csv_path))


def get_iana_cipher_info(openssl_name: str) -> dict[str, str] | None:
    """Get IANA cipher info using the default cipher manager."""
    return default_cipher_manager.get_iana_cipher_info(openssl_name)


def is_recommended_cipher(openssl_name: str) -> bool:
    """Check if cipher is recommended using the default cipher manager."""
    return default_cipher_manager.is_recommended_cipher(openssl_name)


def is_dtls_compatible(openssl_name: str) -> bool:
    """Check if cipher is DTLS compatible using the default cipher manager."""
    return default_cipher_manager.is_dtls_compatible(openssl_name)
