"""
IANA TLS parameter processing for cipher suite evaluation.

This module parses and maps IANA TLS parameters to OpenSSL cipher names.
"""

import csv
import re
from typing import Dict, List, Optional
import logging
import os
import asyncio
from dotenv import load_dotenv

from core.tls.iana_updater import check_and_update_iana_csv, DEFAULT_CACHE_DURATION_DAYS


logger = logging.getLogger(__name__)
load_dotenv()


_iana_cipher_map: Dict[str, Dict[str, str]] = {}
_openssl_to_iana_map: Dict[str, str] = {}


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


def load_iana_ciphers(csv_path: str) -> Dict[str, Dict[str, str]]:
    """
    Load IANA TLS cipher information from CSV file.

    Args:
        csv_path: Path to IANA TLS parameters CSV file

    Returns:
        Dictionary mapping cipher value to cipher details
    """
    global _iana_cipher_map, _openssl_to_iana_map

    result = {}

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
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
                    "normalized_name": _normalize_cipher_name(description),
                }
    except Exception as e:
        logger.error(f"Error loading IANA cipher CSV file: {e}")
        return {}

    _iana_cipher_map = result
    return result


def map_openssl_to_iana_ciphers() -> Dict[str, str]:
    """
    Create mapping between OpenSSL cipher names and IANA cipher values.

    Returns:
        Dictionary mapping OpenSSL cipher names to IANA cipher values
    """
    global _iana_cipher_map, _openssl_to_iana_map

    if not _iana_cipher_map:
        logger.warning("IANA ciphers not loaded, cannot create mapping")
        return {}

    result = {}

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

    for openssl_name, iana_name in special_cases.items():
        for iana_value, cipher_data in _iana_cipher_map.items():
            if cipher_data["name"] == iana_name:
                result[openssl_name] = iana_value
                break

    for openssl_name in get_all_openssl_ciphers():
        if openssl_name in result:
            continue

        normalized_openssl = _normalize_cipher_name(openssl_name)

        for iana_value, cipher_data in _iana_cipher_map.items():
            normalized_iana = cipher_data["normalized_name"]

            if normalized_openssl == normalized_iana:
                result[openssl_name] = iana_value
                break

    _openssl_to_iana_map = result
    return result


def get_all_openssl_ciphers() -> List[str]:
    """
    Get list of all OpenSSL cipher names.

    Returns:
        List of OpenSSL cipher names
    """
    import subprocess

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


def get_iana_cipher_info(openssl_name: str) -> Optional[Dict[str, str]]:
    """
    Get IANA cipher information for an OpenSSL cipher name.

    Args:
        openssl_name: OpenSSL cipher name

    Returns:
        Dictionary with IANA cipher information or None if not found
    """
    global _iana_cipher_map, _openssl_to_iana_map

    if not _iana_cipher_map or not _openssl_to_iana_map:
        logger.warning("IANA mappings not initialized")
        return None

    iana_value = _openssl_to_iana_map.get(openssl_name)
    if not iana_value:
        return None

    return _iana_cipher_map.get(iana_value)


def is_recommended_cipher(openssl_name: str) -> bool:
    """
    Check if a cipher is recommended by IANA.

    Args:
        openssl_name: OpenSSL cipher name

    Returns:
        True if the cipher is recommended, False otherwise
    """
    info = get_iana_cipher_info(openssl_name)
    return info is not None and info.get("recommended", False)


def is_dtls_compatible(openssl_name: str) -> bool:
    """
    Check if a cipher is compatible with DTLS.

    Args:
        openssl_name: OpenSSL cipher name

    Returns:
        True if the cipher is DTLS compatible, False otherwise
    """
    info = get_iana_cipher_info(openssl_name)
    return info is not None and info.get("dtls_ok", False)


def initialize_iana_mappings(csv_path: str) -> bool:
    """
    Initialize IANA mappings from CSV file.

    Checks for updates to the IANA CSV file once per month to reduce network overhead.
    Set the IANA_UPDATE_CACHE_DAYS environment variable to change the cache duration.

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

        load_iana_ciphers(csv_path)
        map_openssl_to_iana_ciphers()
        return bool(_iana_cipher_map) and bool(_openssl_to_iana_map)
    except Exception as e:
        logger.error(f"Error initializing IANA mappings: {e}")
        return False
