# core/network/ip_tools.py

import asyncio
import ipaddress
import os
from datetime import timedelta
from random import random

from ipwhois import IPWhois

from core.logging.logger import setup_logger
from core.cache_manager.cache_manager import IPWhoisCache

logger = setup_logger(__name__)
_ipwhois_cache = None


def is_valid_ip(ip_string: str) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).

    Args:
        ip_string: String to check

    Returns:
        True if string is a valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


async def get_asn_and_prefix(
    ip: str, ignore_cache: bool = False
) -> tuple[str | None, str | None]:
    """
    Retrieve the ASN and prefix for a given IP using the ipwhois library or cache_manager.

    Args:
        ip: IP address to look up
        ignore_cache: Whether to ignore cached results

    Returns:
        Tuple of (ASN, prefix) or (None, None) if lookup fails
    """
    global _ipwhois_cache

    if _ipwhois_cache is None:
        cache_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "..", "cache"
        )
        _ipwhois_cache = IPWhoisCache(cache_dir, timedelta(days=30))

    if not ignore_cache:
        cached_result = _ipwhois_cache.get_result(ip, False)
        if cached_result:
            return cached_result

    logger.debug(f"Getting ASN and prefix for IP {ip}...")
    retries = 0
    max_retries = 3

    while retries <= max_retries:
        try:
            obj = IPWhois(ip)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, obj.lookup_rdap)

            asn = result.get("asn").split(" ")[0]
            prefix = result.get("asn_cidr")

            _ipwhois_cache.save_result(ip, asn, prefix)

            return asn, prefix

        except Exception as e:
            logger.error(f"Error retrieving ASN and prefix for IP {ip}: {e}")

            if retries < max_retries:
                wait_time = 4 + 7 * random()
                logger.info(
                    f"Retrying to get ASN for {ip} in {wait_time:.2f} seconds..."
                )
                await asyncio.sleep(wait_time)

            retries += 1

    return None, None
