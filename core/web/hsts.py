# core/web/hsts.py

import re
from core.logging.logger import setup_logger
from core.web.models import HSTSInfo


logger = setup_logger(__name__)


async def check_hsts(
    domain: str,
    port: int,
    timeout: int,
    response_headers: dict[str, str] | None = None,
) -> HSTSInfo:
    """Check HSTS configuration from provided headers or fetch if not provided."""
    logger.debug(f"Checking HSTS for {domain}:{port}")

    hsts_info = HSTSInfo(
        enabled=False,
        max_age=0,
        include_subdomains=False,
        preload=False,
        header_value=None,
    )

    if not response_headers:
        logger.warning(f"No response headers available for {domain}:{port}")
        return hsts_info

    hsts_header = response_headers.get("strict-transport-security")

    if hsts_header:
        logger.debug(f"Found HSTS header: {hsts_header}")
        hsts_info.enabled = True
        hsts_info.header_value = hsts_header

        max_age_match = re.search(r"max-age=(\d+)", hsts_header, re.IGNORECASE)
        if max_age_match:
            hsts_info.max_age = int(max_age_match.group(1))
            logger.debug(f"HSTS max-age: {hsts_info.max_age}")

        hsts_info.include_subdomains = bool(
            re.search(r"includeSubDomains", hsts_header, re.IGNORECASE)
        )
        logger.debug(f"HSTS includeSubDomains: {hsts_info.include_subdomains}")

        hsts_info.preload = bool(re.search(r"preload", hsts_header, re.IGNORECASE))
        logger.debug(f"HSTS preload: {hsts_info.preload}")
    else:
        logger.debug(f"No HSTS header found for {domain}:{port}")

    logger.debug(
        f"HSTS check results for {domain}:{port}: enabled={hsts_info.enabled}, max-age={hsts_info.max_age}"
    )
    return hsts_info
