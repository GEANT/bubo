import re
import aiohttp
import asyncio
from core.logging.logger import setup_logger
from core.web.models import HSTSInfo
from core.web.headers import USER_AGENT


logger = setup_logger(__name__)


async def check_hsts(domain: str, port: int, timeout: int) -> HSTSInfo:
    """Check HSTS configuration using HTTP request."""
    logger.debug(f"Checking HSTS for {domain}:{port}")

    hsts_info = HSTSInfo(
        enabled=False,
        max_age=0,
        include_subdomains=False,
        preload=False,
        header_value=None,
    )

    url = f"https://{domain}"
    if port != 443:
        url = f"https://{domain}:{port}"

    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Connection": "keep-alive",
        }

        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            logger.debug(f"Sending GET request to {url}")
            async with session.get(
                url, allow_redirects=True, headers=headers, ssl=False
            ) as response:
                logger.debug(f"Response status: {response.status}")
                logger.debug(f"Response headers: {response.headers}")

                hsts_header = None
                for header_name, value in response.headers.items():
                    if header_name.lower() == "strict-transport-security":
                        hsts_header = value
                        break

                if hsts_header:
                    logger.debug(f"Found HSTS header: {hsts_header}")
                    hsts_info.enabled = True
                    hsts_info.header_value = hsts_header

                    max_age_match = re.search(
                        r"max-age=(\d+)", hsts_header, re.IGNORECASE
                    )
                    if max_age_match:
                        hsts_info.max_age = int(max_age_match.group(1))
                        logger.debug(f"HSTS max-age: {hsts_info.max_age}")

                    hsts_info.include_subdomains = bool(
                        re.search(r"includeSubDomains", hsts_header, re.IGNORECASE)
                    )
                    logger.debug(
                        f"HSTS includeSubDomains: {hsts_info.include_subdomains}"
                    )

                    hsts_info.preload = bool(
                        re.search(r"preload", hsts_header, re.IGNORECASE)
                    )
                    logger.debug(f"HSTS preload: {hsts_info.preload}")
                else:
                    logger.debug(f"No HSTS header found for {domain}:{port}")

    except aiohttp.ClientConnectorError as e:
        logger.error(f"Connection error checking HSTS for {domain}:{port}: {e}")
    except aiohttp.ClientError as e:
        logger.error(f"Client error checking HSTS for {domain}:{port}: {e}")
    except asyncio.TimeoutError:
        logger.error(f"Timeout checking HSTS for {domain}:{port}")
    except Exception as e:
        logger.error(
            f"Unexpected error checking HSTS for {domain}:{port}: {e}", exc_info=True
        )

    logger.debug(
        f"HSTS check results for {domain}:{port}: enabled={hsts_info.enabled}, max-age={hsts_info.max_age}"
    )
    return hsts_info
