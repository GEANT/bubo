# core/web/headers.py

import aiohttp
import asyncio
from core.logging.logger import setup_logger
from core.web.models import SecurityHeadersInfo

logger = setup_logger(__name__)


USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) GÉANT-ComplianceScanner/1.0 InternetAndEmailSdandards/1.0"


async def check_security_headers(
    domain: str, port: int, timeout: int
) -> SecurityHeadersInfo:
    """Check security-related HTTP headers."""
    logger.debug(f"Checking security headers for {domain}:{port}")

    headers_info = SecurityHeadersInfo()

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

                response_headers = {k.lower(): v for k, v in response.headers.items()}

                headers_info.content_type_options = response_headers.get(
                    "x-content-type-options"
                )
                logger.debug(
                    f"X-Content-Type-Options: {headers_info.content_type_options}"
                )

                headers_info.frame_options = response_headers.get("x-frame-options")
                logger.debug(f"X-Frame-Options: {headers_info.frame_options}")

                headers_info.content_security_policy = response_headers.get(
                    "content-security-policy"
                )
                logger.debug(
                    f"Content-Security-Policy: {headers_info.content_security_policy}"
                )

                headers_info.referrer_policy = response_headers.get("referrer-policy")
                logger.debug(f"Referrer-Policy: {headers_info.referrer_policy}")

    except aiohttp.ClientConnectorError as e:
        logger.error(
            f"Connection error checking security headers for {domain}:{port}: {e}"
        )
    except aiohttp.ClientError as e:
        logger.error(f"Client error checking security headers for {domain}:{port}: {e}")
    except asyncio.TimeoutError:
        logger.warning(f"Timeout checking security headers for {domain}:{port}")
    except Exception as e:
        logger.error(
            f"Unexpected error checking security headers for {domain}:{port}: {e}",
            exc_info=True,
        )

    logger.debug(
        f"Security headers check results for {domain}:{port}: "
        f"X-Content-Type-Options={bool(headers_info.content_type_options)}, "
        f"X-Frame-Options={bool(headers_info.frame_options)}, "
        f"CSP={bool(headers_info.content_security_policy)}, "
        f"Referrer-Policy={bool(headers_info.referrer_policy)}"
    )
    return headers_info
