# core/web/headers.py
from typing import Dict, Optional
from core.logging.logger import setup_logger
from core.web.models import SecurityHeadersInfo

logger = setup_logger(__name__)


USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) GÉANT-ComplianceScanner/1.0 InternetAndEmailSdandards/1.0"


async def check_security_headers(
    domain: str,
    port: int,
    timeout: int,
    response_headers: Optional[Dict[str, str]] = None,
) -> SecurityHeadersInfo:
    """Check security-related HTTP headers from response or fetch if not provided."""
    logger.debug(f"Checking security headers for {domain}:{port}")
    headers_info = SecurityHeadersInfo()

    # If no headers were provided, return default empty results
    if not response_headers:
        logger.warning(f"No response headers available for {domain}:{port}")
        return headers_info

    headers_info.content_type_options = response_headers.get("x-content-type-options")
    logger.debug(f"X-Content-Type-Options: {headers_info.content_type_options}")

    headers_info.frame_options = response_headers.get("x-frame-options")
    logger.debug(f"X-Frame-Options: {headers_info.frame_options}")

    headers_info.content_security_policy = response_headers.get(
        "content-security-policy"
    )
    logger.debug(f"Content-Security-Policy: {headers_info.content_security_policy}")

    headers_info.referrer_policy = response_headers.get("referrer-policy")
    logger.debug(f"Referrer-Policy: {headers_info.referrer_policy}")

    logger.debug(
        f"Security headers check results for {domain}:{port}: "
        f"X-Content-Type-Options={bool(headers_info.content_type_options)}, "
        f"X-Frame-Options={bool(headers_info.frame_options)}, "
        f"CSP={bool(headers_info.content_security_policy)}, "
        f"Referrer-Policy={bool(headers_info.referrer_policy)}"
    )
    return headers_info
