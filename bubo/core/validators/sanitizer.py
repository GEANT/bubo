# core/validators/sanitizer.py

import html
import re

from bubo.core.logging.logger import setup_logger

logger = setup_logger(__name__)


async def validate_hostname(hostname: str) -> bool:
    """
    Validate that a string is a valid hostname according to DNS rules.

    Args:
        hostname: Hostname to validate

    Returns:
        True if valid hostname, False otherwise
    """
    if not hostname or len(hostname) > 255:
        return False

    if hostname[-1] == ".":
        hostname = hostname[:-1]

    pattern = r"^(?!-)[A-Za-z0-9\u4e00-\u9fa5-]+(?<!-)(?:\.(?!-)[A-Za-z0-9\u4e00-\u9fa5-]+(?<!-))*\.(?!-)[A-Za-z\u4e00-\u9fa5]{2,}(?<!-)$"

    return bool(
        re.match(pattern, hostname)
        and all(len(part) <= 63 for part in hostname.split("."))
    )


def sanitize_domain(domain: str) -> str:
    """
    Sanitize a domain name to prevent injection attacks.

    Args:
        domain: Domain name to sanitize

    Returns:
        Sanitized domain name

    Raises:
        ValueError: If domain contains invalid characters
    """
    domain = domain.strip().strip("'\"")
    if not re.match(r"^[a-zA-Z0-9.\-_]+$", domain):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain


def sanitize_text_field(text: str | None, max_length: int = 100) -> str:
    """
    Sanitize text fields to prevent XSS and injection attacks.

    Args:
        text: Text to sanitize
        max_length: Maximum length to allow

    Returns:
        Sanitized text
    """
    if text is None:
        return ""

    text = text.strip()

    if len(text) > max_length:
        text = text[:max_length]

    return html.escape(text)
