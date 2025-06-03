from dataclasses import dataclass
from enum import Enum


@dataclass
class HSTSInfo:
    """HSTS header information."""

    enabled: bool
    max_age: int
    include_subdomains: bool
    preload: bool
    header_value: str | None = None


@dataclass
class SecurityHeadersInfo:
    """Security headers information."""

    content_type_options: str | None = None
    frame_options: str | None = None
    content_security_policy: str | None = None
    referrer_policy: str | None = None


class SecurityRating(Enum):
    """Security rating levels."""

    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    UNKNOWN = "unknown"
