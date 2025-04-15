from dataclasses import dataclass
from typing import Optional
from enum import Enum


@dataclass
class HSTSInfo:
    """HSTS header information."""

    enabled: bool
    max_age: int
    include_subdomains: bool
    preload: bool
    header_value: Optional[str] = None


@dataclass
class SecurityHeadersInfo:
    """Security headers information."""

    content_type_options: Optional[str] = None
    frame_options: Optional[str] = None
    content_security_policy: Optional[str] = None
    referrer_policy: Optional[str] = None


class SecurityRating(Enum):
    """Security rating levels."""

    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    UNKNOWN = "unknown"
