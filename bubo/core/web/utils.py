from typing import Any

from bubo.core.logging.logger import setup_logger
from bubo.core.tls.models import (
    CertificateResult,
    SignatureAlgorithmSecurity,
    TLSProtocolResult,
)
from bubo.core.web.models import HSTSInfo, SecurityHeadersInfo, SecurityRating

logger = setup_logger(__name__)


def build_security_assessment(
    protocol_results: list[TLSProtocolResult],
    cert_result: CertificateResult,
    has_weak_ciphers: bool,
    hsts_info: HSTSInfo | None = None,
    headers_info: SecurityHeadersInfo | None = None,
) -> dict[str, Any]:
    """
    Build security assessment based on checks with weighted scoring.

    Categorizes issues into critical, major, and minor categories and
    assigns a rating based on the severity and number of issues found.

    Returns a dictionary with assessment details including issues list,
    counts by severity, and an overall security rating.
    """
    security_issues = []
    critical_issues = []
    major_issues = []
    minor_issues = []

    if hasattr(cert_result, "connection_error") and cert_result.connection_error:
        return {
            "issues": ["Cannot assess security due to connection issues"],
            "issues_count": 1,
            "rating": SecurityRating.UNKNOWN.value,
            "connectivity_error": True,
        }

    secure_protocols = [
        r.protocol_name for r in protocol_results if r.supported and r.secure
    ]
    insecure_protocols = [
        r.protocol_name for r in protocol_results if r.supported and not r.secure
    ]

    if not secure_protocols:
        _add_issue("No secure protocols supported", critical_issues, security_issues)
    elif insecure_protocols:
        if len(secure_protocols) == 0:
            _add_issue("Insecure protocols supported", critical_issues, security_issues)
        else:
            _add_issue("Insecure protocols supported", major_issues, security_issues)

    if has_weak_ciphers:
        _add_issue("Weak cipher suites supported", major_issues, security_issues)

    if cert_result.is_expired:
        _add_issue("Certificate expired", critical_issues, security_issues)
    elif (
        cert_result.days_until_expiry is not None and cert_result.days_until_expiry < 30
    ):
        _add_issue(
            f"Certificate expiring soon ({cert_result.days_until_expiry} day(s))",
            major_issues,
            security_issues,
        )

    if cert_result.is_self_signed:
        _add_issue("Self-signed certificate", critical_issues, security_issues)

    if not cert_result.chain_trusted and cert_result.chain_error:
        _add_issue("Untrusted certificate chain", critical_issues, security_issues)

    if cert_result.key_info and not cert_result.key_info.secure:
        _add_issue(
            f"Weak key size ({cert_result.key_info.length} bits for {cert_result.key_info.type})",
            critical_issues,
            security_issues,
        )

    if (
        cert_result.signature_algorithm
        and cert_result.signature_algorithm.security == SignatureAlgorithmSecurity.WEAK
    ):
        _add_issue(
            f"Weak signature algorithm ({cert_result.signature_algorithm.name})",
            critical_issues,
            security_issues,
        )

    if (
        cert_result.subject_alternative_names
        and not cert_result.subject_alternative_names.contains_domain
    ):
        _add_issue(
            "Domain not found in Subject Alternative Names",
            major_issues,
            security_issues,
        )

    if hsts_info:
        if not hsts_info.enabled:
            _add_issue("HSTS not enabled", major_issues, security_issues)
        else:
            if hsts_info.max_age < 31536000:
                _add_issue(
                    f"HSTS max-age too short ({hsts_info.max_age} seconds, should be at least 1 year = 31536000)",
                    minor_issues,
                    security_issues,
                )
            if not hsts_info.include_subdomains:
                _add_issue(
                    "HSTS missing includeSubDomains directive",
                    minor_issues,
                    security_issues,
                )

    if headers_info:
        missing_headers = _get_missing_headers(headers_info)

        if missing_headers:
            if len(missing_headers) >= 3:
                _add_issue(
                    f"Multiple security headers missing: {', '.join(missing_headers)}",
                    major_issues,
                    security_issues,
                )
            else:
                _add_issue(
                    f"Some security headers missing: {', '.join(missing_headers)}",
                    minor_issues,
                    security_issues,
                )

    rating = _determine_rating(critical_issues, major_issues, minor_issues)

    return {
        "issues": security_issues,
        "issues_count": len(security_issues),
        "critical_issues_count": len(critical_issues),
        "major_issues_count": len(major_issues),
        "minor_issues_count": len(minor_issues),
        "rating": rating,
        "connectivity_error": False,
    }


def _add_issue(issue: str, category_list: list[str], main_list: list[str]) -> None:
    """Helper to add an issue to both a category list and the main issues list."""
    category_list.append(issue)
    main_list.append(issue)


def _get_missing_headers(headers_info: SecurityHeadersInfo) -> list[str]:
    """Helper to collect missing security headers."""
    missing = []
    if not headers_info.content_type_options:
        missing.append("X-Content-Type-Options")
    if not headers_info.frame_options:
        missing.append("X-Frame-Options")
    if not headers_info.content_security_policy:
        missing.append("Content-Security-Policy")
    if not headers_info.referrer_policy:
        missing.append("Referrer-Policy")
    return missing


def _determine_rating(
    critical_issues: list[str], major_issues: list[str], minor_issues: list[str]
) -> str:
    """
    Determine security rating based on the number and severity of issues.

    Rating logic:
    - EXCELLENT: No issues of any kind
    - GOOD: No critical issues, at most 2 major issues, and at most 3 minor issues,
            with a combined total of no more than 3 issues
    - FAIR: No critical issues, at most 3 major issues, and at most 5 total issues
    - POOR: Any critical issues, or too many major/minor issues

    Args:
        critical_issues: List of critical security issues
        major_issues: List of major security issues
        minor_issues: List of minor security issues

    Returns:
        str: The security rating value from the SecurityRating enum
    """
    num_critical = len(critical_issues)
    num_major = len(major_issues)
    num_minor = len(minor_issues)
    total_issues = num_critical + num_major + num_minor

    if total_issues == 0 or (num_critical == 0 and num_major == 0 and num_minor <= 2):
        return SecurityRating.EXCELLENT.value
    if num_critical > 0 or num_major > 3 or total_issues > 5:
        return SecurityRating.POOR.value
    if num_major > 2 or total_issues > 3:
        return SecurityRating.FAIR.value
    return SecurityRating.GOOD.value


def parse_security_header(headers, header_name, default=None):
    """
    Case-insensitive parser for HTTP security headers.

    Args:
        headers: Dictionary of HTTP headers
        header_name: Header name to find (case-insensitive)
        default: Default value if header not found

    Returns:
        Header value or default
    """
    if not headers:
        return default

    for name, value in headers.items():
        if name.lower() == header_name.lower():
            return value
    return default


async def resolve_domain(domain: str, port: int, check_func, *args, **kwargs):
    """
    Try to execute a check function with the original domain, then with www-prefixed version if needed.

    Args:
        domain: The domain to check
        port: The port to connect to
        check_func: The async function to execute
        *args, **kwargs: Additional arguments to pass to check_func

    Returns:
        Tuple of (result, resolved_domain)
    """
    domains_to_try = [domain]

    if not domain.startswith("www."):
        domains_to_try.append(f"www.{domain}")

    last_result = None

    for current_domain in domains_to_try:
        try:
            new_args = (
                (current_domain, port) + args[2:]
                if len(args) > 2
                else (current_domain, port)
            )
            result = await check_func(*new_args, **kwargs)

            if hasattr(result, "connection_error") and result.connection_error:
                logger.warning(
                    f"Connection error for {current_domain}:{port}, will try next domain"
                )
                last_result = result
                continue

            logger.debug(f"Check succeeded for {current_domain}:{port}")
            return result, current_domain

        except Exception as e:
            logger.warning(f"Check failed for {current_domain}:{port}: {e}")
            last_result = e

    if isinstance(last_result, Exception):
        logger.error(f"All domain variations failed for {domain}:{port}: {last_result}")
        raise last_result
    logger.warning(f"All domain variations had connection errors for {domain}:{port}")
    return last_result, domain
