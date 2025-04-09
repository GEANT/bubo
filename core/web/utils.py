from typing import List, Dict, Any, Optional
from core.tls.models import TLSProtocolResult, CertificateResult
from core.web.models import HSTSInfo, SecurityHeadersInfo
from core.tls.models import SignatureAlgorithmSecurity
from core.logging.logger import setup_logger


logger = setup_logger(__name__)


def build_security_assessment(
    protocol_results: List[TLSProtocolResult],
    cert_result: CertificateResult,
    has_weak_ciphers: bool,
    hsts_info: Optional[HSTSInfo] = None,
    headers_info: Optional[SecurityHeadersInfo] = None,
) -> Dict[str, Any]:
    """Build security assessment based on checks with weighted scoring."""
    security_issues = []
    critical_issues = []
    major_issues = []
    minor_issues = []

    if hasattr(cert_result, "connection_error") and cert_result.connection_error:
        return {
            "issues": ["Cannot assess security due to connection issues"],
            "issues_count": 1,
            "rating": "unknown",
            "connectivity_error": True,
        }

    secure_protocols = [
        r.protocol_name for r in protocol_results if r.supported and r.secure
    ]
    insecure_protocols = [
        r.protocol_name for r in protocol_results if r.supported and not r.secure
    ]

    if not secure_protocols:
        issue = "No secure protocols supported"
        critical_issues.append(issue)
        security_issues.append(issue)
    elif insecure_protocols:
        issue = "Insecure protocols supported"
        critical_issues.append(issue)
        security_issues.append(issue)

    if has_weak_ciphers:
        issue = "Weak cipher suites supported"
        major_issues.append(issue)
        security_issues.append(issue)

    if cert_result.is_expired:
        issue = "Certificate expired"
        critical_issues.append(issue)
        security_issues.append(issue)
    elif (
        cert_result.days_until_expiry is not None and cert_result.days_until_expiry < 30
    ):
        issue = f"Certificate expiring soon ({cert_result.days_until_expiry} days)"
        major_issues.append(issue)
        security_issues.append(issue)

    if cert_result.is_self_signed:
        issue = "Self-signed certificate"
        critical_issues.append(issue)
        security_issues.append(issue)

    if not cert_result.chain_trusted and cert_result.chain_error:
        issue = "Untrusted certificate chain"
        critical_issues.append(issue)
        security_issues.append(issue)

    if cert_result.key_info and not cert_result.key_info.secure:
        issue = f"Weak key size ({cert_result.key_info.length} bits for {cert_result.key_info.type})"
        critical_issues.append(issue)
        security_issues.append(issue)

    if (
        cert_result.signature_algorithm
        and cert_result.signature_algorithm.security == SignatureAlgorithmSecurity.WEAK
    ):
        issue = f"Weak signature algorithm ({cert_result.signature_algorithm.name})"
        critical_issues.append(issue)
        security_issues.append(issue)

    if (
        cert_result.subject_alternative_names
        and not cert_result.subject_alternative_names.contains_domain
    ):
        issue = "Domain not found in Subject Alternative Names"
        major_issues.append(issue)
        security_issues.append(issue)

    if hsts_info:
        if not hsts_info.enabled:
            issue = "HSTS not enabled"
            major_issues.append(issue)
            security_issues.append(issue)
        else:
            if hsts_info.max_age < 15768000:  # 6 months in seconds
                issue = f"HSTS max-age too short ({hsts_info.max_age} seconds, should be at least 6 months)"
                minor_issues.append(issue)
                security_issues.append(issue)
            if not hsts_info.include_subdomains:
                issue = "HSTS missing includeSubDomains directive"
                minor_issues.append(issue)
                security_issues.append(issue)

    if headers_info:
        missing_headers = []
        if not headers_info.content_type_options:
            missing_headers.append("X-Content-Type-Options")
        if not headers_info.frame_options:
            missing_headers.append("X-Frame-Options")
        if not headers_info.content_security_policy:
            missing_headers.append("Content-Security-Policy")
        if not headers_info.referrer_policy:
            missing_headers.append("Referrer-Policy")

        if missing_headers:
            if len(missing_headers) >= 3:
                issue = (
                    f"Multiple security headers missing: {', '.join(missing_headers)}"
                )
                major_issues.append(issue)
            else:
                issue = f"Some security headers missing: {', '.join(missing_headers)}"
                minor_issues.append(issue)
            security_issues.append(issue)

    if not security_issues:
        rating = "excellent"
    elif not critical_issues:
        if not major_issues:
            rating = "good"
        elif len(major_issues) <= 2:
            rating = "fair"  # 1-2 major issues but fundamentals are solid
        else:
            rating = "moderate"  # Several major issues
    else:
        if len(critical_issues) >= 1 or len(major_issues) >= 2:
            rating = "poor"
        else:
            rating = "moderate"

    cert_protocol_critical = any(
        issue in critical_issues
        for issue in [
            "No secure protocols supported",
            "Certificate expired",
            "Self-signed certificate",
            "Untrusted certificate chain",
            "Weak key size",
        ]
    )

    if cert_protocol_critical:
        rating = "poor"

    return {
        "issues": security_issues,
        "issues_count": len(security_issues),
        "critical_issues_count": len(critical_issues),
        "major_issues_count": len(major_issues),
        "minor_issues_count": len(minor_issues),
        "rating": rating,
        "connectivity_error": False,
    }


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
    else:
        logger.error(f"All domain variations had connection errors for {domain}:{port}")
        return last_result, domain
