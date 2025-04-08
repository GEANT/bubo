from typing import List, Dict, Any, Optional
from core.tls.models import TLSProtocolResult, CertificateResult
from core.web.models import HSTSInfo, SecurityHeadersInfo
from core.tls.models import SignatureAlgorithmSecurity


def build_security_assessment(
    protocol_results: List[TLSProtocolResult],
    cert_result: CertificateResult,
    has_weak_ciphers: bool,
    hsts_info: Optional[HSTSInfo] = None,
    headers_info: Optional[SecurityHeadersInfo] = None,
) -> Dict[str, Any]:
    """Build security assessment based on checks."""
    security_issues = []

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

    if insecure_protocols:
        security_issues.append("Insecure protocols supported")

    if not secure_protocols:
        security_issues.append("No secure protocols supported")

    if has_weak_ciphers:
        security_issues.append("Weak cipher suites supported")

    if cert_result.is_expired:
        security_issues.append("Certificate expired")
    elif (
        cert_result.days_until_expiry is not None and cert_result.days_until_expiry < 30
    ):
        security_issues.append(
            f"Certificate expiring soon ({cert_result.days_until_expiry} days)"
        )

    if cert_result.is_self_signed:
        security_issues.append("Self-signed certificate")

    if not cert_result.chain_trusted and cert_result.chain_error:
        security_issues.append("Untrusted certificate chain")

    if cert_result.key_info and not cert_result.key_info.secure:
        security_issues.append(
            f"Weak key size ({cert_result.key_info.length} bits for {cert_result.key_info.type})"
        )

    if (
        cert_result.signature_algorithm
        and cert_result.signature_algorithm.security == SignatureAlgorithmSecurity.WEAK
    ):
        security_issues.append(
            f"Weak signature algorithm ({cert_result.signature_algorithm.name})"
        )

    if (
        cert_result.subject_alternative_names
        and not cert_result.subject_alternative_names.contains_domain
    ):
        security_issues.append("Domain not found in Subject Alternative Names")

    if hsts_info:
        if not hsts_info.enabled:
            security_issues.append("HSTS not enabled")
        elif hsts_info.max_age < 15768000:  # 6 months in seconds
            security_issues.append(
                f"HSTS max-age too short ({hsts_info.max_age} seconds, should be at least 6 months)"
            )
        elif not hsts_info.include_subdomains:
            security_issues.append("HSTS missing includeSubDomains directive")

    if headers_info:
        if not headers_info.content_type_options:
            security_issues.append("Missing X-Content-Type-Options header")
        if not headers_info.frame_options:
            security_issues.append("Missing X-Frame-Options header")
        if not headers_info.content_security_policy:
            security_issues.append("Missing Content-Security-Policy header")
        if not headers_info.referrer_policy:
            security_issues.append("Missing Referrer-Policy header")

    if not security_issues:
        rating = "excellent"
    elif len(security_issues) <= 1:
        rating = "good"
    elif len(security_issues) <= 3:
        rating = "fair"
    else:
        rating = "poor"

    return {
        "issues": security_issues,
        "issues_count": len(security_issues),
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
