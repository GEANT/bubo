"""
Standards implementation for TLS security checks.

This module provides the main entry point for checking TLS security
of a given domain and port, consolidating results from various checks.
"""

import asyncio
from typing import Any

from core.logging.logger import setup_logger
from core.tls.models import (
    TLSProtocol,
    TLSCheckConfig,
    TLSProtocolResult,
    CertificateResult,
)
from datetime import datetime
from core.tls.protocols import check_protocol, process_protocol_results
from core.tls.certificates import check_certificate
from core.tls.ciphers import check_cipher, process_cipher_results
from core.web.utils import build_security_assessment, resolve_domain
from core.web.http_security import run_http_security_checks, build_http_security_dicts

logger = setup_logger(__name__)


async def run_protocol_checks(
    domain: str, port: int, config: TLSCheckConfig
) -> tuple[list[TLSProtocolResult], list[TLSProtocol]]:
    """Run TLS protocol checks and process the results."""
    tls_protocols = list(TLSProtocol)

    protocol_tasks = [
        asyncio.create_task(check_protocol(domain, port, protocol, config))
        for protocol in tls_protocols
    ]

    protocol_results = await asyncio.gather(*protocol_tasks, return_exceptions=True)
    return process_protocol_results(protocol_results, tls_protocols)


async def run_cipher_checks(
    domain: str,
    port: int,
    supported_protocols: list[TLSProtocol],
    config: TLSCheckConfig,
) -> tuple[dict[str, list[dict]], dict[str, list[str]]]:
    """Run cipher checks for supported protocols and process results."""
    cipher_tasks = [
        asyncio.create_task(check_cipher(domain, port, protocol, config))
        for protocol in supported_protocols
    ]

    cipher_results = await asyncio.gather(*cipher_tasks, return_exceptions=True)
    return process_cipher_results(cipher_results, supported_protocols)


def build_certificate_dict(cert_result: CertificateResult) -> dict[str, Any]:
    """Build a dictionary representation of certificate results."""
    cert_dict = {
        "subject": cert_result.subject,
        "issuer": cert_result.issuer,
        "valid_from": cert_result.valid_from,
        "valid_until": cert_result.valid_until,
        "is_valid": cert_result.is_valid,
        "is_expired": cert_result.is_expired,
        "days_until_expiry": cert_result.days_until_expiry,
        "is_self_signed": cert_result.is_self_signed,
        "validation_error": cert_result.validation_error,
        "chain_trusted": cert_result.chain_trusted,
        "chain_valid": cert_result.chain_valid,
        "chain_length": cert_result.chain_length,
        "chain_error": cert_result.chain_error,
        "connection_error": cert_result.connection_error,
    }

    # Add additional certificate information if available
    if cert_result.key_info:
        cert_dict["key_info"] = {
            "type": cert_result.key_info.type,
            "length": cert_result.key_info.length,
            "secure": cert_result.key_info.secure,
        }

    if cert_result.signature_algorithm:
        cert_dict["signature_algorithm"] = {
            "name": cert_result.signature_algorithm.name,
            "security": cert_result.signature_algorithm.security.value,
        }

    if cert_result.subject_alternative_names:
        cert_dict["subject_alternative_names"] = {
            "names": cert_result.subject_alternative_names.names,
            "contains_domain": cert_result.subject_alternative_names.contains_domain,
        }

    if cert_result.chain_info:
        cert_dict["chain_info"] = cert_result.chain_info

    return cert_dict


def extract_protocol_status(
    results: list[TLSProtocolResult],
) -> tuple[list[str], list[str]]:
    """Extract lists of secure and insecure protocols from results."""
    secure_protocols = [r.protocol_name for r in results if r.supported and r.secure]
    insecure_protocols = [
        r.protocol_name for r in results if r.supported and not r.secure
    ]

    return secure_protocols, insecure_protocols


def build_protocol_dict(
    processed_results: list[TLSProtocolResult],
    secure_protocols: list[str],
    insecure_protocols: list[str],
) -> dict[str, Any]:
    """Build a dictionary of protocol support information."""
    return {
        "protocols": [
            {
                "name": r.protocol_name,
                "supported": r.supported,
                "secure": r.secure,
                "error": r.error,
            }
            for r in processed_results
        ],
        "has_insecure_protocols": bool(insecure_protocols),
        "has_secure_protocols": bool(secure_protocols),
        "insecure_protocols": insecure_protocols,
        "secure_protocols": secure_protocols,
    }


def build_cipher_dict(
    ciphers_by_protocol: dict[str, list[dict]], cipher_strength: dict[str, list[str]]
) -> dict[str, Any]:
    """Build a dictionary of cipher information."""
    return {
        "by_protocol": ciphers_by_protocol,
        "by_strength": {
            strength: ciphers for strength, ciphers in cipher_strength.items()
        },
        "has_weak_ciphers": bool(cipher_strength.get("weak")),
        "has_strong_ciphers": bool(cipher_strength.get("strong")),
    }


async def run(
    domain: str, port: int = 443, config: TLSCheckConfig | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Run comprehensive TLS security checks on the specified domain and port.
    Will try with www. prefix if the original domain fails to connect.
    """
    if config is None:
        config = TLSCheckConfig()

    logger.info(f"Processing Web security checks for {domain}")

    results = {}
    state = {domain: {}}

    try:
        cert_result, resolved_domain = await resolve_domain(
            domain, port, check_certificate, domain, port, config
        )

        if hasattr(cert_result, "connection_error") and cert_result.connection_error:
            logger.error(
                f"Certificate check failed for all domain variations of {domain}:{port}"
            )
            processed_results = []
            supported_protocols = []
            ciphers_by_protocol = {}
            cipher_strength = {}
            hsts_info = None
            headers_info = None
        else:
            try:
                processed_results, supported_protocols = await run_protocol_checks(
                    resolved_domain, port, config
                )

                try:
                    hsts_info, headers_info = await run_http_security_checks(
                        resolved_domain, port, config
                    )
                except Exception as http_error:
                    logger.error(f"HTTP security checks failed: {http_error}")
                    hsts_info = None
                    headers_info = None

                try:
                    ciphers_by_protocol, cipher_strength = await run_cipher_checks(
                        resolved_domain, port, supported_protocols, config
                    )
                except Exception as cipher_error:
                    logger.error(f"Cipher checks failed: {cipher_error}")
                    ciphers_by_protocol = {}
                    cipher_strength = {}

            except Exception as e:
                logger.error(f"Protocol checks failed: {e}")
                processed_results = []
                supported_protocols = []
                ciphers_by_protocol = {}
                cipher_strength = {}
                hsts_info = None
                headers_info = None

        cert_dict = build_certificate_dict(cert_result)

        if processed_results:
            secure_protocols, insecure_protocols = extract_protocol_status(
                processed_results
            )
            protocol_dict = build_protocol_dict(
                processed_results, secure_protocols, insecure_protocols
            )
        else:
            protocol_dict = {
                "protocols": [],
                "has_insecure_protocols": False,
                "has_secure_protocols": False,
                "insecure_protocols": [],
                "secure_protocols": [],
            }

        if hasattr(cert_result, "connection_error") and cert_result.connection_error:
            cipher_dict = {
                "by_protocol": {},
                "by_strength": {},
                "has_weak_ciphers": False,
                "has_strong_ciphers": False,
                "connection_error": True,
            }
        else:
            cipher_dict = build_cipher_dict(ciphers_by_protocol, cipher_strength)

        if hsts_info is not None and headers_info is not None:
            hsts_dict, headers_dict = build_http_security_dicts(hsts_info, headers_info)
        else:
            hsts_dict, headers_dict = None, None

        security_assessment = build_security_assessment(
            processed_results if processed_results else [],
            cert_result,
            bool(cipher_strength.get("weak")) if cipher_strength else False,
            hsts_info,
            headers_info,
        )

        domain_results = {
            "protocol_support": protocol_dict,
            "certificate": cert_dict,
            "ciphers": cipher_dict,
            "security_assessment": security_assessment,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        if resolved_domain != domain:
            domain_results["resolved_domain"] = resolved_domain

        if hasattr(cert_result, "connection_error") and cert_result.connection_error:
            domain_results["connectivity_error"] = True
            domain_results["error_message"] = cert_result.validation_error

        if hsts_dict:
            domain_results["hsts"] = hsts_dict

        if headers_dict:
            domain_results["security_headers"] = headers_dict

        results[domain] = domain_results

        state[domain] = {
            "tls_secure": (
                not getattr(cert_result, "connection_error", False)
                and cert_result.is_valid
                and not cert_result.is_expired
                and protocol_dict.get("has_secure_protocols", False)
                and not protocol_dict.get("has_insecure_protocols", False)
                and (
                    not hasattr(cert_result, "chain_trusted")
                    or cert_result.chain_trusted
                )
                and not bool(cipher_strength.get("weak", False))
                and not cert_result.is_self_signed
            ),
            "rating": security_assessment["rating"],
            "cert_valid": not getattr(cert_result, "connection_error", False)
            and cert_result.is_valid
            and not cert_result.is_expired,
            "issues_count": security_assessment["issues_count"],
            "uses_secure_protocols": protocol_dict.get("has_secure_protocols", False),
        }

        if resolved_domain != domain:
            state[domain]["resolved_domain"] = resolved_domain

        if hasattr(cert_result, "connection_error") and cert_result.connection_error:
            state[domain]["connectivity_error"] = True
            state[domain]["connectivity_error_message"] = cert_result.validation_error

        logger.debug(f"Completed TLS checks for {domain}:{port}")
        return results, state

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error in TLS check: {error_msg}", exc_info=True)

        results[domain] = {
            "error": f"Error checking TLS: {error_msg}",
            "protocol_support": {
                "protocols": [],
                "has_insecure_protocols": False,
                "has_secure_protocols": False,
            },
            "certificate": {"is_valid": False, "validation_error": error_msg},
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "security_assessment": {
                "rating": "error",
                "issues": ["Error during TLS check"],
                "issues_count": 1,
                "connectivity_error": True,
            },
        }

        state[domain] = {
            "tls_secure": False,
            "rating": "error",
            "cert_valid": False,
            "error": error_msg,
            "connectivity_error": True,
            "connectivity_error_message": error_msg,
            "issues_count": 1,
            "uses_secure_protocols": False,
        }

        return results, state
