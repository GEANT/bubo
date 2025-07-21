# core/tls/certificates.py

import asyncio
import datetime
import re
import socket
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from bubo.core.logging.logger import setup_logger
from bubo.core.tls.models import (
    CertificateResult,
    TLSCheckConfig,
)
from bubo.core.tls.utils import (
    create_error_cert_result,
    extract_key_info,
    extract_san_info,
    extract_signature_algorithm,
    format_serial_number,
    format_x509_name,
    has_openssl,
    run_openssl_command,
)

logger = setup_logger(__name__)


async def _establish_ssl_connection(
    domain: str, port: int, timeout: int
) -> tuple[ssl.SSLSocket, None] | tuple[None, CertificateResult]:
    """Establish SSL connection with timeout handling.

    Returns:
        Tuple of (ssl_socket, None) on success or (None, error_result) on failure
    """
    sock = None
    ssl_sock = None

    try:
        # Create context and socket
        context = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Connect with timeout
        connect_task = asyncio.create_task(
            asyncio.to_thread(sock.connect, (domain, port))
        )
        try:
            await asyncio.wait_for(connect_task, timeout=timeout)
        except asyncio.TimeoutError:
            return None, create_error_cert_result(
                f"Connection timeout to {domain}:{port}", is_connection_error=True
            )

        # Handshake with timeout
        handshake_task = asyncio.create_task(
            asyncio.to_thread(context.wrap_socket, sock, server_hostname=domain)
        )
        try:
            ssl_sock = await asyncio.wait_for(handshake_task, timeout=timeout)
        except asyncio.TimeoutError:
            return None, create_error_cert_result(
                "TLS handshake timeout", is_connection_error=True
            )

        return ssl_sock, None

    except Exception as e:
        try:
            if ssl_sock:
                ssl_sock.close()
            elif sock:
                sock.close()
        except Exception:
            pass
        raise e


def _parse_certificate_dates(cert: dict) -> tuple[datetime.datetime, datetime.datetime]:
    """Parse certificate validity dates."""
    not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    return not_before, not_after


def _extract_certificate_info(cert: dict) -> tuple[dict, dict]:
    """Extract subject and issuer information from certificate."""
    subject = {x[0][0]: x[0][1] for x in cert.get("subject", [])}
    issuer = {x[0][0]: x[0][1] for x in cert.get("issuer", [])}
    return subject, issuer


def _is_self_signed_certificate(subject: dict, issuer: dict) -> bool:
    """Check if certificate is self-signed."""
    subject_cn = subject.get("commonName", "")
    issuer_cn = issuer.get("commonName", "")

    return subject_cn == issuer_cn and subject.get(
        "organizationName", ""
    ) == issuer.get("organizationName", "")


def _create_base_certificate_result(
    subject: dict,
    issuer: dict,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    is_self_signed: bool,
) -> CertificateResult:
    """Create base certificate result with common fields."""
    now = datetime.datetime.now()
    is_expired = now > not_after
    days_until_expiry = (not_after - now).days

    return CertificateResult(
        subject=subject.get("commonName", "Unknown"),
        issuer=issuer.get("commonName", "Unknown"),
        valid_from=not_before.isoformat(),
        valid_until=not_after.isoformat(),
        is_valid=True,
        is_expired=is_expired,
        days_until_expiry=days_until_expiry,
        is_self_signed=is_self_signed,
        validation_error=None,
    )


def _enhance_certificate_with_parsed_info(
    cert_result: CertificateResult,
    parsed_cert: x509.Certificate,
    config: TLSCheckConfig,
    domain: str,
) -> None:
    """Enhance certificate result with additional parsed certificate info."""
    if config.check_key_info:
        key_info = extract_key_info(parsed_cert)
        cert_result.key_info = key_info

    if config.check_signature_algorithm:
        sig_algo_info = extract_signature_algorithm(parsed_cert)
        cert_result.signature_algorithm = sig_algo_info

    if config.check_san:
        san_info = extract_san_info(parsed_cert, domain)
        cert_result.subject_alternative_names = san_info


def _get_certificate_from_socket(
    ssl_sock: ssl.SSLSocket, config: TLSCheckConfig
) -> tuple[dict, x509.Certificate | None]:
    """Extract certificate and parsed certificate from SSL socket."""
    cert = ssl_sock.getpeercert()
    if not cert:
        raise ValueError("No certificate data received")

    parsed_cert = None
    if config.check_key_info or config.check_signature_algorithm or config.check_san:
        der_cert = ssl_sock.getpeercert(binary_form=True)
        if der_cert:
            try:
                parsed_cert = x509.load_der_x509_certificate(
                    der_cert, default_backend()
                )
            except Exception as e:
                logger.warning(f"Failed to parse certificate with cryptography: {e}")

    return cert, parsed_cert


async def check_certificate_with_socket(
    domain: str, port: int, timeout: int, config: TLSCheckConfig
) -> CertificateResult:
    """Get certificate information using socket connection."""
    logger.debug(f"Checking certificate for {domain}:{port} using socket")

    ssl_sock = None
    try:
        ssl_sock, error_result = await _establish_ssl_connection(domain, port, timeout)
        if error_result:
            return error_result

        cert, parsed_cert = _get_certificate_from_socket(ssl_sock, config)

        subject, issuer = _extract_certificate_info(cert)
        not_before, not_after = _parse_certificate_dates(cert)
        is_self_signed = _is_self_signed_certificate(subject, issuer)

        cert_result = _create_base_certificate_result(
            subject, issuer, not_before, not_after, is_self_signed
        )

        if parsed_cert:
            _enhance_certificate_with_parsed_info(
                cert_result, parsed_cert, config, domain
            )

        return cert_result

    except ssl.SSLCertVerificationError as e:
        return create_error_cert_result(f"Certificate verification failed: {e}")
    except (TimeoutError, OSError) as e:
        return create_error_cert_result(
            f"Connection error: {e}", is_connection_error=True
        )
    except Exception as e:
        error_msg = str(e).lower()
        connection_errors = [
            "timeout",
            "connection refused",
            "unreachable",
            "network",
            "host",
            "route",
            "connect",
        ]
        is_conn_error = any(term in error_msg for term in connection_errors)

        return create_error_cert_result(
            f"Error: {e}", is_connection_error=is_conn_error
        )
    finally:
        try:
            if ssl_sock is not None:
                ssl_sock.close()
        except Exception:
            pass


class ChainValidationResult:
    """Container for chain validation results."""

    def __init__(self):
        self.is_trusted: bool = False
        self.is_valid: bool = False
        self.chain_length: int = 0
        self.chain_info: list[dict[str, Any]] = []
        self.error_message: str | None = None


def _parse_openssl_verify_result(output: str) -> tuple[bool, bool, str | None]:
    """Parse OpenSSL verify result from command output."""
    verify_result = re.search(r"Verify return code: (\d+) \(([^)]+)\)", output)
    if not verify_result:
        return False, False, "No verify result found"

    verify_code = int(verify_result.group(1))
    verify_message = verify_result.group(2).strip()

    is_valid = verify_code == 0
    is_trusted = verify_code == 0

    error_message = None
    if not is_valid:
        error_message = f"Certificate validation failed: {verify_message}"

    return is_trusted, is_valid, error_message


def _extract_san_from_cert(cert: x509.Certificate) -> list[str]:
    """Extract Subject Alternative Names from certificate."""
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        if not san_ext:
            return []

        sans = []
        for dns_name in san_ext.value.get_values_for_type(x509.DNSName):
            sans.append(f"DNS:{dns_name}")
        for ip in san_ext.value.get_values_for_type(x509.IPAddress):
            sans.append(f"IP:{ip}")
        return sans
    except Exception:
        return []


def _parse_single_pem_certificate(pem_cert: str, position: int) -> dict[str, Any]:
    """Parse a single PEM certificate and return certificate info."""
    try:
        cert_bytes = pem_cert.encode()
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        subject = format_x509_name(cert.subject)
        issuer = format_x509_name(cert.issuer)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        key_info = extract_key_info(cert)
        sig_algo_info = extract_signature_algorithm(cert)
        is_self_signed = subject == issuer

        cert_data = {
            "position": position,
            "subject": subject,
            "issuer": issuer,
            "valid_from": not_before.isoformat(),
            "valid_until": not_after.isoformat(),
            "is_self_signed": is_self_signed,
            "key_type": key_info.type,
            "key_length": key_info.length,
            "key_secure": key_info.secure,
            "signature_algorithm": sig_algo_info.name,
            "signature_security": sig_algo_info.security.value,
        }

        try:
            cert_data["serial_number"] = format_serial_number(cert.serial_number)
        except Exception:
            cert_data["serial_number"] = "Unknown"

        sans = _extract_san_from_cert(cert)
        if sans:
            cert_data["subject_alternative_names"] = sans

        return cert_data

    except Exception as e:
        logger.warning(f"Error parsing certificate at position {position}: {e}")
        return {
            "position": position,
            "parsing_error": str(e),
            "raw_pem": pem_cert[:100] + "..." if len(pem_cert) > 100 else pem_cert,
        }


def _parse_pem_certificates(output: str) -> tuple[int, list[dict[str, Any]]]:
    """Parse PEM certificates from OpenSSL output."""
    pem_certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        output,
        re.DOTALL,
    )

    if not pem_certs:
        return 0, []

    chain_length = len(pem_certs)
    chain_info = []

    for i, pem_cert in enumerate(pem_certs):
        cert_data = _parse_single_pem_certificate(pem_cert, i)
        chain_info.append(cert_data)

    return chain_length, chain_info


def _parse_chain_fallback(output: str) -> tuple[int, list[dict[str, Any]]]:
    """Fallback parsing when PEM certificates are not found."""
    # Try to extract chain length from depth information
    depth_matches = re.findall(r"depth=(\d+)", output)
    if depth_matches:
        unique_depths = {int(d) for d in depth_matches}
        chain_length = len(unique_depths)
        chain_info = []

        # Generate basic chain info
        for depth in sorted(unique_depths):
            depth_line = re.search(f"depth={depth} (.*?)(?=\n|$)", output)
            if depth_line:
                chain_info.append(
                    {
                        "position": str(depth),
                        "subject": depth_line.group(1).strip(),
                    }
                )

        return chain_length, chain_info

    # Try alternative parsing method
    if "verify return:" in output:
        depth_lines = re.findall(r"depth=(\d+).*?verify return:(\d+)", output)
        if depth_lines:
            unique_depths = {int(d[0]) for d in depth_lines}
            return len(unique_depths), []

    return 0, []


def _handle_self_signed_chain(result: ChainValidationResult) -> None:
    """Handle special case of self-signed certificates."""
    if (
        result.chain_length == 1
        and result.chain_info
        and result.chain_info[0].get("is_self_signed", False)
    ):
        result.is_trusted = False
        result.is_valid = False
        if not result.error_message:
            result.error_message = "Self-signed certificate"


async def check_certificate_chain(
    domain: str, port: int, timeout: int
) -> tuple[bool, bool, int, list[dict[str, Any]], str | None]:
    """Check certificate chain trust and validity using OpenSSL, with detailed cert info."""
    logger.debug(f"Checking certificate chain for {domain}:{port}")

    result = ChainValidationResult()

    try:
        output, exit_code = await run_openssl_command(
            domain, port, ["-verify_return_error", "-showcerts"], timeout, retries=2
        )

        result.is_trusted, result.is_valid, result.error_message = (
            _parse_openssl_verify_result(output)
        )

        result.chain_length, result.chain_info = _parse_pem_certificates(output)

        # If no PEM certificates found, try fallback parsing
        if result.chain_length == 0:
            result.chain_length, result.chain_info = _parse_chain_fallback(output)

        _handle_self_signed_chain(result)

        return (
            result.is_trusted,
            result.is_valid,
            result.chain_length,
            result.chain_info,
            result.error_message,
        )

    except Exception as e:
        return False, False, 0, [], f"Error checking certificate chain: {e}"


async def check_certificate(
    domain: str, port: int, config: TLSCheckConfig
) -> CertificateResult:
    """Check certificate validity and chain trust."""
    logger.debug(f"Checking certificate for {domain}:{port}")

    if not config.check_certificate:
        return create_error_cert_result("Certificate checking disabled")

    cert_result = await check_certificate_with_socket(
        domain, port, config.timeout_connect, config
    )

    if (
        cert_result.is_valid
        and has_openssl()
        and config.use_openssl
        and config.verify_chain
    ):
        (
            chain_trusted,
            chain_valid,
            chain_length,
            chain_info,
            chain_error,
        ) = await check_certificate_chain(domain, port, config.timeout_command)

        cert_result.chain_trusted = chain_trusted
        cert_result.chain_valid = chain_valid
        cert_result.chain_length = chain_length
        cert_result.chain_info = chain_info
        cert_result.chain_error = chain_error

    return cert_result
