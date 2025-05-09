# core/tls/certificates.py

import asyncio
import datetime
import re
import socket
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from core.logging.logger import setup_logger
from core.tls.models import (
    CertificateResult,
    TLSCheckConfig,
)
from core.tls.utils import (
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


async def check_certificate_with_socket(
    domain: str, port: int, timeout: int, config: TLSCheckConfig
) -> CertificateResult:
    """Get certificate information using socket connection."""
    logger.debug(f"Checking certificate for {domain}:{port} using socket")

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
            return create_error_cert_result(
                f"Connection timeout to {domain}:{port}", is_connection_error=True
            )

        # Handshake with timeout
        handshake_task = asyncio.create_task(
            asyncio.to_thread(context.wrap_socket, sock, server_hostname=domain)
        )
        try:
            ssl_sock = await asyncio.wait_for(handshake_task, timeout=timeout)
        except asyncio.TimeoutError:
            return create_error_cert_result(
                "TLS handshake timeout", is_connection_error=True
            )

        # Get certificate
        cert = ssl_sock.getpeercert()
        if not cert:
            return create_error_cert_result("No certificate data received")

        # Get raw DER certificate for additional processing
        der_cert = ssl_sock.getpeercert(binary_form=True)
        parsed_cert = None
        if der_cert and (
            config.check_key_info
            or config.check_signature_algorithm
            or config.check_san
        ):
            try:
                parsed_cert = x509.load_der_x509_certificate(
                    der_cert, default_backend()
                )
            except Exception as e:
                logger.warning(f"Failed to parse certificate with cryptography: {e}")

        # Parse certificate info
        now = datetime.datetime.now()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        # Parse dates
        not_before = datetime.datetime.strptime(
            cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
        )
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

        is_expired = now > not_after
        days_until_expiry = (not_after - now).days

        # Check if self-signed
        subject_cn = subject.get("commonName", "")
        issuer_cn = issuer.get("commonName", "")

        is_self_signed = subject_cn == issuer_cn and subject.get(
            "organizationName", ""
        ) == issuer.get("organizationName", "")

        cert_result = CertificateResult(
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

        if parsed_cert:
            if config.check_key_info:
                key_info = extract_key_info(parsed_cert)
                cert_result.key_info = key_info

            if config.check_signature_algorithm:
                sig_algo_info = extract_signature_algorithm(parsed_cert)
                cert_result.signature_algorithm = sig_algo_info

            if config.check_san:
                san_info = extract_san_info(parsed_cert, domain)
                cert_result.subject_alternative_names = san_info

        return cert_result

    except ssl.SSLCertVerificationError as e:
        return create_error_cert_result(f"Certificate verification failed: {str(e)}")
    except (TimeoutError, OSError) as e:
        return create_error_cert_result(
            f"Connection error: {str(e)}", is_connection_error=True
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
            f"Error: {str(e)}", is_connection_error=is_conn_error
        )
    finally:
        try:
            if ssl_sock:
                ssl_sock.close()
            elif sock:
                sock.close()
        except Exception:
            pass


async def check_certificate_chain(
    domain: str, port: int, timeout: int
) -> tuple[bool, bool, int, list[dict[str, Any]], str | None]:
    """Check certificate chain trust and validity using OpenSSL, with detailed cert info."""
    logger.debug(f"Checking certificate chain for {domain}:{port}")

    is_trusted = False
    is_valid = False
    chain_length = 0
    chain_info = []
    error_message = None

    try:
        output, exit_code = await run_openssl_command(
            domain, port, ["-verify_return_error", "-showcerts"], timeout, retries=2
        )

        verify_result = re.search(r"Verify return code: (\d+) \(([^)]+)\)", output)
        if verify_result:
            verify_code = int(verify_result.group(1))
            verify_message = verify_result.group(2).strip()
            is_valid = verify_code == 0
            is_trusted = verify_code == 0
            if not is_valid:
                error_message = f"Certificate validation failed: {verify_message}"

        pem_certs = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            output,
            re.DOTALL,
        )

        if pem_certs:
            chain_length = len(pem_certs)

            for i, pem_cert in enumerate(pem_certs):
                try:
                    # Parse the certificate using cryptography
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
                        "position": i,  # Position in chain (0 = leaf, higher = towards root)
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
                        cert_data["serial_number"] = format_serial_number(
                            cert.serial_number
                        )
                    except Exception:
                        cert_data["serial_number"] = "Unknown"

                    try:
                        san_ext = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        )
                        if san_ext:
                            sans = []
                            for dns_name in san_ext.value.get_values_for_type(
                                x509.DNSName
                            ):
                                sans.append(f"DNS:{dns_name}")
                            for ip in san_ext.value.get_values_for_type(x509.IPAddress):
                                sans.append(f"IP:{ip}")
                            cert_data["subject_alternative_names"] = sans
                    except Exception as e:
                        logger.debug(
                            f"Error extracting SANs for cert in position {i}: {e}"
                        )

                    chain_info.append(cert_data)

                except Exception as e:
                    logger.warning(f"Error parsing certificate at position {i}: {e}")
                    # Add minimal info if parsing fails
                    chain_info.append(
                        {
                            "position": i,
                            "parsing_error": str(e),
                            "raw_pem": pem_cert[:100] + "..."
                            if len(pem_cert) > 100
                            else pem_cert,
                        }
                    )

        if chain_length == 0:
            depth_matches = re.findall(r"depth=(\d+)", output)
            if depth_matches:
                unique_depths = {int(d) for d in depth_matches}
                chain_length = len(unique_depths)

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

            elif "verify return:" in output:
                depth_lines = re.findall(r"depth=(\d+).*?verify return:(\d+)", output)
                if depth_lines:
                    unique_depths = {int(d[0]) for d in depth_lines}
                    chain_length = len(unique_depths)

        if (
            chain_length == 1
            and chain_info
            and chain_info[0].get("is_self_signed", False)
        ):
            is_trusted = False
            is_valid = False
            if not error_message:
                error_message = "Self-signed certificate"

        return is_trusted, is_valid, chain_length, chain_info, error_message

    except Exception as e:
        return False, False, 0, [], f"Error checking certificate chain: {str(e)}"


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
