# core/tls/protocols.py
import asyncio
import re
import socket
import ssl
from typing import List, Optional, Tuple, Union
from core.logging.logger import setup_logger
from core.tls.models import (
    TLSProtocol,
    TLSProtocolResult,
    TLSCheckConfig,
    PROTOCOL_SECURITY,
)
from core.tls.utils import has_openssl, run_openssl_command


logger = setup_logger(__name__)


async def check_protocol_with_socket(
    domain: str, port: int, protocol: TLSProtocol, timeout: int
) -> Tuple[bool, Optional[str]]:
    """Check if a server supports a TLS protocol using direct socket connections."""
    logger.debug(f"Checking {protocol.value} for {domain}:{port} using socket")

    protocol_to_ssl_version = {
        TLSProtocol.TLSv1_0: (ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1),
        TLSProtocol.TLSv1_1: (ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1_1),
        TLSProtocol.TLSv1_2: (ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1_2),
        TLSProtocol.TLSv1_3: (ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1_3),
    }

    sock = None
    ssl_sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            connect_task = asyncio.create_task(
                asyncio.to_thread(sock.connect, (domain, port))
            )
            await asyncio.wait_for(connect_task, timeout=timeout)
        except asyncio.TimeoutError:
            return False, f"Connection timeout to {domain}:{port}"
        except socket.error as e:
            return False, f"Connection error: {str(e)}"

        protocol_version, min_version = protocol_to_ssl_version[protocol]
        context = ssl.SSLContext(protocol_version)
        context.minimum_version = min_version
        context.maximum_version = min_version
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if protocol in [TLSProtocol.TLSv1_0, TLSProtocol.TLSv1_1]:
            context.set_ciphers("ALL:@SECLEVEL=0")

        try:
            handshake_task = asyncio.create_task(
                asyncio.to_thread(context.wrap_socket, sock, server_hostname=domain)
            )
            ssl_sock = await asyncio.wait_for(handshake_task, timeout=timeout)
        except asyncio.TimeoutError:
            return False, f"TLS handshake timeout for {protocol.value}"

        version_used = ssl_sock.version()
        logger.debug(f"Connection successful with {version_used} for {domain}:{port}")
        if protocol.value in version_used or f"TLSv{min_version.value}" in version_used:
            logger.debug(f"{protocol.value} supported by {domain}:{port}")
            return True, None
        else:
            return (
                False,
                f"Protocol mismatch: requested {protocol.value}, got {version_used}",
            )

    except ssl.SSLError as e:
        error_msg = str(e)
        logger.debug(f"SSL error for {protocol.value} on {domain}:{port}: {error_msg}")
        # Identify protocol not supported errors
        not_supported_indicators = [
            "wrong version",
            "no protocols available",
            "wrong ssl version",
            "unsupported protocol",
            "tlsv1 alert protocol version",
        ]
        if any(msg in error_msg.lower() for msg in not_supported_indicators):
            return False, "Protocol not supported by server"

        if "application data after close notify" in error_msg.lower():
            return True, None

        return False, f"SSL error: {error_msg}"

    except (socket.timeout, socket.error) as e:
        return False, f"Connection error: {str(e)}"

    except Exception as e:
        logger.error(
            f"Unexpected error checking {protocol.value} for {domain}:{port}: {str(e)}"
        )
        return False, f"Error: {str(e)}"

    finally:
        try:
            if ssl_sock:
                ssl_sock.close()
            elif sock:
                sock.close()
        except Exception:
            logger.error("Failed to close socket")


async def check_protocol_with_openssl(
    domain: str, port: int, protocol: TLSProtocol, timeout: int
) -> Tuple[bool, Optional[str]]:
    """Check if a server supports a TLS protocol using OpenSSL."""
    logger.debug(f"Checking {protocol.value} for {domain}:{port} using OpenSSL")

    if not has_openssl():
        return False, "OpenSSL not found in PATH"

    protocol_options = {
        TLSProtocol.TLSv1_0: "-tls1",  # Not -tls1_0
        TLSProtocol.TLSv1_1: "-tls1_1",
        TLSProtocol.TLSv1_2: "-tls1_2",
        TLSProtocol.TLSv1_3: "-tls1_3",
    }

    protocol_option = protocol_options.get(protocol)
    args = [protocol_option]

    # Add SECLEVEL=0 for older protocols to allow testing them
    if protocol in [TLSProtocol.TLSv1_0, TLSProtocol.TLSv1_1]:
        args.append("-cipher")
        args.append("DEFAULT:@SECLEVEL=0")

    logger.debug(f"Using OpenSSL args for {protocol.value}: {args}")
    output, exit_code = await run_openssl_command(domain, port, args, timeout)

    logger.debug(
        f"OpenSSL output for {protocol.value}:\n{output[:500]}"
    )

    critical_failures = [
        "sslv3 alert handshake failure",
        "unsupported protocol",
        "Connection reset by peer",
        "write:errno=104",
        "alert handshake failure",
        "error:0A000",
        "Cipher is (NONE)",
        "Cipher    : 0000",
    ]

    for failure in critical_failures:
        if failure in output:
            logger.debug(f"Critical failure detected for {protocol.value}: {failure}")
            return False, "Protocol not supported by server"

    # Success requires BOTH a protocol match AND a valid cipher
    protocol_match = re.search(r"Protocol\s+:\s+(TLSv[\d\.]+)", output)
    cipher_match = re.search(r"Cipher\s+:\s+([A-Z0-9-]+)", output)

    if protocol_match and cipher_match:
        detected_protocol = protocol_match.group(1)
        cipher = cipher_match.group(1)

        if cipher and cipher != "0000" and cipher != "(NONE)":
            logger.debug(f"Success: {detected_protocol} with cipher {cipher}")
            return True, None

    # Another success case: explicit confirmation of cipher
    new_cipher_match = re.search(
        r"New,\s+(TLSv[\d\.]+),\s+Cipher\s+is\s+([A-Z0-9-]+)", output
    )
    if new_cipher_match and new_cipher_match.group(2) != "(NONE)":
        logger.debug(
            f"Success: {new_cipher_match.group(1)} with cipher {new_cipher_match.group(2)}"
        )
        return True, None

    # If we got here, the protocol is not supported
    logger.debug(
        f"Protocol {protocol.value} not supported (no valid cipher negotiated)"
    )
    return False, "Protocol not supported by server"


async def check_protocol(
    domain: str, port: int, protocol: TLSProtocol, config: TLSCheckConfig
) -> TLSProtocolResult:
    """Check protocol support with improved fallback between methods."""
    openssl_available = has_openssl() and config.use_openssl
    logger.debug(f"Checking protocol {protocol.value} for {domain}:{port}")

    is_supported, error = await check_protocol_with_socket(
        domain, port, protocol, config.timeout_connect
    )
    logger.debug(
        f"Socket check for {protocol.value}: supported={is_supported}, error={error}"
    )

    if openssl_available and not is_supported:
        logger.debug(
            f"Socket connection not supported. Trying OpenSSL for {protocol.value}"
        )
        openssl_supported, openssl_error = await check_protocol_with_openssl(
            domain, port, protocol, config.timeout_command
        )

        if openssl_supported:
            logger.debug(
                f"OpenSSL detected {protocol.value} support where socket failed"
            )
            is_supported = True
            error = None
        elif not is_supported:
            logger.debug(
                f"Both socket and OpenSSL report protocol unsupported. OpenSSL error: {openssl_error}"
            )

    final_error = None
    if not is_supported:
        if protocol in [TLSProtocol.TLSv1_0, TLSProtocol.TLSv1_1]:
            final_error = None
        elif protocol == TLSProtocol.TLSv1_2:
            final_error = "Security issue: TLSv1.2 not supported. This is a secure protocol required by modern security standards."
        elif protocol == TLSProtocol.TLSv1_3:
            final_error = "Security issue: TLSv1.3 not supported. This protocol provides enhanced security and should be enabled."

    logger.debug(
        f"Protocol check result for {protocol.value}: supported={is_supported}, error={final_error}"
    )

    return TLSProtocolResult(
        protocol_name=protocol.value,
        supported=is_supported,
        secure=PROTOCOL_SECURITY[protocol],
        error=final_error,
    )


def process_protocol_results(
    results: List[Union[TLSProtocolResult, Exception]], protocols: List[TLSProtocol]
) -> Tuple[List[TLSProtocolResult], List[TLSProtocol]]:
    """Process protocol check results and identify supported protocols."""
    processed_results = []
    supported_protocols = []

    for i, result in enumerate(results):
        protocol = protocols[i]

        if isinstance(result, Exception):
            logger.error(f"Error checking {protocol.value}: {str(result)}")
            processed_results.append(
                TLSProtocolResult(
                    protocol_name=protocol.value,
                    supported=False,
                    secure=PROTOCOL_SECURITY[protocol],
                    error=f"Error: {str(result)}",
                )
            )
        else:
            processed_results.append(result)
            if result.supported:
                supported_protocols.append(protocol)

    return processed_results, supported_protocols
