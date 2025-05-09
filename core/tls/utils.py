"""
# core/tls/utils.py
This module provides utility functions for TLS certificate and protocols checks.
"""

import asyncio
import functools
import re
import shutil
from collections.abc import Awaitable, Callable
from random import random
from typing import Any, TypeVar

from cryptography import x509

from core.logging.logger import setup_logger
from core.tls.models import (
    KEY_LENGTH_RECOMMENDATIONS,
    SIGNATURE_ALGORITHMS,
    CertificateResult,
    CipherStrength,
    KeyInfo,
    SANInfo,
    SignatureAlgorithmInfo,
    SignatureAlgorithmSecurity,
)

logger = setup_logger(__name__)

T = TypeVar("T")
_openssl_timeout_occurred = []


async def with_retries(
    func: Callable[..., Awaitable[T]],
    *args: Any,
    retries: int = 3,
    backoff_factor: float = 1.5,
    retry_exceptions: tuple = (Exception,),
    fatal_exceptions: tuple = (),
    operation_name: str | None = None,
    **kwargs: Any,
) -> T:
    """
    Execute an async function with retries and exponential backoff.

    Args:
        func: The async function to call
        *args: Positional arguments to pass to the function
        retries: Maximum number of retries (default: 3)
        backoff_factor: Backoff multiplier (default: 1.5)
        retry_exceptions: Exceptions that trigger a retry
        fatal_exceptions: Exceptions that should not be retried
        operation_name: Name of the operation for logging (defaults to function name)
        **kwargs: Keyword arguments to pass to the function

    Returns:
        The return value of the function

    Raises:
        Exception: If all retries fail
    """
    op_name = operation_name or func.__name__
    current_try = 0

    while True:
        try:
            return await func(*args, **kwargs)
        except fatal_exceptions:
            # Don't retry fatal exceptions
            logger.error(f"{op_name} failed with fatal exception")
            raise
        except retry_exceptions as e:
            current_try += 1
            if current_try > retries:
                logger.error(f"{op_name} failed after {retries} retries: {e}")
                raise

            wait_time = (backoff_factor ** (current_try - 1)) * (1 + random() * 0.1)
            logger.warning(
                f"{op_name} attempt {current_try}/{retries} failed: {e}. "
                f"Retrying in {wait_time:.2f} seconds..."
            )
            await asyncio.sleep(wait_time)


def retry_async(
    retries: int = 3,
    backoff_factor: float = 1.5,
    retry_exceptions: tuple = (Exception,),
    fatal_exceptions: tuple = (),
    operation_name: str | None = None,
):
    """
    Decorator for retrying async functions with exponential backoff.

    Args:
        retries: Maximum number of retries
        backoff_factor: Backoff multiplier
        retry_exceptions: Exceptions that trigger a retry
        fatal_exceptions: Exceptions that should not be retried
        operation_name: Name of the operation for logging

    Returns:
        Decorated function
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await with_retries(
                func,
                *args,
                retries=retries,
                backoff_factor=backoff_factor,
                retry_exceptions=retry_exceptions,
                fatal_exceptions=fatal_exceptions,
                operation_name=operation_name,
                **kwargs,
            )

        return wrapper

    return decorator


# ------------------------------------------------------------------------------
# OpenSSL Utilities
# ------------------------------------------------------------------------------


def has_openssl() -> bool:
    """Check if OpenSSL command-line tool is available."""
    return shutil.which("openssl") is not None


async def get_openssl_version() -> tuple[int, int, int]:
    """
    Get the OpenSSL version as a tuple of (major, minor, patch).
    Uses LRU cache_manager to avoid repeated calls.

    Returns:
        Tuple of version numbers, or (0, 0, 0) if unable to parse
    """
    if not has_openssl():
        return (0, 0, 0)

    try:
        # Create async subprocess
        proc = await asyncio.create_subprocess_exec(
            "openssl",
            "version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()

        match = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", output)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return (0, 0, 0)
    except Exception as e:
        logger.error(f"Error getting OpenSSL version: {e}")
        return (0, 0, 0)


# ------------------------------------------------------------------------------
# Cipher and Algorithm Analysis
# ------------------------------------------------------------------------------


def categorize_cipher_strength(cipher_name: str) -> CipherStrength:
    """Categorize cipher strength."""
    from core.tls.cipher_utils import classify_cipher

    return classify_cipher(cipher_name)


def categorize_signature_algorithm(sig_alg: str) -> SignatureAlgorithmSecurity:
    """
    Categorize a signature algorithm's security level.

    Args:
        sig_alg: Signature algorithm string

    Returns:
        SignatureAlgorithmSecurity enum value
    """
    sig_alg_lower = sig_alg.lower()

    for category, algorithms in SIGNATURE_ALGORITHMS.items():
        for algorithm in algorithms:
            if algorithm in sig_alg_lower:
                return category

    return SignatureAlgorithmSecurity.UNKNOWN


# ------------------------------------------------------------------------------
# Certificate Analysis
# ------------------------------------------------------------------------------
def clean_ssl_error_message(error_msg: str) -> str:
    """
    Clean up SSL error messages to be more user-friendly.

    Args:
        error_msg: Original error message

    Returns:
        Cleaned up error message
    """
    if "self-signed certificate" in error_msg.lower():
        return "Self-signed certificate detected"

    if "certificate has expired" in error_msg.lower():
        return "Certificate has expired"

    if "hostname mismatch" in error_msg.lower() or "doesn't match" in error_msg.lower():
        return "Certificate hostname verification failed"

    if "unable to get local issuer certificate" in error_msg.lower():
        return "Certificate chain incomplete - unable to verify with a trusted root"

    if "certificate verify failed" in error_msg.lower():
        return "Certificate verification failed"

    cleaned_msg = re.sub(r"\([^)]*\.[^)]*:[0-9]+\)", "", error_msg)
    cleaned_msg = re.sub(r"\[SSL: [A-Z_]+\]", "", cleaned_msg)
    cleaned_msg = re.sub(r"certificate verify failed:", "", cleaned_msg)
    cleaned_msg = " ".join(cleaned_msg.split())

    if cleaned_msg.strip():
        return cleaned_msg

    return "Certificate validation failed"


def create_error_cert_result(
    error_msg: str, is_connection_error: bool = False
) -> CertificateResult:
    """
    Create a CertificateResult object for error conditions.

    Args:
        error_msg: Error message to include

    Returns:
        CertificateResult with error information
    """
    is_self_signed = (
        "self-signed certificate" in error_msg.lower()
        or "self signed certificate" in error_msg.lower()
    )
    cleaned_error = clean_ssl_error_message(error_msg)

    return CertificateResult(
        subject="Unknown",
        issuer="Unknown",
        valid_from="Unknown",
        valid_until="Unknown",
        is_valid=False,
        is_expired=True,
        days_until_expiry=None,
        is_self_signed=is_self_signed,
        validation_error=cleaned_error,
        connection_error=is_connection_error,
    )


def extract_key_info(cert: x509.Certificate) -> KeyInfo:
    """
    Extract key type and length from certificate.

    Args:
        cert: x509 Certificate object

    Returns:
        KeyInfo with key type, length and security assessment
    """
    public_key = cert.public_key()
    key_type = type(public_key).__name__

    logger.debug(f"Certificate key type: {key_type}")

    key_length = 0
    key_name = "Unknown"

    if hasattr(public_key, "key_size"):
        key_length = public_key.key_size

    if "RSA" in key_type:
        key_name = "RSA"
    elif "DSA" in key_type:
        key_name = "DSA"
    elif "EllipticCurve" in key_type or "EC" in key_type:
        key_name = "EC"
        if key_length == 0 and hasattr(public_key, "curve"):
            try:
                curve_name = public_key.curve.name.lower()
                if "p256" in curve_name or "secp256" in curve_name:
                    key_length = 256
                elif "p384" in curve_name or "secp384" in curve_name:
                    key_length = 384
                elif "p521" in curve_name or "secp521" in curve_name:
                    key_length = 521
            except Exception as e:
                logger.warning(f"Error determining EC curve size: {e}")
    elif "Ed25519" in key_type:
        key_name = "Ed25519"
        key_length = 256
    elif "Ed448" in key_type:
        key_name = "Ed448"
        key_length = 456
    elif "ECDSA" in key_type:
        key_name = "ECDSA"

    secure = False
    if key_name in KEY_LENGTH_RECOMMENDATIONS:
        secure = key_length >= KEY_LENGTH_RECOMMENDATIONS[key_name]

    return KeyInfo(type=key_name, length=key_length, secure=secure)


def extract_signature_algorithm(cert: x509.Certificate) -> SignatureAlgorithmInfo:
    """
    Extract and categorize the signature algorithm from certificate.

    Args:
        cert: x509 Certificate object

    Returns:
        SignatureAlgorithmInfo with algorithm name and security assessment
    """
    sig_algorithm = cert.signature_algorithm_oid._name

    if hasattr(cert.signature_algorithm_oid, "_name"):
        sig_algorithm = cert.signature_algorithm_oid._name
    else:
        sig_algorithm = str(cert.signature_algorithm_oid)

    sig_algorithm = sig_algorithm.replace("ENCRYPTION", "").replace("WITH", " with ")

    security = categorize_signature_algorithm(sig_algorithm)

    return SignatureAlgorithmInfo(name=sig_algorithm, security=security)


def extract_san_info(cert: x509.Certificate, domain: str) -> SANInfo:
    """
    Extract Subject Alternative Names from certificate.

    Args:
        cert: x509 Certificate object
        domain: Domain being checked

    Returns:
        SANInfo with list of names and domain presence check
    """
    names = []
    contains_domain = False

    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        if san_ext:
            san = san_ext.value

            for dns_name in san.get_values_for_type(x509.DNSName):
                names.append(f"DNS:{dns_name}")
                if dns_name == domain or (
                    dns_name.startswith("*.") and domain.endswith(dns_name[1:])
                ):
                    contains_domain = True

            for ip in san.get_values_for_type(x509.IPAddress):
                names.append(f"IP:{ip}")
                if str(ip) == domain:
                    contains_domain = True
    except Exception as e:
        logger.warning(f"Error extracting SANs: {e}")

    return SANInfo(names=names, contains_domain=contains_domain)


async def run_openssl_command(
    domain: str, port: int, args: list[str], timeout: int, retries: int = 1
) -> tuple[str, int]:
    """
    Run OpenSSL command asynchronously with optimized retry logic.

    Uses different strategies for cipher tests vs. regular TLS connectivity checks.

    Args:
        domain: Target domain
        port: Target port
        args: OpenSSL arguments
        timeout: Initial timeout in seconds
        retries: Maximum number of retries

    Returns:
        Tuple of (command_output, return_code)
    """
    global _openssl_timeout_occurred
    if not has_openssl():
        return "OpenSSL not available", 1

    base_cmd = ["openssl", "s_client", "-connect", f"{domain}:{port}"]
    valid_args = [arg for arg in args if arg]
    cmd = base_cmd + valid_args
    cmd_str = " ".join(cmd)

    # Detect if this is a cipher test
    is_cipher_test = any("-cipher" in arg for arg in valid_args)

    # Use optimized parameters for cipher tests
    if is_cipher_test:
        # Cipher tests get shorter timeouts and fewer retries
        effective_timeout = min(2.0, timeout)
        effective_retries = min(1, retries)
        retry_delay = 0.5  # Very short retry delay for ciphers
    else:
        # Normal connectivity tests use standard values
        effective_timeout = timeout
        effective_retries = retries
        retry_delay = 2.0

    logger.debug(f"Running OpenSSL command: {cmd_str}")

    for attempt in range(effective_retries + 1):
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                # Use newline to complete handshake
                stdin_data = b"\n"
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=stdin_data), timeout=effective_timeout
                )
                output = stdout.decode(errors="replace") + stderr.decode(
                    errors="replace"
                )
                return output, proc.returncode

            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass

                if attempt < effective_retries:
                    if domain not in _openssl_timeout_occurred:
                        _openssl_timeout_occurred.append(domain)
                        logger.info(
                            f"Command timeout for {domain}:{port} (attempt {attempt + 1}/{effective_retries + 1}). "
                            f"Retrying in {retry_delay:.2f} seconds..."
                        )
                    await asyncio.sleep(retry_delay)
                    continue

                return "Command timed out", 1

        except Exception as e:
            logger.error(f"Error running OpenSSL for {domain}:{port}: {e}")

            if attempt < effective_retries:
                await asyncio.sleep(retry_delay)
                continue

            return f"Error running OpenSSL: {str(e)}", 1

    return "All retry attempts failed", 1


def format_x509_name(name):
    """Format X509Name object into a readable string."""
    name_parts = []
    for attr in name:
        oid = attr.oid
        if hasattr(oid, "_name"):
            attr_name = oid._name
        else:
            attr_name = oid.dotted_string

        name_parts.append(f"{attr_name}={attr.value}")

    return ", ".join(name_parts)


def format_serial_number(serial):
    """Format serial number as a colon-separated hex string."""
    serial_hex = format(serial, "x")
    if len(serial_hex) % 2 != 0:
        serial_hex = "0" + serial_hex

    return ":".join(serial_hex[i : i + 2] for i in range(0, len(serial_hex), 2))
