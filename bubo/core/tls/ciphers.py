import asyncio
import re
from collections import defaultdict

from bubo.core.logging.logger import setup_logger
from bubo.core.tls.cipher_utils import (
    get_cipher_details,
    get_cipher_strength,
    get_protocol_ciphers,
)
from bubo.core.tls.models import (
    CipherResult,
    TLSCheckConfig,
    TLSProtocol,
)
from bubo.core.tls.utils import (
    has_openssl,
    run_openssl_command,
)

logger = setup_logger(__name__)


async def check_ciphers(
    domain: str, port: int, protocol: TLSProtocol, config: TLSCheckConfig
) -> list[CipherResult] | None:
    """Check all supported ciphers for a protocol with enhanced error handling."""
    if not config.check_ciphers or not has_openssl():
        return None

    protocol_option = {
        TLSProtocol.TLSv1_0: "-tls1",
        TLSProtocol.TLSv1_1: "-tls1_1",
        TLSProtocol.TLSv1_2: "-tls1_2",
        TLSProtocol.TLSv1_3: "-tls1_3",
    }.get(protocol)

    if not await _protocol_supported(
        domain, port, protocol_option, config.timeout_command
    ):
        logger.debug(f"Protocol {protocol.value} not supported by {domain}:{port}")
        return None

    ciphers = get_ciphers_for_protocol(protocol)

    if not ciphers:
        return None

    security_level = ""
    if protocol in [TLSProtocol.TLSv1_0, TLSProtocol.TLSv1_1]:
        security_level = ":@SECLEVEL=0"

    cipher_semaphore = asyncio.Semaphore(5)

    tasks = []
    for cipher in ciphers:
        if protocol == TLSProtocol.TLSv1_3:
            cipher_spec = cipher
        else:
            cipher_spec = f"{cipher}{security_level}"

        task = asyncio.create_task(
            _check_cipher_with_semaphore(
                cipher_semaphore,
                domain,
                port,
                protocol_option,
                cipher_spec,
                protocol.value,
                config.timeout_command,
            )
        )
        tasks.append(task)

    supported_ciphers = []
    for future in asyncio.as_completed(tasks):
        try:
            result = await future
            if result:
                supported_ciphers.append(result)
        except Exception as e:
            logger.debug(f"Error testing cipher: {e}")
            continue

    if not supported_ciphers:
        return None
    return supported_ciphers


async def _protocol_supported(
    domain: str, port: int, protocol_option: str, timeout: int
) -> bool:
    """
    Check if a protocol is supported by the server before testing individual ciphers.

    Args:
        domain: Target domain
        port: Target port
        protocol_option: OpenSSL protocol option (e.g., "-tls1_3")
        timeout: Command timeout

    Returns:
        True if protocol is supported, False otherwise
    """
    args = [protocol_option]
    output, _ = await run_openssl_command(domain, port, args, timeout)

    if re.search(r"New,.*Cipher\s+is\s+[^(]", output) or re.search(
        r"Cipher\s+:\s+[^(]", output
    ):
        return True

    return not any(
        error in output
        for error in [
            "sslv3 alert handshake failure",
            "wrong version number",
            "unsupported protocol",
            "no protocols available",
        ]
    )


async def _check_cipher_with_semaphore(
    semaphore: asyncio.Semaphore,
    domain: str,
    port: int,
    protocol_option: str,
    cipher_spec: str,
    protocol: str,
    timeout: int,
) -> CipherResult | None:
    """
    Test a cipher with semaphore-controlled concurrency and enhanced error handling.
    """
    async with semaphore:
        await asyncio.sleep(0.1 + (hash(cipher_spec) % 100) / 1000)

        return await test_cipher(
            domain, port, protocol_option, cipher_spec, protocol, timeout
        )


def process_cipher_results(
    results: list[list[CipherResult] | CipherResult | Exception | None],
    protocols: list[TLSProtocol],
) -> tuple[dict[str, list[dict]], dict[str, list[str]]]:
    """Process cipher check results."""
    ciphers_by_protocol = {}
    cipher_strength = defaultdict(list)

    for i, protocol_results in enumerate(results):
        if isinstance(protocol_results, Exception) or protocol_results is None:
            continue

        protocol = protocols[i]
        ciphers_by_protocol[protocol.value] = []

        if isinstance(protocol_results, list):
            for result in protocol_results:
                cipher_info = {
                    "name": result.name,
                    "strength": result.strength.value,
                    "bits": result.bits,
                }

                if hasattr(result, "key_exchange") and result.key_exchange:
                    cipher_info["key_exchange"] = result.key_exchange
                if hasattr(result, "authentication") and result.authentication:
                    cipher_info["authentication"] = result.authentication
                if hasattr(result, "encryption") and result.encryption:
                    cipher_info["encryption"] = result.encryption
                if hasattr(result, "mac") and result.mac:
                    cipher_info["mac"] = result.mac

                if hasattr(result, "iana_value") and result.iana_value:
                    cipher_info["iana_value"] = result.iana_value
                if hasattr(result, "iana_name") and result.iana_name:
                    cipher_info["iana_name"] = result.iana_name
                if hasattr(result, "dtls_ok"):
                    cipher_info["dtls_ok"] = result.dtls_ok
                if hasattr(result, "recommended"):
                    cipher_info["recommended"] = result.recommended
                if hasattr(result, "reference") and result.reference:
                    cipher_info["reference"] = result.reference

                ciphers_by_protocol[protocol.value].append(cipher_info)
                cipher_strength[result.strength.value].append(result.name)
        else:
            cipher_result = protocol_results
            cipher_info = {
                "name": cipher_result.name,
                "strength": cipher_result.strength.value,
                "bits": cipher_result.bits,
            }

            if hasattr(cipher_result, "key_exchange") and cipher_result.key_exchange:
                cipher_info["key_exchange"] = cipher_result.key_exchange
            if (
                hasattr(cipher_result, "authentication")
                and cipher_result.authentication
            ):
                cipher_info["authentication"] = cipher_result.authentication
            if hasattr(cipher_result, "encryption") and cipher_result.encryption:
                cipher_info["encryption"] = cipher_result.encryption
            if hasattr(cipher_result, "mac") and cipher_result.mac:
                cipher_info["mac"] = cipher_result.mac

            ciphers_by_protocol[protocol.value].append(cipher_info)
            cipher_strength[cipher_result.strength.value].append(cipher_result.name)

    return ciphers_by_protocol, cipher_strength


def get_ciphers_for_protocol(protocol: TLSProtocol) -> list[str]:
    """
    Get list of ciphers to test for a protocol.

    Note: TLS 1.3 uses a different format for cipher specification and requires
    different flags (-ciphersuites instead of -cipher).
    """
    protocol_ciphers = get_protocol_ciphers()
    return protocol_ciphers.get(protocol, [])


async def test_cipher(
    domain: str,
    port: int,
    protocol_option: str,
    cipher_spec: str,
    protocol: str,
    timeout: int,
) -> CipherResult | None:
    """
    Test if a cipher is supported.

    Args:
        domain: Domain to check
        port: Port to connect to
        protocol_option: OpenSSL protocol option (e.g., "-tls1_2")
        cipher_spec: Cipher specification to test
        protocol: Protocol name for the result
        timeout: Command timeout

    Returns:
        CipherResult if the cipher is supported, None otherwise
    """
    if protocol == TLSProtocol.TLSv1_3.value:
        args = [protocol_option, "-ciphersuites", cipher_spec]
    else:
        args = [protocol_option, "-cipher", cipher_spec]

    output, exit_code = await run_openssl_command(domain, port, args, timeout)

    cipher_match = None
    cipher_match = re.search(r"New,.*?Cipher\s+is\s+(\S+)", output)
    if not cipher_match:
        cipher_match = re.search(r"Cipher\s*:\s*(\S+)", output)

    if "handshake failure" in output or "alert" in output.lower():
        logger.debug(
            f"Handshake failure for {cipher_spec} - {protocol}: {output[:100]}"
        )
        return None

    if cipher_match:
        cipher_name = cipher_match.group(1).strip()
        if cipher_name and cipher_name not in ("(NONE)", "0000", "NONE", "none"):
            bits = None
            bits_match = re.search(r"(\d+) bit", output)
            if bits_match:
                bits = int(bits_match.group(1))

            strength = get_cipher_strength(cipher_name)

            cipher_details = get_cipher_details().get(cipher_name)

            key_exchange = None
            authentication = None
            encryption = None
            mac = None
            iana_value = None
            iana_name = None
            dtls_ok = False
            recommended = False
            reference = None

            if cipher_details:
                key_exchange = cipher_details.key_exchange
                authentication = cipher_details.authentication
                encryption = cipher_details.encryption
                mac = cipher_details.mac

                if hasattr(cipher_details, "iana_value"):
                    iana_value = cipher_details.iana_value
                if hasattr(cipher_details, "iana_name"):
                    iana_name = cipher_details.iana_name
                if hasattr(cipher_details, "dtls_ok"):
                    dtls_ok = cipher_details.dtls_ok
                if hasattr(cipher_details, "recommended"):
                    recommended = cipher_details.recommended
                if hasattr(cipher_details, "reference"):
                    reference = cipher_details.reference

            return CipherResult(
                name=cipher_name,
                protocol=protocol,
                strength=strength,
                bits=bits,
                key_exchange=key_exchange,
                authentication=authentication,
                encryption=encryption,
                mac=mac,
                iana_value=iana_value,
                iana_name=iana_name,
                dtls_ok=dtls_ok,
                recommended=recommended,
                reference=reference,
            )

    return None
