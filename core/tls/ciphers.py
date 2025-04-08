# core/tls/ciphers.py

from typing import Dict, List, Optional, Tuple, Union
from collections import defaultdict
from core.tls.utils import (
    has_openssl,
    run_openssl_command,
    extract_cipher_info,
)
from core.logging.logger import setup_logger
from core.tls.models import (
    TLSProtocol,
    CipherResult,
    TLSCheckConfig,
)


logger = setup_logger(__name__)


async def check_cipher(
    domain: str, port: int, protocol: TLSProtocol, config: TLSCheckConfig
) -> Optional[CipherResult]:
    """Check supported cipher for a protocol."""
    if not config.check_ciphers or not has_openssl():
        return None

    protocol_option = {
        TLSProtocol.TLSv1_0: "-tls1",
        TLSProtocol.TLSv1_1: "-tls1_1",
        TLSProtocol.TLSv1_2: "-tls1_2",
        TLSProtocol.TLSv1_3: "-tls1_3",
    }.get(protocol)

    output, _ = await run_openssl_command(
        domain, port, [protocol_option], config.timeout_command
    )

    cipher_info = extract_cipher_info(output, protocol.value)

    if cipher_info:
        return CipherResult(
            name=cipher_info["name"],
            protocol=cipher_info["protocol"],
            strength=cipher_info["strength"],
            bits=cipher_info["bits"],
        )
    return None


def process_cipher_results(
    results: List[Union[CipherResult, Exception, None]], protocols: List[TLSProtocol]
) -> Tuple[Dict[str, List[Dict]], Dict[str, List[str]]]:
    """Process cipher check results."""
    ciphers_by_protocol = {}
    cipher_strength = defaultdict(list)

    for i, result in enumerate(results):
        if isinstance(result, Exception) or result is None:
            continue
        protocol = protocols[i]
        ciphers_by_protocol[protocol.value] = [
            {
                "name": result.name,
                "strength": result.strength.value,
                "bits": result.bits,
            }
        ]

        cipher_strength[result.strength.value].append(result.name)

    return ciphers_by_protocol, cipher_strength
