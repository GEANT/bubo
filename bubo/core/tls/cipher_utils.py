import asyncio
import os
import re
import subprocess
from pathlib import Path

from bubo.core.logging.logger import setup_logger
from bubo.core.tls.models import CipherDetails, CipherStrength, TLSProtocol

logger = setup_logger(__name__)
_protocol_ciphers: dict[TLSProtocol, list[str]] | None = None
_strength_ciphers: dict[str, list[str]] | None = None
_cipher_details: dict[str, CipherDetails] | None = None
_cipher_to_strength: dict[str, CipherStrength] | None = None
_initialization_lock = asyncio.Lock()
_initialized = False
_iana_initialized = False


def get_cache_directory() -> Path:
    """Get the cache directory for IANA data.

    Returns:
        Path to the cache directory (bubo/cache/iana_data/)
    """

    current_file = Path(__file__).resolve()
    project_root = current_file.parent.parent.parent
    cache_dir = project_root / "cache" / "iana_data"

    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_iana_csv_path() -> Path:
    """Get the path to the IANA CSV file.

    Returns:
        Path to the IANA TLS parameters CSV file
    """

    env_path = os.environ.get("IANA_CIPHERS_CSV")
    if env_path:
        return Path(env_path)

    return get_cache_directory() / "iana_tls_parameters.csv"


_iana_csv_path = str(get_iana_csv_path())


def classify_cipher(
    cipher_name: str,
    protocol_str: str | None = None,
    kx: str | None = None,
    auth: str | None = None,
    enc: str | None = None,
    mac: str | None = None,
) -> CipherStrength:
    """
    Classify cipher strength based on protocol, key exchange, auth, encryption, MAC,
    and IANA recommendations if available.

    Args:
        cipher_name: Full cipher name
        protocol_str: Protocol version (e.g., "TLSv1.3")
        kx: Key exchange method (e.g., "Kx=ECDH")
        auth: Authentication method (e.g., "Au=RSA")
        enc: Encryption algorithm (e.g., "Enc=AESGCM(256)")
        mac: Message authentication code (e.g., "Mac=AEAD")

    Returns:
        CipherStrength enum value
    """
    from bubo.core.tls.models import CipherStrength

    if _iana_initialized:
        from bubo.core.tls.iana_ciphers import is_recommended_cipher

        if is_recommended_cipher(cipher_name):
            return CipherStrength.STRONG

    if protocol_str is None:
        if cipher_name.startswith("TLS_"):
            return CipherStrength.STRONG

        if any(
            weak in cipher_name
            for weak in ["NULL", "RC4", "3DES", "EXPORT", "anon", "MD5"]
        ):
            return CipherStrength.WEAK

        if "GCM" in cipher_name or "CHACHA20" in cipher_name or "CCM" in cipher_name:
            if any(pfs in cipher_name for pfs in ["ECDHE-", "DHE-"]):
                return CipherStrength.STRONG
            return CipherStrength.MEDIUM

        if any(pfs in cipher_name for pfs in ["ECDHE-", "DHE-"]) and (
            "SHA256" in cipher_name or "SHA384" in cipher_name
        ):
            return CipherStrength.MEDIUM

        if cipher_name.endswith("-SHA") or (
            not any(pfs in cipher_name for pfs in ["ECDHE-", "DHE-"])
            and not any(aead in cipher_name for aead in ["GCM", "CCM", "CHACHA20"])
            and "RSA" in cipher_name
        ):
            return CipherStrength.WEAK

        return CipherStrength.UNKNOWN

    kx_value = kx.split("=")[1] if "=" in kx else kx
    mac_value = mac.split("=")[1] if "=" in mac else mac

    enc_alg = ""

    if "=" in enc and "(" in enc:
        enc_part = enc.split("=")[1]
        enc_alg = enc_part.split("(")[0]

    if protocol_str == "TLSv1.3":
        return CipherStrength.STRONG

    if any(x in cipher_name for x in ["NULL", "RC4", "3DES", "EXPORT", "anon", "MD5"]):
        return CipherStrength.WEAK

    is_aead = (
        mac_value == "AEAD"
        or "GCM" in enc_alg
        or "CCM" in enc_alg
        or "CHACHA20" in enc_alg
    )

    has_pfs = any(x in kx_value for x in ["ECDH", "DH"]) and kx_value != "RSA"

    has_secure_hash = (
        "SHA256" in cipher_name
        or "SHA384" in cipher_name
        or mac_value in ["SHA256", "SHA384"]
    )
    has_sha1 = "SHA1" in mac_value or cipher_name.endswith("-SHA")

    is_psk_only = "PSK" in kx_value and not has_pfs
    is_srp = "SRP" in kx_value

    is_static_rsa = kx_value == "RSA"

    if is_aead:
        if has_pfs:
            return CipherStrength.STRONG
        return CipherStrength.MEDIUM
    if has_pfs:
        if has_secure_hash:
            return CipherStrength.MEDIUM
        return CipherStrength.WEAK
    if (
        has_sha1
        or is_psk_only
        or is_srp
        or (is_static_rsa and not is_aead)
        or "SSLv3" in protocol_str
    ):
        return CipherStrength.WEAK

    return CipherStrength.UNKNOWN


def parse_openssl_ciphers() -> tuple[
    dict[TLSProtocol, list[str]], dict[str, list[str]], dict[str, CipherDetails]
]:
    """
    Parse the output of 'openssl ciphers -v' to dynamically build:
    1. Protocol-to-ciphers mapping
    2. Classification of ciphers by strength
    3. Detailed information for each cipher

    Returns:
        Tuple containing:
            - Dict mapping TLSProtocol to list of cipher names
            - Dict mapping strength category to list of cipher names
            - Dict mapping cipher names to their detailed information
    """
    try:
        result = subprocess.run(
            ["openssl", "ciphers", "-v"], capture_output=True, text=True, check=True
        )
        output = result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        from bubo.core.tls.models import PROTOCOL_CIPHERS

        return PROTOCOL_CIPHERS, {}, {}

    protocol_ciphers = {
        TLSProtocol.TLSv1_0: [],
        TLSProtocol.TLSv1_1: [],
        TLSProtocol.TLSv1_2: [],
        TLSProtocol.TLSv1_3: [],
    }

    strength_ciphers = {"strong": [], "medium": [], "weak": []}

    cipher_details = {}

    for line in output.strip().split("\n"):
        parts = re.split(r"\s+", line.strip(), maxsplit=5)
        if len(parts) < 6:
            continue

        cipher_name, protocol_str, kx, auth, enc, mac = parts

        kx_value = kx.split("=")[1] if "=" in kx else kx
        auth_value = auth.split("=")[1] if "=" in auth else auth
        enc_value = enc.split("=")[1] if "=" in enc else enc
        mac_value = mac.split("=")[1] if "=" in mac else mac

        protocol = None
        if protocol_str == "TLSv1.3":
            protocol = TLSProtocol.TLSv1_3
        elif protocol_str == "TLSv1.2":
            protocol = TLSProtocol.TLSv1_2
        elif protocol_str == "TLSv1":
            protocol = TLSProtocol.TLSv1_0
            protocol_ciphers[TLSProtocol.TLSv1_1].append(cipher_name)
        elif protocol_str == "SSLv3":
            protocol = TLSProtocol.TLSv1_0

        if protocol:
            protocol_ciphers[protocol].append(cipher_name)

        strength = classify_cipher(cipher_name, protocol_str, kx, auth, enc, mac)
        strength_ciphers[strength.value].append(cipher_name)

        cipher_details[cipher_name] = CipherDetails(
            protocol=protocol_str,
            key_exchange=kx_value,
            authentication=auth_value,
            encryption=enc_value,
            mac=mac_value,
            strength=strength.value,
        )

    if _iana_initialized:
        from bubo.core.tls.iana_ciphers import get_iana_cipher_info

        for cipher_name, details in cipher_details.items():
            iana_info = get_iana_cipher_info(cipher_name)
            if iana_info:
                cipher_details[cipher_name] = CipherDetails(
                    protocol=details.protocol,
                    key_exchange=details.key_exchange,
                    authentication=details.authentication,
                    encryption=details.encryption,
                    mac=details.mac,
                    strength=details.strength,
                    iana_value=iana_info.get("value", ""),
                    iana_name=iana_info.get("name", ""),
                    dtls_ok=iana_info.get("dtls_ok", False),
                    recommended=iana_info.get("recommended", False),
                    reference=iana_info.get("reference", ""),
                )

    return protocol_ciphers, strength_ciphers, cipher_details


async def initialize() -> None:
    """Initialize cipher caches if not already done."""
    global \
        _protocol_ciphers, \
        _strength_ciphers, \
        _cipher_details, \
        _cipher_to_strength, \
        _initialized, \
        _iana_initialized

    async with _initialization_lock:
        if not _initialized:
            loop = asyncio.get_running_loop()
            (
                _protocol_ciphers,
                _strength_ciphers,
                _cipher_details,
            ) = await loop.run_in_executor(None, parse_openssl_ciphers)

            _cipher_to_strength = {}
            for strength, ciphers in _strength_ciphers.items():
                for cipher in ciphers:
                    _cipher_to_strength[cipher] = CipherStrength(strength)

            try:
                from bubo.core.tls.iana_ciphers import (
                    get_iana_cipher_info,
                    initialize_iana_mappings,
                )

                _iana_initialized = await loop.run_in_executor(
                    None, initialize_iana_mappings, _iana_csv_path
                )

                if _iana_initialized:
                    for cipher_name, details in _cipher_details.items():
                        iana_info = get_iana_cipher_info(cipher_name)
                        if iana_info:
                            _cipher_details[cipher_name] = CipherDetails(
                                protocol=details.protocol,
                                key_exchange=details.key_exchange,
                                authentication=details.authentication,
                                encryption=details.encryption,
                                mac=details.mac,
                                strength=details.strength,
                                iana_value=iana_info.get("value", ""),
                                iana_name=iana_info.get("name", ""),
                                dtls_ok=iana_info.get("dtls_ok", False),
                                recommended=iana_info.get("recommended", False),
                                reference=iana_info.get("reference", ""),
                            )
            except Exception as e:
                logger.warning(f"Failed to initialize IANA cipher mappings: {e}")

            _initialized = True


def get_protocol_ciphers() -> dict[TLSProtocol, list[str]]:
    """Get the cached protocol-to-ciphers mapping."""
    if not _initialized:
        raise RuntimeError(
            "Cipher cache not initialized. Call 'await initialize()' first."
        )
    return _protocol_ciphers


def get_strength_ciphers() -> dict[str, list[str]]:
    """Get the cached strength-to-ciphers mapping."""
    if not _initialized:
        raise RuntimeError(
            "Cipher cache not initialized. Call 'await initialize()' first."
        )
    return _strength_ciphers


def get_cipher_strength(cipher_name: str) -> CipherStrength:
    """Get the strength classification for a cipher."""
    if not _initialized:
        raise RuntimeError(
            "Cipher cache not initialized. Call 'await initialize()' first."
        )

    return _cipher_to_strength.get(cipher_name, classify_cipher(cipher_name))


def get_cipher_details() -> dict[str, CipherDetails]:
    """Get the cached detailed information for each cipher."""
    if not _initialized:
        raise RuntimeError(
            "Cipher cache not initialized. Call 'await initialize()' first."
        )
    return _cipher_details
