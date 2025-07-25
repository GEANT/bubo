# core/tls/models.py
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple


class CipherStrength(Enum):
    """Cipher strength categories."""

    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"
    UNKNOWN = "unknown"


class SignatureAlgorithmSecurity(Enum):
    """Signature algorithm security classification."""

    STRONG = "strong"
    ACCEPTABLE = "acceptable"
    WEAK = "weak"
    UNKNOWN = "unknown"


@dataclass
class SignatureAlgorithmInfo:
    """Certificate signature algorithm information."""

    name: str
    security: SignatureAlgorithmSecurity


class TLSProtocol(Enum):
    """TLS protocol versions."""

    TLSv1_0 = "TLSv1.0"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"


@dataclass
class TLSProtocolResult:
    """Result of a TLS protocol check."""

    protocol_name: str
    supported: bool
    secure: bool
    error: str | None = None


@dataclass
class KeyInfo:
    """Certificate key information."""

    type: str
    length: int
    secure: bool


@dataclass
class TLSCheckConfig:
    """Configuration for SSL checks."""

    use_openssl: bool = True
    timeout_connect: int = 10
    timeout_command: int = 10
    command_retries: int = 2
    check_ciphers: bool = True
    check_certificate: bool = True
    verify_chain: bool = True
    check_key_info: bool = True
    check_signature_algorithm: bool = True
    check_hsts: bool = True
    check_san: bool = True
    check_security_headers: bool = True
    max_cipher_concurrency: int = 10


@dataclass
class SANInfo:
    """Subject Alternative Names information."""

    names: list[str]
    contains_domain: bool


@dataclass
class CertificateResult:
    """Certificate validation result."""

    subject: str
    issuer: str
    valid_from: str
    valid_until: str
    is_valid: bool
    is_expired: bool
    days_until_expiry: int | None
    is_self_signed: bool = False
    validation_error: str | None = None
    chain_trusted: bool = False
    chain_valid: bool = False
    chain_length: int = 0
    chain_error: str | None = None
    chain_info: list[dict[str, str]] = field(default_factory=list)
    key_info: KeyInfo | None = None
    signature_algorithm: SignatureAlgorithmInfo | None = None
    subject_alternative_names: SANInfo | None = None
    connection_error: bool = False


class CipherResult:
    def __init__(
        self,
        name: str,
        protocol: str,
        strength: CipherStrength,
        bits: int | None = None,
        key_exchange: str | None = None,
        authentication: str | None = None,
        encryption: str | None = None,
        mac: str | None = None,
        iana_value: str | None = None,
        iana_name: str | None = None,
        dtls_ok: bool = False,
        recommended: bool = False,
        reference: str | None = None,
    ):
        self.name = name
        self.protocol = protocol
        self.strength = strength
        self.bits = bits
        self.key_exchange = key_exchange
        self.authentication = authentication
        self.encryption = encryption
        self.mac = mac
        self.iana_value = iana_value
        self.iana_name = iana_name
        self.dtls_ok = dtls_ok
        self.recommended = recommended
        self.reference = reference


PROTOCOL_SECURITY = {
    TLSProtocol.TLSv1_0: False,
    TLSProtocol.TLSv1_1: False,
    TLSProtocol.TLSv1_2: True,
    TLSProtocol.TLSv1_3: True,
}

KEY_LENGTH_RECOMMENDATIONS = {
    "RSA": 2048,
    "DSA": 2048,
    "EC": 256,
    "ECDSA": 256,
    "Ed25519": 256,
    "Ed448": 448,
}

# Signature algorithm security classification
SIGNATURE_ALGORITHMS = {
    SignatureAlgorithmSecurity.STRONG: [
        "sha256",
        "sha384",
        "sha512",
        "ed25519",
        "ed448",
    ],
    SignatureAlgorithmSecurity.ACCEPTABLE: ["sha224"],
    SignatureAlgorithmSecurity.WEAK: ["sha1", "md5", "md2", "md4"],
}


class CipherDetails(NamedTuple):
    protocol: str
    key_exchange: str
    authentication: str
    encryption: str
    mac: str
    strength: str
    iana_value: str = ""
    iana_name: str = ""
    dtls_ok: bool = False
    recommended: bool = False
    reference: str = ""
