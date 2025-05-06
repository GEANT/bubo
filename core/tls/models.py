# core/tls/models.py
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple, Optional


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
        bits: Optional[int] = None,
        key_exchange: Optional[str] = None,
        authentication: Optional[str] = None,
        encryption: Optional[str] = None,
        mac: Optional[str] = None,
        iana_value: Optional[str] = None,
        iana_name: Optional[str] = None,
        dtls_ok: bool = False,
        recommended: bool = False,
        reference: Optional[str] = None,
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

# Cipher patterns for strength classification
CIPHER_PATTERNS = {
    CipherStrength.STRONG: [
        # TLS 1.3 AEAD ciphers (all provide AEAD + forward secrecy)
        r"^TLS_AES_128_GCM_SHA256$",
        r"^TLS_AES_256_GCM_SHA384$",
        r"^TLS_CHACHA20_POLY1305_SHA256$",
        r"^TLS_AES_128_CCM_SHA256$",
        r"^TLS_AES_128_CCM_8_SHA256$",
        # TLS 1.2 AEAD with Ephemeral key exchange (ECDHE/DHE)
        r"^ECDHE-.*-AES128-GCM-SHA256$",
        r"^ECDHE-.*-AES256-GCM-SHA384$",
        r"^DHE-RSA-AES128-GCM-SHA256$",
        r"^DHE-RSA-AES256-GCM-SHA384$",
        # TLS 1.2 ChaCha20-Poly1305 with Ephemeral key exchange
        r"^ECDHE-.*-CHACHA20-POLY1305$",
        r"^DHE-RSA-CHACHA20-POLY1305$",
    ],
    CipherStrength.MEDIUM: [
        # TLS 1.2 AEAD without forward secrecy (RSA key-exchange)
        r"^AES128-GCM-SHA256$",
        r"^AES256-GCM-SHA384$",
        # TLS 1.2 CBC with SHA-2 and forward secrecy
        r"^ECDHE-.*-AES128-SHA256$",
        r"^ECDHE-.*-AES256-SHA384$",
        r"^DHE-RSA-AES128-SHA256$",
        r"^DHE-RSA-AES256-SHA256$",
        # TLS 1.2 CBC with SHA-2 without forward secrecy
        r"^AES128-SHA256$",
        r"^AES256-SHA256$",
    ],
    CipherStrength.WEAK: [
        # SHA-1 based ciphers (any with SHA$ or SHA1)
        r"-SHA$",
        r"-SHA1$",
        # Static RSA key exchange (no PFS)
        r"^TLS_RSA_.*",
        # PSK and SRP ciphers (often weaker or no PKI auth)
        r"PSK-",
        r"ECDHE-PSK-",
        r"DHE-PSK-",
        r"RSA-PSK-",
        r"SRP-",
        # Obsolete algorithms and protocols
        r"RC4",
        r"3DES",
        r"DES",
        r"NULL",
        r"EXPORT",
        r"anon",
        r"MD5",
        r"^SSLv3",
        r"DSS",
    ],
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
