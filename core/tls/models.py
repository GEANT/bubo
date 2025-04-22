# core/tls/models.py
from dataclasses import dataclass, field
from enum import Enum


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


@dataclass
class CipherResult:
    """Result of a cipher suite check."""

    name: str
    protocol: str
    strength: CipherStrength
    bits: int | None = None


PROTOCOL_SECURITY = {
    TLSProtocol.TLSv1_0: False,
    TLSProtocol.TLSv1_1: False,
    TLSProtocol.TLSv1_2: True,
    TLSProtocol.TLSv1_3: True,
}

# Cipher patterns for strength classification
CIPHER_PATTERNS = {
    CipherStrength.STRONG: [
        r"ECDHE.*AES.*GCM",
        r"ECDHE.*CHACHA20",
        r"DHE.*AES.*GCM",
        r"ECDHE.*AES.*CCM",
        r"TLS_AES_",
        r"TLS_CHACHA20_",
        r"AES256-SHA256",
    ],
    CipherStrength.MEDIUM: [
        r"ECDHE.*AES.*CBC",
        r"DHE.*AES.*CBC",
        r"RSA.*AES.*GCM",
        r"ECDH.*AES",
    ],
    CipherStrength.WEAK: [
        r"RC4",
        r"DES",
        r"3DES",
        r"NULL",
        r"anon",
        r"MD5",
        r"SHA(?!256|384|512)"
        r"EXPORT",
        r"PSK",
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
