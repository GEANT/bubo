# tests/conftest.py

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.cache_manager.cache_manager import DomainResultsCache
from core.tls.models import (
    TLSCheckConfig,
)


@pytest.fixture
def sample_domain():
    return "example.com"


@pytest.fixture
def sample_servers():
    return {
        "domain_ns": ["ns1.example.com", "ns2.example.com"],
        "domain_mx": ["mail.example.com"],
        "mail_ns": [["ns1.mail.example.com"]],
    }


@pytest.fixture
def mock_standards_results():
    return {
        "rpki": (
            {
                "example.com": {
                    "domain_ns": {
                        "ns1.example.com": {
                            "ipv6": ["2001:db8::1"],
                            "prefix": {
                                "192.0.2.0/24": {
                                    "asn": "64496",
                                    "ipv4": ["192.0.2.1"],
                                    "rpki_state": "Valid",
                                }
                            },
                        }
                    }
                }
            },
            {
                "example.com": {
                    "Mail Server of Domain": "valid",
                    "Nameserver of Domain": "valid",
                    "Nameserver of Mail Server": "valid",
                }
            },
        ),
        "dane": (
            {
                "example.com": {
                    "domain_mx": {
                        "mail.example.com": {
                            "tlsa_records": [{"record": "test_record", "valid": True}],
                            "validation": True,
                        }
                    }
                }
            },
            {
                "example.com": {
                    "Mail Server of Domain": "valid",
                    "Nameserver of Domain": "valid",
                    "Nameserver of Mail Server": "valid",
                }
            },
        ),
        "dnssec": (
            {
                "example.com": {
                    "dnssec_status": {
                        "is_signed": True,
                        "nameservers": {"status": "Signed"},
                        "registrar": {"status": "FullySigned"},
                    }
                }
            },
            {"example.com": {"DNSSEC": True}},
        ),
    }


@pytest.fixture
def cache_dir(tmp_path):
    return tmp_path / "cache_manager"


@pytest.fixture
def mock_cache():
    return MagicMock(spec=DomainResultsCache)


@pytest.fixture
def mock_cache_generator():
    mock_cache = MagicMock(spec=DomainResultsCache)
    mock_cache.get_results.return_value = None
    return mock_cache


@pytest.fixture
def mock_dns_resolver():
    mock_resolver = MagicMock()
    mock_resolver.resolve = AsyncMock()
    return mock_resolver


@pytest.fixture
def mock_ipv4_records():
    record = MagicMock()
    record.__str__ = lambda _: "192.168.1.1"

    records = MagicMock()
    records.__iter__.return_value = [record]
    return records


@pytest.fixture
def mock_ipv6_records():
    record = MagicMock()
    record.__str__ = lambda _: "2001:db8::1"

    records = MagicMock()
    records.__iter__.return_value = [record]
    return records


@pytest.fixture
def mock_mx_records():
    record1 = MagicMock()
    record1.exchange = MagicMock()
    record1.exchange.to_text.return_value = "mail1.example.com."

    record2 = MagicMock()
    record2.exchange = MagicMock()
    record2.exchange.to_text.return_value = "mail2.example.com."

    records = MagicMock()
    records.__iter__.return_value = [record1, record2]
    return records


@pytest.fixture
def mock_ns_records():
    record1 = MagicMock()
    record1.__str__ = lambda _: "ns1.example.com."

    record2 = MagicMock()
    record2.__str__ = lambda _: "ns2.example.com."

    records = MagicMock()
    records.__iter__.return_value = [record1, record2]
    return records


@pytest.fixture
def sample_cache_results():
    return {
        "validations": {
            "RPKI": {
                "results": {"domain.com": {"status": True}},
                "state": {"domain.com": {"Nameserver of Domain": "valid"}},
            },
            "DANE": {
                "results": {"domain.com": {"tlsa_records": []}},
                "state": {"domain.com": {"Nameserver of Domain": "not-valid"}},
            },
            "DNSSEC": {
                "results": {"domain.com": {"dnssec_status": {"is_signed": True}}},
                "state": {"domain.com": {"DNSSEC": True}},
            },
        },
        "domain_metadata": {"domain.com": {"country": "US", "institution": "Example"}},
    }


@pytest.fixture
def mock_rpki_valid_response():
    return {
        "validated_route": {
            "route": {"origin_asn": "AS1103", "prefix": "195.169.124.0/24"},
            "validity": {
                "state": "valid",
                "description": "At least one VRP Matches the Route Prefix",
                "VRPs": {
                    "matched": [
                        {
                            "asn": "AS1103",
                            "prefix": "195.169.0.0/16",
                            "max_length": "24",
                        }
                    ],
                    "unmatched_as": [],
                    "unmatched_length": [],
                },
            },
        },
        "generatedTime": "2025-02-10T08:35:23Z",
    }


@pytest.fixture
def mock_dnssec_response():
    def _make_response(is_signed=True):
        status = "Signed" if is_signed else "Unsigned"
        records = ["sample record"] if is_signed else []
        return {
            "root_domain": "example.com",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dnssec_status": {
                "is_signed": is_signed,
                "registrar": {"status": status, "ds_records": records},
                "nameservers": {
                    "status": status,
                    "dnskey_records": records,
                    "rrsig_records": records,
                },
            },
            "verification_chain": [],
        }

    return _make_response


@pytest.fixture
def mock_rpki_valid():
    async def setup_mock(mock_validate, mock_resolve, mock_asn):
        mock_validate.return_value = {
            "validated_route": {"validity": {"state": "valid"}}
        }
        mock_resolve.return_value = (["192.0.2.1"], ["2001:db8::1"])
        mock_asn.return_value = ("AS64496", "192.0.2.0/24")

        return None

    return setup_mock


@pytest.fixture
def mock_dane_valid():
    async def setup_mock(mock_tlsa, mock_validate):
        mock_tlsa.return_value = ["3 1 1 hash_value"]
        mock_validate.return_value = True

        return None

    return setup_mock


@pytest.fixture
def mock_successful_openssl_response():
    """Return a mock successful OpenSSL response."""
    return (
        """
    New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
    Server public key is 2048 bit
    Secure Renegotiation IS supported
    Compression: NONE
    Expansion: NONE
    No ALPN negotiated
    SSL-Session:
        Protocol  : TLSv1.2
        Cipher    : ECDHE-RSA-AES256-GCM-SHA384
        Session-ID: 5F7C...
        Master-Key: 8F3A...
        PSK identity: None
        PSK identity hint: None
        SRP username: None
        TLS session ticket lifetime hint: 300 (seconds)
        TLS session ticket:
        Start Time: 1622541234
        Timeout   : 300 (sec)
        Verify return code: 0 (ok)
    """,
        0,
    )


@pytest.fixture
def mock_failed_openssl_response():
    """Return a mock failed OpenSSL response."""
    return (
        """
    140736010562752:error:1409E0E5:SSL routines:ssl3_write_bytes:ssl handshake failure:../ssl/record/rec_layer_s3.c:1543:
    no peer certificate available
    No client certificate CA names sent
    SSL handshake has read 0 bytes and written 0 bytes
    New, (NONE), Cipher is (NONE)
    Secure Renegotiation IS NOT supported
    """,
        1,
    )


@pytest.fixture
def mock_async_openssl_command():
    """Create a properly configured AsyncMock for openssl command."""
    async_mock = AsyncMock()
    async_mock.return_value = ("Mock OpenSSL Output", 0)
    return async_mock


@pytest.fixture
def mock_tls_check_config():
    """Return a mock TLS check configuration."""

    return TLSCheckConfig(
        use_openssl=True,
        timeout_connect=10,
        timeout_command=10,
        command_retries=2,
        check_ciphers=True,
        check_certificate=True,
        verify_chain=True,
        check_key_info=True,
        check_signature_algorithm=True,
        check_hsts=True,
        check_san=True,
        check_security_headers=True,
    )


@pytest.fixture
def mock_cipher_result_factory():
    """Return a factory for creating CipherResult objects with proper enum handling."""
    from core.tls.models import CipherResult, CipherStrength

    def _create_cipher_result(name, protocol, strength_val, bits=None):
        # Convert string strength to enum if needed
        if isinstance(strength_val, str):
            for strength in CipherStrength:
                if strength.value == strength_val:
                    strength_val = strength
                    break

        return CipherResult(
            name=name, protocol=protocol, strength=strength_val, bits=bits
        )

    return _create_cipher_result


@pytest.fixture
def mock_openssl_utils():
    """Mock the OpenSSL utility functions properly for async testing."""
    has_openssl_mock = MagicMock(return_value=True)
    run_openssl_mock = AsyncMock()
    run_openssl_mock.return_value = ("Mock OpenSSL Output", 0)

    extract_cipher_info_mock = MagicMock(
        return_value={
            "name": "ECDHE-RSA-AES256-GCM-SHA384",
            "protocol": "TLSv1.2",
            "strength": "strong",
            "bits": 256,
        }
    )

    with (
        patch("core.tls.utils.has_openssl", has_openssl_mock),
        patch("core.tls.utils.run_openssl_command", run_openssl_mock),
        patch("core.tls.utils.extract_cipher_info", extract_cipher_info_mock),
    ):
        yield has_openssl_mock, run_openssl_mock, extract_cipher_info_mock


@pytest.fixture
def mock_openssl_output_tls1_0():
    """Sample OpenSSL output for TLSv1.0."""
    return """
    SSL-Session:
        Protocol  : TLSv1
        Cipher    : ECDHE-RSA-AES256-SHA
        Session-ID: 
        ...
    New, TLSv1.0, Cipher is ECDHE-RSA-AES256-SHA
    """


@pytest.fixture
def mock_openssl_output_tls1_2():
    """Sample OpenSSL output for TLSv1.2."""
    return """
    SSL-Session:
        Protocol  : TLSv1.2
        Cipher    : ECDHE-RSA-AES256-GCM-SHA384
        Session-ID: 
        ...
    New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
    Server public key is 2048 bit
    """


@pytest.fixture
def mock_openssl_output_tls1_3():
    """Sample OpenSSL output for TLSv1.3."""
    return """
    SSL-Session:
        Protocol  : TLSv1.3
        Cipher    : TLS_AES_256_GCM_SHA384
        Session-ID: 
        ...
    New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Server public key is 4096 bit
    """


@pytest.fixture
def mock_openssl_output_failed():
    """Sample OpenSSL output for failed connection."""
    return """
    140736010562752:error:1409E0E5:SSL routines:ssl3_write_bytes:ssl handshake failure:../ssl/record/rec_layer_s3.c:1543:
    no peer certificate available
    No client certificate CA names sent
    """
