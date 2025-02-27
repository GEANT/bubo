# tests/conftest.py

import pytest
from unittest.mock import AsyncMock, MagicMock
from core.cache_manager import DomainResultsCache
from datetime import datetime


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
    return tmp_path / "cache"


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
    return [MagicMock(__str__=lambda x: "192.168.1.1")]


@pytest.fixture
def mock_ipv6_records():
    return [MagicMock(__str__=lambda x: "2001:db8::1")]


@pytest.fixture
def mock_mx_records():
    records = []
    for hostname in ["mail1.example.com", "mail2.example.com"]:
        record = MagicMock()
        record.exchange = MagicMock()
        record.exchange.to_text.return_value = hostname
        records.append(record)

    result = MagicMock()
    result.__iter__.return_value = records
    return result


@pytest.fixture
def mock_ns_records():
    return [
        MagicMock(__str__=lambda _: "ns1.example.com"),
        MagicMock(__str__=lambda _: "ns2.example.com"),
    ]


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

    return setup_mock


@pytest.fixture
def mock_dane_valid():
    async def setup_mock(mock_tlsa, mock_validate):
        mock_tlsa.return_value = ["3 1 1 hash_value"]
        mock_validate.return_value = True

    return setup_mock
