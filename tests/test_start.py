# tests/test_main.py

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from unittest.mock import patch, AsyncMock, MagicMock, mock_open
import argparse
from start import main, process_single_domain, start
from core.cache_manager import DomainResultsCache


@pytest.fixture
def mock_cache_generator():
    mock_cache = MagicMock(spec=DomainResultsCache)
    mock_cache.get_results.return_value = None
    with patch("start.DomainResultsCache", return_value=mock_cache):
        yield mock_cache


@pytest.fixture
def mock_cache():
    return MagicMock(spec=DomainResultsCache)


@pytest.fixture
def sample_domain_info():
    return {"Domain": "example.com", "Country": "US", "Institution": "Example Corp"}


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
        "email_security": (
            {
                "example.com": {
                    "spf": {
                        "record_exists": True,
                        "valid": True,
                        "record": "v=spf1 -all",
                        "policy": "hard fail",
                        "includes": [],
                        "error": None,
                    },
                    "dkim": {
                        "record_exists": True,
                        "valid": True,
                        "record": "v=DKIM1; k=rsa; p=example_key",
                        "error": None,
                    },
                    "dmarc": {
                        "record_exists": True,
                        "valid": True,
                        "record": "v=DMARC1; p=reject; rua=mailto:",
                    },
                }
            }
        ),
    }


@pytest.mark.asyncio
async def test_process_single_domain_no_nameservers(sample_domain_info):
    with patch("start.process_domain", new_callable=AsyncMock) as mock_process_domain:
        mock_process_domain.return_value = (None, None, None)
        result = await process_single_domain(sample_domain_info)
        assert result is None


@pytest.mark.asyncio
async def test_main_single_mode(mock_cache_generator):
    test_args = ["--single", "example.com"]

    with (
        patch("sys.argv", ["script.py"] + test_args),
        patch("start.start", new_callable=AsyncMock) as mock_start,
        patch.object(argparse.ArgumentParser, "parse_args") as mock_parse_args,
    ):
        mock_parse_args.return_value = argparse.Namespace(
            single="example.com", batch=None, max_concurrent=10, ignore_cache=False
        )

        await main()
        mock_start.assert_called_once()


@pytest.mark.asyncio
async def test_main_batch_mode(mock_cache_generator):
    test_args = ["--batch", "domains.csv"]
    csv_content = "Domain,Country,Institution\nexample.com,US,Example Corp"

    with (
        patch("sys.argv", ["script.py"] + test_args),
        patch("start.start", new_callable=AsyncMock) as mock_start,
        patch("builtins.open", mock_open(read_data=csv_content)),
        patch.object(argparse.ArgumentParser, "parse_args") as mock_parse_args,
    ):
        mock_parse_args.return_value = argparse.Namespace(
            single=None, batch="domains.csv", max_concurrent=10, ignore_cache=False
        )

        await main()
        mock_start.assert_called_once()


@pytest.mark.asyncio
async def test_main_invalid_input(mock_cache_generator):
    test_args = []

    with (
        patch("sys.argv", ["script.py"] + test_args),
        patch.object(argparse.ArgumentParser, "parse_args") as mock_parse_args,
    ):
        mock_parse_args.return_value = argparse.Namespace(
            single=None, batch=None, max_concurrent=10, ignore_cache=False
        )

        await main()


@pytest.mark.asyncio
async def test_cache_integration(mock_standards_results):
    domain_info = {
        "Domain": "example.com",
        "Country": "US",
        "Institution": "Example Corp",
    }
    mock_cache = MagicMock(spec=DomainResultsCache)

    with (
        patch("start.cache", new=mock_cache),
        patch(
            "start.process_single_domain", new_callable=AsyncMock
        ) as mock_process_domain,
        patch("start.generate_html_report", new_callable=AsyncMock),
    ):
        mock_cache.get_results.return_value = None

        # Update mock_standards_results to include proper format for email_security
        email_security_results = (
            {
                "example.com": {
                    "spf": {
                        "record_exists": True,
                        "valid": True,
                        "record": "v=spf1 -all",
                        "policy": "hard fail",
                        "includes": [],
                        "error": None,
                    },
                    "dkim": {
                        "record_exists": True,
                        "valid": True,
                        "record": "v=DKIM1; k=rsa; p=example_key",
                        "error": None,
                    },
                    "dmarc": {
                        "record_exists": True,
                        "valid": True,
                        "record": "v=DMARC1; p=reject; rua=mailto:",
                    },
                }
            },
            {"example.com": {"DKIM": "valid", "DMARC": "valid", "SPF": "valid"}},
        )

        mock_process_domain.return_value = {
            "domain": "example.com",
            "country": "US",
            "institution": "Example Corp",
            "RPKI": mock_standards_results["rpki"],
            "DANE": mock_standards_results["dane"],
            "DNSSEC": mock_standards_results["dnssec"],
            "EMAIL_SECURITY": email_security_results,
        }

        await start(domain_info, "single")
        assert mock_cache.save_results.called
        assert mock_process_domain.called
