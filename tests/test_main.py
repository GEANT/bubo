import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import argparse
from unittest.mock import AsyncMock, patch

import pytest

from main import DomainValidator, main


@pytest.fixture
def domain_validator(mock_cache_generator):
    with patch("main.DomainResultsCache", return_value=mock_cache_generator):
        validator = DomainValidator(
            cache_dir="test_cache",
            cache_duration=timedelta(days=1),
            routinator_url="http://localhost:8323",
        )
        return validator


@pytest.fixture
def sample_domain_info():
    return {"Domain": "example.com", "Country": "US", "Institution": "Example Corp"}


@pytest.mark.asyncio
async def test_process_single_domain(
    domain_validator, sample_domain_info, mock_standards_results
):
    standard_returns = {
        "RPKI": (
            {"example.com": {"status": True}},
            {"example.com": {"Nameserver of Domain": "valid"}},
        ),
        "DANE": (
            {"example.com": {"status": True}},
            {"example.com": {"Nameserver of Domain": "valid"}},
        ),
        "DNSSEC": (
            {"example.com": {"status": True}},
            {"example.com": {"DNSSEC": True}},
        ),
        "EMAIL_SECURITY": (
            {"example.com": {"status": True}},
            {"example.com": {"status": "valid"}},
        ),
    }

    with (
        patch(
            "core.dns.records.process_domain", new_callable=AsyncMock
        ) as mock_process_domain,
        patch(
            "main.DomainValidator.VALIDATION_TYPES", new={}
        ),  # Clear the validation types first
        patch("main.rpki.run", new_callable=AsyncMock) as mock_rpki_run,
        patch("main.dane.run", new_callable=AsyncMock) as mock_dane_run,
        patch("main.dnssec.run", new_callable=AsyncMock) as mock_dnssec_run,
        patch(
            "main.email_security.run", new_callable=AsyncMock
        ) as mock_email_security_run,
    ):
        domain_validator.VALIDATION_TYPES = {
            "RPKI": mock_rpki_run,
            "DANE": mock_dane_run,
            "DNSSEC": mock_dnssec_run,
            "EMAIL_SECURITY": mock_email_security_run,
        }

        mock_process_domain.return_value = (
            ["ns1.example.com"],
            ["mail.example.com"],
            ["ns1.mail.example.com"],
        )

        mock_rpki_run.return_value = standard_returns["RPKI"]
        mock_dane_run.return_value = standard_returns["DANE"]
        mock_dnssec_run.return_value = standard_returns["DNSSEC"]
        mock_email_security_run.return_value = standard_returns["EMAIL_SECURITY"]

        result = await domain_validator.process_single_domain(sample_domain_info)

        mock_rpki_run.assert_called_once()
        mock_dane_run.assert_called_once()
        mock_dnssec_run.assert_called_once()
        mock_email_security_run.assert_called_once()

        assert result is not None
        assert result["domain"] == "example.com"
        assert result["country"] == "US"
        assert result["institution"] == "Example Corp"
        assert all(
            key in result for key in ["RPKI", "DANE", "DNSSEC", "EMAIL_SECURITY"]
        )


@pytest.mark.asyncio
async def test_process_single_domain_no_nameservers(
    domain_validator, sample_domain_info
):
    async def mock_process_domain_impl(*args, **kwargs):
        return (None, None, None)

    with (
        patch("main.process_domain", new_callable=AsyncMock) as mock_process_domain,
        patch.object(
            domain_validator, "create_validation_tasks", new_callable=AsyncMock
        ),
    ):
        mock_process_domain.side_effect = mock_process_domain_impl
        result = await domain_validator.process_single_domain(sample_domain_info)
        assert result is None


@pytest.mark.asyncio
async def test_main_batch_mode():
    test_args = ["--batch", "domains.csv"]
    _ = "Domain,Country,Institution\nexample.com,US,Example Corp"

    def mock_process_file_impl(file_path):
        return [
            {"Domain": "example.com", "Country": "US", "Institution": "Example Corp"}
        ]

    def mock_sanitize_file_path(path):
        return path

    mock_process_file = AsyncMock(side_effect=mock_process_file_impl)

    with (
        patch("sys.argv", ["main.py"] + test_args),
        patch("main.DomainValidator") as mock_validator_class,
        patch("main.process_file", mock_process_file),
        patch("main.generate_html_report", new_callable=AsyncMock),
        patch("argparse.ArgumentParser.parse_args") as mock_parse_args,
        patch("core.io.file_processor.sanitize_file_path", mock_sanitize_file_path),
    ):
        mock_validator = AsyncMock()
        mock_validator_class.return_value = mock_validator

        mock_validator.process_domain.return_value = {
            "test": "results",
            "success": True,
            "validations": {
                "RPKI": {"results": {"example.com": "data"}, "state": {}},
                "DANE": {"results": {}, "state": {}},
                "DNSSEC": {"results": {}, "state": {}},
                "EMAIL_SECURITY": {"results": {}, "state": {}},
                "WEB_SECURITY": {"results": {}, "state": {}},
            },
            "domain_metadata": {
                "example.com": {"country": "US", "institution": "Example Corp"}
            },
        }

        mock_parse_args.return_value = argparse.Namespace(
            single=None,
            batch="nrens.csv",
            max_concurrent=10,
            ignore_cache=False,
            routinator_url="http://localhost:8323",
            output_dir="results",
        )

        await main()
