import pytest
from unittest.mock import AsyncMock, patch
from standards import dane
import dns


@pytest.mark.asyncio
async def test_check_tlsa_record_with_records():
    with patch(
        "dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        mock_answer = AsyncMock()
        mock_answer.to_text = lambda: "3 1 1 hash_value"
        mock_resolve.return_value = [mock_answer]

        result = await dane.check_tlsa_record("example.com", 443)
        assert result == ["3 1 1 hash_value"]


@pytest.mark.asyncio
async def test_check_tlsa_record_no_records():
    with patch(
        "dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.side_effect = dns.exception.DNSException()
        result = await dane.check_tlsa_record("example.com", 443)
        assert result == []


@pytest.mark.asyncio
async def test_validate_tlsa_hash_success():
    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_proc:
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (b"Verification: OK", b"")
        mock_proc.return_value = process_mock

        result = await dane.validate_tlsa_hash(
            "example.com", 443, "3 1 1 hash_value", "ns1.example.com"
        )
        assert result is True


@pytest.mark.asyncio
async def test_validate_tlsa_hash_failure():
    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_proc:
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (b"Verification: Failed", b"")
        mock_proc.return_value = process_mock

        result = await dane.validate_tlsa_hash(
            "example.com", 443, "3 1 1 hash_value", "ns1.example.com"
        )
        assert result is False


@pytest.mark.asyncio
async def test_process_servers_with_valid_records(mock_dane_valid):
    with (
        patch("standards.dane.check_tlsa_record", new_callable=AsyncMock) as mock_check,
        patch(
            "standards.dane.validate_tlsa_hash", new_callable=AsyncMock
        ) as mock_validate,
    ):
        await mock_dane_valid(mock_check, mock_validate)
        servers = ["ns1.example.com"]
        results = await dane.process_servers("example.com", servers, 443, "domain_ns")

        assert "ns1.example.com" in results
        assert results["ns1.example.com"]["validation"] is True
        assert len(results["ns1.example.com"]["tlsa_records"]) == 1


@pytest.mark.asyncio
async def test_process_servers_no_records():
    with patch(
        "standards.dane.check_tlsa_record", new_callable=AsyncMock
    ) as mock_check:
        mock_check.return_value = []
        servers = ["ns1.example.com"]
        results = await dane.process_servers("example.com", servers, 443, "domain_ns")

        assert "ns1.example.com" in results
        assert results["ns1.example.com"]["validation"] is False
        assert len(results["ns1.example.com"]["tlsa_records"]) == 0


@pytest.mark.asyncio
async def test_run_successful_validation(sample_domain, sample_servers):
    with patch(
        "standards.dane.process_servers", new_callable=AsyncMock
    ) as mock_process:
        mock_process.return_value = {
            "ns1.example.com": {
                "tlsa_records": [{"record": "3 1 1 hash_value", "valid": True}],
                "validation": True,
            }
        }

        results, state = await dane.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        assert sample_domain in results
        assert state[sample_domain]["Nameserver of Domain"] == "valid"


@pytest.mark.asyncio
async def test_run_failed_validation(sample_domain, sample_servers):
    with patch(
        "standards.dane.process_servers", new_callable=AsyncMock
    ) as mock_process:
        mock_process.side_effect = [
            {"ns1.example.com": {"tlsa_records": [], "validation": False}},
            {"mail.example.com": {"tlsa_records": [], "validation": False}},
            {"ns1.mail.example.com": {"tlsa_records": [], "validation": False}},
        ]

        results, state = await dane.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        assert sample_domain in results
        assert state[sample_domain]["Nameserver of Domain"] == "not-valid"
