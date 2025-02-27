import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from standards import dnssec


@pytest.mark.asyncio
async def test_dnssec_validation_structure(sample_domain):
    """Test DNSSEC validation result structure."""

    mock_response = MagicMock()
    mock_response.rrset = [MagicMock()]

    mock_rrsig = MagicMock()
    mock_response.response = MagicMock()
    mock_response.response.find_rrset.return_value = [mock_rrsig]

    with patch(
        "dns.asyncresolver.Resolver.resolve", AsyncMock(return_value=mock_response)
    ):
        with patch(
            "core.utils.dns_manager.resolve_dnssec",
            AsyncMock(return_value=mock_response),
        ):
            results, state = await dnssec.run(sample_domain)

            assert isinstance(results, dict)
            assert isinstance(state, dict)
            assert sample_domain in results
            assert "dnssec_status" in results[sample_domain]

            status = results[sample_domain]["dnssec_status"]
            assert "is_signed" in status
            assert isinstance(status["is_signed"], bool)
            assert "registrar" in status
            assert "nameservers" in status


@pytest.mark.asyncio
async def test_dnssec_no_records(sample_domain, mock_dnssec_response):
    with patch.object(
        dnssec.DNSSECChecker, "check_dnssec", new_callable=AsyncMock
    ) as mock_check:
        mock_check.return_value = mock_dnssec_response(is_signed=False)

        results, state = await dnssec.run(sample_domain)

        assert sample_domain in results
        assert sample_domain in state

        status = results[sample_domain]["dnssec_status"]
        assert status["is_signed"] is False
        assert status["registrar"]["status"] == "Unsigned"
        assert status["nameservers"]["status"] == "Unsigned"
        assert len(status["registrar"]["ds_records"]) == 0
        assert len(status["nameservers"]["dnskey_records"]) == 0
        assert state[sample_domain]["DNSSEC"] is False


@pytest.mark.asyncio
async def test_dnssec_signed_records(sample_domain, mock_dnssec_response):
    """Test DNSSEC validation when records are properly signed."""
    with patch.object(
        dnssec.DNSSECChecker, "check_dnssec", new_callable=AsyncMock
    ) as mock_check:
        mock_check.return_value = mock_dnssec_response(is_signed=True)

        results, state = await dnssec.run(sample_domain)

        assert results[sample_domain]["dnssec_status"]["is_signed"] is True
        assert state[sample_domain]["DNSSEC"] is True
