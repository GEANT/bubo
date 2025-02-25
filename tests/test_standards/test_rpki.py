import pytest
from unittest.mock import AsyncMock, patch
from standards import rpki


@pytest.mark.asyncio
async def test_rpki_validation_structure(
    sample_domain, sample_servers, mock_rpki_valid
):
    """Test RPKI validation result structure."""
    with (
        patch("standards.rpki.validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch("standards.rpki.resolve_ips", new_callable=AsyncMock) as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix", new_callable=AsyncMock) as mock_asn,
    ):
        await mock_rpki_valid(mock_validate, mock_resolve, mock_asn)

        results, state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        assert isinstance(results, dict)
        assert isinstance(state, dict)
        assert sample_domain in results
        assert any(
            key in results[sample_domain]
            for key in ["domain_ns", "domain_mx", "mailserver_ns"]
        )

        for server_type, status in state[sample_domain].items():
            assert status in ["valid", "not-valid", "partially-valid", None]


@pytest.mark.asyncio
async def test_rpki_dns_resolution_failure(
    sample_domain, sample_servers, mock_rpki_valid_response
):
    """Test RPKI validation when DNS resolution fails."""
    with (
        patch("standards.rpki.validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch("standards.rpki.resolve_ips", new_callable=AsyncMock) as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix", new_callable=AsyncMock) as mock_asn,
    ):
        mock_resolve.return_value = ([], ["No IPv6"])
        mock_validate.return_value = mock_rpki_valid_response
        mock_asn.return_value = ("AS1103", "195.169.124.0/24")

        results, state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        for server_type in results[sample_domain].values():
            for server_data in server_type.values():
                assert "message" in server_data
                assert "No IPv4 addresses found" in server_data["message"]


@pytest.mark.asyncio
async def test_rpki_asn_lookup_failure(
    sample_domain, sample_servers, mock_rpki_valid_response
):
    """Test RPKI validation when ASN lookup fails."""
    with (
        patch("standards.rpki.validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch("standards.rpki.resolve_ips", new_callable=AsyncMock) as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix", new_callable=AsyncMock) as mock_asn,
    ):
        mock_resolve.return_value = (["192.0.2.1"], ["2001:db8::1"])
        mock_asn.return_value = (None, None)
        mock_validate.return_value = mock_rpki_valid_response

        results, state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        for server_type in results[sample_domain].values():
            for server_data in server_type.values():
                if "message" in server_data:
                    assert "No valid RPKI information found" in server_data["message"]


@pytest.mark.asyncio
async def test_rpki_mixed_validation_states(sample_domain, sample_servers):
    """Test RPKI validation with mixed states."""
    with (
        patch("standards.rpki.validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch("standards.rpki.resolve_ips", new_callable=AsyncMock) as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix", new_callable=AsyncMock) as mock_asn,
    ):
        mock_resolve.return_value = (["192.0.2.1"], ["2001:db8::1"])
        mock_asn.return_value = ("AS64496", "192.0.2.0/24")

        # Create enough responses for all servers (ns1, ns2, mail, and mail_ns)
        mock_validate.side_effect = [
            {"validated_route": {"validity": {"state": "valid"}}},  # ns1
            {"validated_route": {"validity": {"state": "invalid"}}},  # ns2
            {"validated_route": {"validity": {"state": "valid"}}},  # mail
            {"validated_route": {"validity": {"state": "valid"}}},  # mail_ns
        ] * 3  # Multiply to ensure enough responses

        results, state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        assert state[sample_domain]["Nameserver of Domain"] == "partially-valid"
