import pytest
from unittest.mock import AsyncMock, patch
from standards import rpki, dane, dnssec


@pytest.mark.asyncio
async def test_integration_all_valid(
    sample_domain,
    sample_servers,
    mock_rpki_valid,
    mock_dane_valid,
    mock_dnssec_response,
):
    """Test integration when all standards pass validation."""
    with (
        patch(
            "standards.rpki.validate_rpki", new_callable=AsyncMock
        ) as mock_rpki_validate,
        patch(
            "standards.rpki.resolve_ips", new_callable=AsyncMock
        ) as mock_rpki_resolve,
        patch(
            "standards.rpki.get_asn_and_prefix", new_callable=AsyncMock
        ) as mock_rpki_asn,
        patch(
            "standards.dane.check_tlsa_record", new_callable=AsyncMock
        ) as mock_dane_tlsa,
        patch(
            "standards.dane.validate_tlsa_hash", new_callable=AsyncMock
        ) as mock_dane_validate,
        patch.object(
            dnssec.DNSSECChecker, "check_dnssec", new_callable=AsyncMock
        ) as mock_dnssec,
    ):
        await mock_rpki_valid(mock_rpki_validate, mock_rpki_resolve, mock_rpki_asn)
        await mock_dane_valid(mock_dane_tlsa, mock_dane_validate)
        mock_dnssec.return_value = mock_dnssec_response(is_signed=True)

        rpki_results, rpki_state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        dane_results, dane_state = await dane.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        dnssec_results, dnssec_state = await dnssec.run(sample_domain)

        assert (
            set(rpki_results.keys())
            == set(dane_results.keys())
            == set(dnssec_results.keys())
            == {sample_domain}
        )
        assert rpki_state[sample_domain]["Nameserver of Domain"] == "valid"
        assert dane_state[sample_domain]["Nameserver of Domain"] == "valid"
        assert dnssec_state[sample_domain]["DNSSEC"] is True


@pytest.mark.asyncio
async def test_integration_mixed_results(
    sample_domain,
    sample_servers,
    mock_rpki_valid,
    mock_dane_valid,
    mock_dnssec_response,
):
    """Test integration with mixed validation results."""
    with (
        patch(
            "standards.rpki.validate_rpki", new_callable=AsyncMock
        ) as mock_rpki_validate,
        patch(
            "standards.rpki.resolve_ips", new_callable=AsyncMock
        ) as mock_rpki_resolve,
        patch(
            "standards.rpki.get_asn_and_prefix", new_callable=AsyncMock
        ) as mock_rpki_asn,
        patch(
            "standards.dane.check_tlsa_record", new_callable=AsyncMock
        ) as mock_dane_tlsa,
        patch(
            "standards.dane.validate_tlsa_hash", new_callable=AsyncMock
        ) as mock_dane_validate,
        patch.object(
            dnssec.DNSSECChecker, "check_dnssec", new_callable=AsyncMock
        ) as mock_dnssec,
    ):
        # Mixed results setup
        mock_rpki_validate.return_value = {
            "validated_route": {"validity": {"state": "invalid"}}
        }
        mock_rpki_resolve.return_value = (["192.0.2.1"], ["2001:db8::1"])
        mock_rpki_asn.return_value = ("AS64496", "192.0.2.0/24")

        await mock_dane_valid(mock_dane_tlsa, mock_dane_validate)
        mock_dnssec.return_value = mock_dnssec_response(is_signed=False)

        rpki_results, rpki_state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        dane_results, dane_state = await dane.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        dnssec_results, dnssec_state = await dnssec.run(sample_domain)

        assert rpki_state[sample_domain]["Nameserver of Domain"] == "not-valid"
        assert dane_state[sample_domain]["Nameserver of Domain"] == "valid"
        assert dnssec_state[sample_domain]["DNSSEC"] is False


@pytest.mark.asyncio
async def test_integration_result_structure(
    sample_domain,
    sample_servers,
    mock_rpki_valid,
    mock_dane_valid,
    mock_dnssec_response,
):
    """Test the structure of results from all validations."""
    with (
        patch(
            "standards.rpki.validate_rpki", new_callable=AsyncMock
        ) as mock_rpki_validate,
        patch(
            "standards.rpki.resolve_ips", new_callable=AsyncMock
        ) as mock_rpki_resolve,
        patch(
            "standards.rpki.get_asn_and_prefix", new_callable=AsyncMock
        ) as mock_rpki_asn,
        patch(
            "standards.dane.check_tlsa_record", new_callable=AsyncMock
        ) as mock_dane_tlsa,
        patch(
            "standards.dane.validate_tlsa_hash", new_callable=AsyncMock
        ) as mock_dane_validate,
        patch.object(
            dnssec.DNSSECChecker, "check_dnssec", new_callable=AsyncMock
        ) as mock_dnssec,
    ):
        await mock_rpki_valid(mock_rpki_validate, mock_rpki_resolve, mock_rpki_asn)
        await mock_dane_valid(mock_dane_tlsa, mock_dane_validate)
        mock_dnssec.return_value = mock_dnssec_response(is_signed=True)

        rpki_results, rpki_state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        dane_results, dane_state = await dane.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        dnssec_results, dnssec_state = await dnssec.run(sample_domain)

        for results in [rpki_results, dane_results, dnssec_results]:
            assert isinstance(results, dict)
            assert sample_domain in results

        for results in [rpki_results, dane_results]:
            assert all(
                key in results[sample_domain]
                for key in ["domain_ns", "domain_mx", "mailserver_ns"]
            )

        assert "dnssec_status" in dnssec_results[sample_domain]
        assert "DNSSEC" in dnssec_state[sample_domain]
