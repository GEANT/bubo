from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from standards import dnssec
from standards.dnssec import DNSSECChecker, run


@pytest.fixture(autouse=True)
def mock_dns_manager():
    # Update the import path to match the new structure
    with patch(
        "standards.dnssec.dns_manager.resolve_dnssec", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.return_value = None
        yield mock_resolve


@pytest.fixture
def mock_ds_record():
    record = MagicMock()
    record.key_tag = 12345
    record.algorithm = 8  # RSA/SHA-256
    record.digest_type = 2  # SHA-256
    record.digest = bytes.fromhex(
        "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
    )
    return record


@pytest.fixture
def mock_dnskey_record():
    record = MagicMock()
    record.flags = 257  # KSK
    record.protocol = 3
    record.algorithm = 8  # RSA/SHA-256
    record.to_text.return_value = "257 3 8 AwEAAZ2YKh5yEXJK1qRJTnTlDiTL6TfZg+DfTSYUDqlmZW7FTSC4OYuXKb71 H7URDJxv8OSWRRE5NP1ViPNjdOFeApzFwrRRxc0SyQ=="
    return record


@pytest.fixture
def mock_rrsig_record():
    record = MagicMock()
    record.type_covered = dns.rdatatype.DNSKEY
    record.algorithm = 8
    record.labels = 2
    record.original_ttl = 3600
    record.expiration = 1612137600  # Some future date
    record.inception = 1609459200  # Some past date
    record.key_tag = 12345
    record.signer = dns.name.from_text("example.com")
    record.signature = b"sample_signature"
    record.rdtype = dns.rdatatype.RRSIG
    return record


@pytest.fixture
def mock_ns_record():
    record = MagicMock()
    record.target = dns.name.from_text("ns1.example.com")
    return record


@pytest.fixture
def mock_a_record():
    record = MagicMock()
    record.address = "192.0.2.1"
    return record


@pytest.fixture
def mock_dns_response(request):
    response = MagicMock()
    rrset = MagicMock()

    if hasattr(request, "param") and "empty" in request.param:
        rrset = None
    else:
        rrset = [request.param] if hasattr(request, "param") else []

    response.rrset = rrset
    full_response = MagicMock()

    if hasattr(request, "param") and request.param == "with_answer":
        mock_rrset = MagicMock()
        full_response.answer = [mock_rrset]
    else:
        full_response.answer = []

    response.response = full_response
    response.__iter__ = lambda self: iter(rrset or [])

    return response


@pytest.mark.asyncio
async def test_dnssec_validation_structure(sample_domain):
    mock_response = MagicMock()
    mock_response.rrset = [MagicMock()]
    mock_rrsig = MagicMock()
    mock_response.response = MagicMock()
    mock_response.response.find_rrset.return_value = [mock_rrsig]

    with patch(
        "dns.asyncresolver.Resolver.resolve", AsyncMock(return_value=mock_response)
    ):
        with patch(
            "core.dns.resolver.dns_manager.resolve_dnssec",
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
    with patch.object(
        dnssec.DNSSECChecker, "check_dnssec", new_callable=AsyncMock
    ) as mock_check:
        mock_check.return_value = mock_dnssec_response(is_signed=True)
        results, state = await dnssec.run(sample_domain)

        assert results[sample_domain]["dnssec_status"]["is_signed"] is True
        assert state[sample_domain]["DNSSEC"] is True


@pytest.mark.asyncio
async def test_get_ds_records_success(mock_dns_manager, mock_ds_record):
    dns_response = MagicMock()
    dns_response.rrset = [mock_ds_record]
    mock_dns_manager.return_value = dns_response
    checker = DNSSECChecker("example.com")
    result = await checker._get_ds_records()

    assert len(result) == 1
    assert result[0]["key_tag"] == 12345
    assert result[0]["algorithm"] == 8
    assert result[0]["digest_type"] == 2
    mock_dns_manager.assert_called_once_with(
        "example.com", "DS", raise_on_no_answer=False
    )


@pytest.mark.asyncio
async def test_get_ds_records_exception(mock_dns_manager):
    mock_dns_manager.side_effect = Exception("Test exception")
    checker = DNSSECChecker("example.com")
    with pytest.raises(Exception) as excinfo:
        await checker._get_ds_records()

    assert "Error getting DS records: Test exception" in str(excinfo.value)


@pytest.mark.asyncio
async def test_get_dnskey_records_success(mock_dns_manager, mock_dnskey_record):
    dns_response = MagicMock()
    dns_response.rrset = [mock_dnskey_record]
    mock_dns_manager.return_value = dns_response

    checker = DNSSECChecker("example.com")
    result = await checker._get_dnskey_records()

    assert len(result) == 1
    assert result[0]["flags"] == 257
    assert result[0]["protocol"] == 3
    assert result[0]["algorithm"] == 8
    mock_dns_manager.assert_called_once_with(
        "example.com", "DNSKEY", raise_on_no_answer=False
    )


@pytest.mark.asyncio
async def test_get_dnskey_records_exception(mock_dns_manager):
    mock_dns_manager.side_effect = Exception("Test exception")

    checker = DNSSECChecker("example.com")

    with pytest.raises(Exception) as excinfo:
        await checker._get_dnskey_records()

    assert "Error getting DNSKEY records: Test exception" in str(excinfo.value)


@pytest.mark.asyncio
async def test_get_rrsig_records_success(mock_dns_manager, mock_rrsig_record):
    dns_response = MagicMock()
    dns_response.rrset = ["dummy_rrset"]  # Not empty

    def mock_find_rrset(section, name, rdclass, rdtype1, rdtype2=None):
        return [mock_rrsig_record]

    dns_response.response = MagicMock()
    dns_response.response.find_rrset = mock_find_rrset
    mock_dns_manager.return_value = dns_response

    checker = DNSSECChecker("example.com")
    result = await checker._get_rrsig_records()

    assert len(result) == 1
    assert result[0]["type_covered"] == "DNSKEY"
    assert result[0]["algorithm"] == 8
    mock_dns_manager.assert_called_once_with(
        "example.com", "DNSKEY", raise_on_no_answer=False
    )


@pytest.mark.asyncio
async def test_get_rrsig_records_no_records(mock_dns_manager):
    dns_response = MagicMock()
    dns_response.rrset = None
    dns_response.response = None
    mock_dns_manager.return_value = dns_response
    checker = DNSSECChecker("example.com")
    result = await checker._get_rrsig_records()

    assert result == []


@pytest.mark.asyncio
async def test_get_rrsig_records_exception(mock_dns_manager):
    mock_dns_manager.side_effect = Exception("Test exception")
    checker = DNSSECChecker("example.com")

    with pytest.raises(Exception) as excinfo:
        await checker._get_rrsig_records()

    assert "Error getting RRSIG records: Test exception" in str(excinfo.value)


@pytest.mark.asyncio
async def test_check_dnssec_fully_signed(
    mock_dns_manager, mock_ds_record, mock_dnskey_record, mock_rrsig_record
):
    checker = DNSSECChecker("example.com")

    with (
        patch.object(checker, "_verify_chain", new_callable=AsyncMock),
        patch.object(checker, "_get_ds_records", new_callable=AsyncMock) as mock_get_ds,
        patch.object(
            checker, "_get_dnskey_records", new_callable=AsyncMock
        ) as mock_get_dnskey,
        patch.object(
            checker, "_get_rrsig_records", new_callable=AsyncMock
        ) as mock_get_rrsig,
    ):
        mock_get_ds.return_value = [
            {"key_tag": 12345, "algorithm": 8, "digest_type": 2, "digest": "1a2b3c4d"}
        ]
        mock_get_dnskey.return_value = [
            {"flags": 257, "protocol": 3, "algorithm": 8, "key": "DNSKEY data"}
        ]
        mock_get_rrsig.return_value = [{"type_covered": "DNSKEY", "algorithm": 8}]

        result = await checker.check_dnssec()

        assert result["dnssec_status"]["is_signed"] is True
        assert result["dnssec_status"]["registrar"]["status"] == "FullySigned"
        assert result["dnssec_status"]["nameservers"]["status"] == "Signed"
        assert len(result["dnssec_status"]["registrar"]["ds_records"]) == 1
        assert len(result["dnssec_status"]["nameservers"]["dnskey_records"]) == 1
        assert len(result["dnssec_status"]["nameservers"]["rrsig_records"]) == 1


@pytest.mark.asyncio
async def test_check_dnssec_registrar_unsigned(mock_dns_manager):
    checker = DNSSECChecker("example.com")

    with (
        patch.object(checker, "_verify_chain", new_callable=AsyncMock),
        patch.object(checker, "_get_ds_records", new_callable=AsyncMock) as mock_get_ds,
        patch.object(
            checker, "_get_dnskey_records", new_callable=AsyncMock
        ) as mock_get_dnskey,
        patch.object(
            checker, "_get_rrsig_records", new_callable=AsyncMock
        ) as mock_get_rrsig,
    ):
        # Set up return values - no DS records but DNSKEY records exist
        mock_get_ds.return_value = []
        mock_get_dnskey.return_value = [
            {"flags": 257, "protocol": 3, "algorithm": 8, "key": "DNSKEY data"}
        ]
        mock_get_rrsig.return_value = [{"type_covered": "DNSKEY", "algorithm": 8}]

        result = await checker.check_dnssec()

        # Verify the result
        assert result["dnssec_status"]["is_signed"] is True  # Domain has DNSKEYs
        assert (
            result["dnssec_status"]["registrar"]["status"] == "Unsigned"
        )  # No DS records
        assert (
            result["dnssec_status"]["nameservers"]["status"] == "Signed"
        )  # Has DNSKEY records


@pytest.mark.asyncio
async def test_check_dnssec_fully_unsigned(mock_dns_manager):
    checker = DNSSECChecker("example.com")

    with (
        patch.object(checker, "_verify_chain", new_callable=AsyncMock),
        patch.object(checker, "_get_ds_records", new_callable=AsyncMock) as mock_get_ds,
        patch.object(
            checker, "_get_dnskey_records", new_callable=AsyncMock
        ) as mock_get_dnskey,
        patch.object(
            checker, "_get_rrsig_records", new_callable=AsyncMock
        ) as mock_get_rrsig,
    ):
        mock_get_ds.return_value = []
        mock_get_dnskey.return_value = []
        mock_get_rrsig.return_value = []
        result = await checker.check_dnssec()

        assert result["dnssec_status"]["is_signed"] is False
        assert result["dnssec_status"]["registrar"]["status"] == "Unsigned"
        assert result["dnssec_status"]["nameservers"]["status"] == "Unsigned"


@pytest.mark.asyncio
async def test_check_dnssec_exception(mock_dns_manager):
    checker = DNSSECChecker("example.com")

    with patch.object(
        checker, "_verify_chain", new_callable=AsyncMock
    ) as mock_verify_chain:
        mock_verify_chain.side_effect = Exception("Test verification exception")

        result = await checker.check_dnssec()

        assert "Test verification exception" in result["error"]
        assert result["dnssec_status"]["is_signed"] is False


@pytest.mark.asyncio
async def test_verify_chain(mock_dns_manager):
    checker = DNSSECChecker("example.com")
    with (
        patch.object(
            checker, "_verify_zone", new_callable=AsyncMock
        ) as mock_verify_zone,
        patch.object(
            checker, "_get_auth_nameservers", new_callable=AsyncMock
        ) as mock_get_auth_ns,
        patch.object(
            checker, "_verify_a_records", new_callable=AsyncMock
        ) as mock_verify_a,
    ):
        mock_verify_zone.return_value = {
            "zone": "example.com",
            "dnskey_records": ["DNSKEY1"],
        }
        mock_get_auth_ns.return_value = ["ns1.example.com", "ns2.example.com"]
        mock_verify_a.return_value = {
            "zone": "example.com",
            "nameserver": "ns1.example.com",
            "a_records": ["192.0.2.1"],
        }

        await checker._verify_chain()
        assert len(checker.verification_chain) > 0
        assert mock_verify_zone.call_count == 3  # ".", "com", "example.com"

        mock_get_auth_ns.assert_called_once_with("example.com")

        assert mock_verify_a.call_count == 2  # For ns1.example.com and ns2.example.com


@pytest.mark.asyncio
async def test_verify_zone_root(
    mock_dns_manager, mock_dnskey_record, mock_rrsig_record
):
    checker = DNSSECChecker("example.com")
    dns_response = MagicMock()
    dns_response.rrset = [mock_dnskey_record]
    answer_rrset = MagicMock()
    rrsigs = [mock_rrsig_record]
    answer_rrset.__iter__ = lambda self: iter(rrsigs)
    dns_response.response = MagicMock()
    dns_response.response.answer = [answer_rrset]
    mock_dns_manager.return_value = dns_response
    result = await checker._verify_zone(".")

    assert result["zone"] == "."
    assert len(result["dnskey_records"]) > 0
    assert len(result["rrsig_info"]) > 0


@pytest.mark.asyncio
async def test_verify_zone_with_ds(
    mock_dns_manager, mock_dnskey_record, mock_ds_record, mock_rrsig_record
):
    checker = DNSSECChecker("example.com")
    dnskey_response = MagicMock()
    dnskey_response.rrset = [mock_dnskey_record]
    answer_rrset = MagicMock()
    rrsigs = [mock_rrsig_record]
    answer_rrset.__iter__ = lambda self: iter(rrsigs)
    dnskey_response.response = MagicMock()
    dnskey_response.response.answer = [answer_rrset]
    ds_response = MagicMock()
    ds_response.rrset = [mock_ds_record]
    ds_response.__iter__ = lambda self: iter([mock_ds_record])

    async def mock_resolve_dnssec(zone, record_type, raise_on_no_answer=True):
        if record_type == "DNSKEY":
            return dnskey_response
        elif record_type == "DS":
            return ds_response
        return None

    mock_dns_manager.side_effect = mock_resolve_dnssec

    with (
        patch("dns.dnssec.key_id", return_value=12345),
        patch("dns.dnssec.algorithm_to_text", return_value="RSA-SHA256"),
    ):
        result = await checker._verify_zone("example.com")

        assert result["zone"] == "example.com"
        assert len(result["dnskey_records"]) > 0
        assert len(result["ds_records"]) > 0
        assert len(result["rrsig_info"]) > 0


@pytest.mark.asyncio
async def test_verify_zone_exception(mock_dns_manager):
    checker = DNSSECChecker("example.com")
    mock_dns_manager.side_effect = Exception("Test exception")
    result = await checker._verify_zone("example.com")

    assert "error" in result
    assert "Test exception" in result["error"]


@pytest.mark.asyncio
async def test_get_auth_nameservers(mock_dns_manager, mock_ns_record):
    checker = DNSSECChecker("example.com")
    dns_response = MagicMock()
    dns_response.__iter__ = lambda self: iter([mock_ns_record])

    mock_dns_manager.return_value = dns_response
    result = await checker._get_auth_nameservers("example.com")

    assert len(result) == 1
    assert result[0] == "ns1.example.com."
    mock_dns_manager.assert_called_once_with("example.com", "NS")


@pytest.mark.asyncio
async def test_get_auth_nameservers_exception(mock_dns_manager):
    checker = DNSSECChecker("example.com")
    mock_dns_manager.side_effect = Exception("Test exception")
    result = await checker._get_auth_nameservers("example.com")
    assert result == []


@pytest.mark.asyncio
async def test_verify_a_records(mock_dns_manager, mock_a_record, mock_rrsig_record):
    checker = DNSSECChecker("example.com")
    dns_response = MagicMock()
    dns_response.__iter__ = lambda self: iter([mock_a_record])
    answer_rrset = MagicMock()
    rrsigs = [mock_rrsig_record]
    answer_rrset.__iter__ = lambda self: iter(rrsigs)
    dns_response.response = MagicMock()
    dns_response.response.answer = [answer_rrset]
    mock_dns_manager.return_value = dns_response
    result = await checker._verify_a_records("example.com", "ns1.example.com")

    assert result["zone"] == "example.com"
    assert result["nameserver"] == "ns1.example.com"
    assert len(result["a_records"]) > 0
    assert len(result["rrsig_info"]) > 0
    mock_dns_manager.assert_called_once_with("example.com", "A")


@pytest.mark.asyncio
async def test_verify_a_records_exception(mock_dns_manager):
    checker = DNSSECChecker("example.com")
    mock_dns_manager.side_effect = Exception("Test exception")
    result = await checker._verify_a_records("example.com", "ns1.example.com")

    assert "error" in result
    assert "Test exception" in result["error"]


@pytest.mark.asyncio
async def test_run_success():
    expected_result = {
        "root_domain": "example.com",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dnssec_status": {
            "is_signed": True,
            "registrar": {"status": "FullySigned", "ds_records": [{"key_tag": 12345}]},
            "nameservers": {
                "status": "Signed",
                "dnskey_records": [{"flags": 257}],
                "rrsig_records": [{"type_covered": "DNSKEY"}],
            },
        },
        "verification_chain": [{"zone": ".", "dnskey_records": ["DNSKEY1"]}],
    }

    with patch(
        "standards.dnssec.DNSSECChecker.check_dnssec", new_callable=AsyncMock
    ) as mock_check:
        mock_check.return_value = expected_result
        results, state = await run("example.com")

        assert "example.com" in results
        assert results["example.com"] == expected_result
        assert state["example.com"]["DNSSEC"] is True


@pytest.mark.asyncio
async def test_run_exception():
    with patch(
        "standards.dnssec.DNSSECChecker.check_dnssec", new_callable=AsyncMock
    ) as mock_check:
        mock_check.side_effect = Exception("Test exception")
        results, state = await run("example.com")

        assert "example.com" in results
        assert "error" in results["example.com"]
        assert "Test exception" in results["example.com"]["error"]
        assert state["example.com"]["DNSSEC"] is False
        assert "error" in state["example.com"]
