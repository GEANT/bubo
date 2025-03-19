import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import dns.resolver
import dns.exception

from standards.email_security import (
    get_txt_records,
    check_dkim_selector,
    check_dkim,
    check_dmarc,
    run,
    COMMON_DKIM_SELECTORS,
)


@pytest.fixture(autouse=True)
def mock_dns_manager():
    with patch(
        "core.utils.dns_manager.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        # Default behavior - return empty list to avoid errors
        mock_resolve.return_value = []
        yield mock_resolve


@pytest.fixture
def mock_dns_answer():
    record = MagicMock()
    record.strings = [b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"]
    return [record]


@pytest.fixture
def mock_dmarc_answer():
    record = MagicMock()
    record.strings = [
        b"v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:reports@example.com"
    ]
    return [record]


@pytest.fixture
def mock_invalid_dmarc_answer():
    record = MagicMock()
    record.strings = [b"v=DMARC1; p=none; pct=50;"]
    return [record]


@pytest.fixture
def mock_multiple_dmarc_answer():
    record1 = MagicMock()
    record1.strings = [b"v=DMARC1; p=reject;"]
    record2 = MagicMock()
    record2.strings = [b"v=DMARC1; p=quarantine;"]
    return [record1, record2]


@pytest.mark.asyncio
async def test_get_txt_records_success(mock_dns_answer):
    with patch(
        "standards.email_security.dns_manager.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.return_value = mock_dns_answer
        result = await get_txt_records("example.com")
        assert result == ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"]
        mock_resolve.assert_called_once_with("example.com", "TXT")


@pytest.mark.asyncio
async def test_get_txt_records_nxdomain():
    with patch(
        "standards.email_security.dns_manager.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        result = await get_txt_records("nonexistent.com", "test")
        assert result == []


@pytest.mark.asyncio
async def test_get_txt_records_noanswer():
    with patch(
        "standards.email_security.dns_manager.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer()
        result = await get_txt_records("example.com", "test")
        assert result == []


@pytest.mark.asyncio
async def test_get_txt_records_exception():
    with patch(
        "standards.email_security.dns_manager.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.side_effect = Exception("Test exception")
        result = await get_txt_records("example.com", "test")
        assert result == []


@pytest.mark.asyncio
async def test_check_dkim_selector_valid(mock_dns_answer):
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = [
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
        ]
        result = await check_dkim_selector("example.com", "selector1")
        assert result == {
            "record": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
            "valid": True,
            "selector": "selector1",
        }
        mock_get_txt.assert_called_once_with("selector1._domainkey.example.com", "dkim")


@pytest.mark.asyncio
async def test_check_dkim_selector_invalid():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = [
            "v=spf1 include:_spf.example.com ~all"
        ]  # Not a DKIM record
        result = await check_dkim_selector("example.com", "selector1")
        assert result is None


@pytest.mark.asyncio
async def test_check_dkim_selector_no_records():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = []
        result = await check_dkim_selector("example.com", "selector1")
        assert result is None


@pytest.mark.asyncio
async def test_check_dkim_valid_selectors():
    valid_selector = {
        "record": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
        "valid": True,
        "selector": "selector1",
    }

    with patch(
        "standards.email_security.check_dkim_selector", new_callable=AsyncMock
    ) as mock_check_selector:

        async def side_effect(domain, selector):
            if selector == "selector1":
                return valid_selector
            return None

        mock_check_selector.side_effect = side_effect

        result = await check_dkim("example.com")

        assert result["valid"] is True
        assert result["selectors_found"] == ["selector1"]
        assert result["records"] == {
            "selector1": {
                "record": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
                "valid": True,
            }
        }
        assert result["error"] is None
        assert mock_check_selector.call_count == len(COMMON_DKIM_SELECTORS)


@pytest.mark.asyncio
async def test_check_dkim_no_valid_selectors():
    with patch(
        "standards.email_security.check_dkim_selector", new_callable=AsyncMock
    ) as mock_check_selector:
        mock_check_selector.return_value = None

        result = await check_dkim("example.com")

        assert result["valid"] is False
        assert result["selectors_found"] == []
        assert result["records"] == {}
        assert result["error"] == "No DKIM records found with common selectors"
        assert mock_check_selector.call_count == len(COMMON_DKIM_SELECTORS)


@pytest.mark.asyncio
async def test_check_dkim_exception():
    with patch(
        "standards.email_security.check_dkim_selector", new_callable=AsyncMock
    ) as mock_check_selector:
        mock_check_selector.side_effect = Exception("Test exception")

        result = await check_dkim("example.com")

        assert result["valid"] is False
        assert "Test exception" in result["error"]


@pytest.mark.asyncio
async def test_check_dmarc_valid(mock_dmarc_answer):
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = [
            "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:reports@example.com"
        ]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is True
        assert (
            result["record"]
            == "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:reports@example.com"
        )
        assert result["policy"] == "reject"
        assert result["sub_policy"] == "quarantine"
        assert result["percentage"] == 100
        assert result["error"] is None
        assert result["warnings"] == []


@pytest.mark.asyncio
async def test_check_dmarc_invalid_policy():
    """Test checking DMARC with 'none' policy."""
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; p=none; pct=100;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["policy"] == "none"
        assert (
            result["error"]
            == "Policy 'none' is insufficient to prevent domain abuse. It should be 'reject' or 'quarantine' to be effective and strict."
        )


@pytest.mark.asyncio
async def test_check_dmarc_partial_enforcement():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; p=quarantine; pct=50;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is True
        assert result["policy"] == "quarantine"
        assert result["percentage"] == 50
        assert (
            "Partial DMARC enforcement (50%) may reduce effectiveness"
            in result["warnings"]
        )


@pytest.mark.asyncio
async def test_check_dmarc_subdomain_none_policy():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; p=reject; sp=none; pct=100;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is True
        assert result["policy"] == "reject"
        assert result["sub_policy"] == "none"
        assert (
            "Subdomain policy 'none' may allow domain abuse via subdomains"
            in result["warnings"]
        )


@pytest.mark.asyncio
async def test_check_dmarc_missing_record():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = []

        result = await check_dmarc("example.com")

        assert result["record_exists"] is False
        assert result["valid"] is False
        assert result["error"] == "No DMARC record found"


@pytest.mark.asyncio
async def test_check_dmarc_multiple_records():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = [
            "v=DMARC1; p=reject; pct=100;",
            "v=DMARC1; p=quarantine; pct=100;",
        ]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["error"] == "Multiple DMARC records found"


@pytest.mark.asyncio
async def test_check_dmarc_invalid_syntax():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1 p=reject pct=100"]  # Missing semicolons

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["error"] == "Invalid DMARC syntax"


@pytest.mark.asyncio
async def test_check_dmarc_missing_policy():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; pct=100;"]  # Missing p tag

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["error"] == "Missing required policy (p) tag"


@pytest.mark.asyncio
async def test_check_dmarc_invalid_percentage():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = [
            "v=DMARC1; p=reject; pct=101;"
        ]  # Invalid pct value

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["error"] == "Invalid percentage value: 101"


@pytest.mark.asyncio
async def test_check_dmarc_exception():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.side_effect = Exception("Test exception")
        result = await check_dmarc("example.com")

        assert result["valid"] is False
        assert "Test exception" in result["error"]


@pytest.mark.asyncio
async def test_run_success():
    spf_result = {"valid": True, "record": "v=spf1 include:_spf.example.com ~all"}
    dkim_result = {
        "selectors_found": ["selector1"],
        "records": {"selector1": {"record": "v=DKIM1; k=rsa;", "valid": True}},
        "valid": True,
        "error": None,
    }
    dmarc_result = {
        "record_exists": True,
        "valid": True,
        "record": "v=DMARC1; p=reject; pct=100;",
        "policy": "reject",
        "sub_policy": "reject",
        "percentage": 100,
        "error": None,
        "warnings": [],
    }

    with (
        patch("standards.email_security.check_spf", new_callable=AsyncMock) as mock_spf,
        patch(
            "standards.email_security.check_dkim", new_callable=AsyncMock
        ) as mock_dkim,
        patch(
            "standards.email_security.check_dmarc", new_callable=AsyncMock
        ) as mock_dmarc,
    ):
        mock_spf.return_value = spf_result
        mock_dkim.return_value = dkim_result
        mock_dmarc.return_value = dmarc_result

        results, state = await run("example.com")

        assert "example.com" in results
        assert results["example.com"]["spf"] == spf_result
        assert results["example.com"]["dkim"] == dkim_result
        assert results["example.com"]["dmarc"] == dmarc_result

        assert state["example.com"]["SPF"] == "valid"
        assert state["example.com"]["DKIM"] == "valid"
        assert state["example.com"]["DMARC"] == "valid"


@pytest.mark.asyncio
async def test_run_with_invalid_checks():
    spf_result = {"valid": False, "record": "v=spf1 -all"}
    dkim_result = {
        "selectors_found": [],
        "records": {},
        "valid": False,
        "error": "No DKIM records found with common selectors",
    }
    dmarc_result = {
        "record_exists": True,
        "valid": False,
        "record": "v=DMARC1; p=none;",
        "policy": "none",
        "sub_policy": "none",
        "percentage": 100,
        "error": "Policy 'none' is insufficient to prevent domain abuse",
        "warnings": [],
    }

    with (
        patch("standards.email_security.check_spf", new_callable=AsyncMock) as mock_spf,
        patch(
            "standards.email_security.check_dkim", new_callable=AsyncMock
        ) as mock_dkim,
        patch(
            "standards.email_security.check_dmarc", new_callable=AsyncMock
        ) as mock_dmarc,
    ):
        mock_spf.return_value = spf_result
        mock_dkim.return_value = dkim_result
        mock_dmarc.return_value = dmarc_result

        results, state = await run("example.com")

        assert state["example.com"]["SPF"] == "not-valid"
        assert state["example.com"]["DKIM"] == "not-valid"
        assert state["example.com"]["DMARC"] == "not-valid"


@pytest.mark.asyncio
async def test_run_exception():
    with patch(
        "standards.email_security.check_spf", new_callable=AsyncMock
    ) as mock_spf:
        mock_spf.side_effect = Exception("Test exception")

        results, state = await run("example.com")

        # Both dictionaries should be empty due to the exception
        assert results == {}
        assert state == {}
