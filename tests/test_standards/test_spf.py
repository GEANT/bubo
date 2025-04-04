import pytest
import asyncio
from unittest.mock import patch, AsyncMock

from standards.spf import (
    get_spf_record,
    parse_spf_record,
    count_dns_lookups,
    check_policy_strictness,
    check_spf,
    check_domains,
    MAX_DNS_LOOKUPS,
)


class MockDNSRecord:
    def __init__(self, strings):
        self.strings = strings


@pytest.fixture
def mock_dns_manager():
    # Update the patch path to match the new import in standards.spf
    with patch("standards.spf.dns_manager") as mock_dns:
        yield mock_dns


@pytest.mark.asyncio
async def test_get_spf_record_success(mock_dns_manager):
    domain = "example.com"
    spf_txt = "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.123 a -all"
    mock_record = MockDNSRecord([spf_txt.encode()])

    mock_dns_manager.resolve = AsyncMock(return_value=[mock_record])

    result = await get_spf_record(domain)

    assert result == spf_txt
    mock_dns_manager.resolve.assert_called_once_with(domain, "TXT")


@pytest.mark.asyncio
async def test_get_spf_record_multiple_txt_records(mock_dns_manager):
    domain = "example.com"
    spf_txt = "v=spf1 ip4:192.0.2.0/24 -all"
    other_txt = "Some other TXT record"

    mock_records = [
        MockDNSRecord([other_txt.encode()]),
        MockDNSRecord([spf_txt.encode()]),
    ]

    mock_dns_manager.resolve = AsyncMock(return_value=mock_records)

    result = await get_spf_record(domain)

    assert result == spf_txt


@pytest.mark.asyncio
async def test_get_spf_record_multipart_string(mock_dns_manager):
    domain = "example.com"
    spf_part1 = "v=spf1 ip4:192.0.2.0/24 "
    spf_part2 = "ip4:198.51.100.123 -all"

    mock_record = MockDNSRecord([spf_part1.encode(), spf_part2.encode()])

    mock_dns_manager.resolve = AsyncMock(return_value=[mock_record])

    result = await get_spf_record(domain)

    assert result == spf_part1 + spf_part2


@pytest.mark.asyncio
async def test_get_spf_record_fallback_to_spf_type(mock_dns_manager):
    domain = "example.com"
    spf_txt = "v=spf1 ip4:192.0.2.0/24 -all"

    mock_dns_manager.resolve = AsyncMock(
        side_effect=[
            [MockDNSRecord(["some-other-txt".encode()])],
            [MockDNSRecord([spf_txt.encode()])],
        ]
    )

    result = await get_spf_record(domain)

    assert result == spf_txt
    assert mock_dns_manager.resolve.call_count == 2
    assert mock_dns_manager.resolve.call_args_list[0][0] == (domain, "TXT")
    assert mock_dns_manager.resolve.call_args_list[1][0] == (domain, "SPF")


@pytest.mark.asyncio
async def test_get_spf_record_no_record(mock_dns_manager):
    domain = "example.com"

    mock_dns_manager.resolve = AsyncMock(
        side_effect=[
            [MockDNSRecord(["some-txt-record".encode()])],
            [MockDNSRecord(["some-other-record".encode()])],
        ]
    )

    result = await get_spf_record(domain)

    assert result is None


@pytest.mark.asyncio
async def test_get_spf_record_timeout(mock_dns_manager):
    domain = "example.com"
    mock_dns_manager.resolve = AsyncMock(side_effect=asyncio.TimeoutError())

    result = await get_spf_record(domain)

    assert result is None


@pytest.mark.asyncio
async def test_get_spf_record_exception(mock_dns_manager):
    domain = "example.com"
    mock_dns_manager.resolve = AsyncMock(side_effect=Exception("DNS error"))

    result = await get_spf_record(domain)

    assert result is None


@pytest.mark.asyncio
async def test_parse_spf_record_valid():
    record = (
        "v=spf1 ip4:192.0.2.0/24 include:_spf.example.org a:mail.example.org mx -all"
    )
    domain = "example.com"

    result = await parse_spf_record(record, domain)

    assert result["valid"] is True
    assert result["policy"] == "-all"
    assert result["includes"] == ["_spf.example.org"]
    assert result["a_records"] == ["mail.example.org"]
    assert result["mx_records"] == ["example.com"]
    assert result["record"] == record


@pytest.mark.asyncio
async def test_parse_spf_record_with_redirect():
    record = "v=spf1 redirect=_spf.example.org"
    domain = "example.com"
    result = await parse_spf_record(record, domain)

    assert result["valid"] is True
    assert result["redirect"] == "_spf.example.org"
    assert result["policy"] == "?all"


@pytest.mark.asyncio
async def test_parse_spf_record_with_exists():
    record = "v=spf1 exists:example.org ~all"
    domain = "example.com"
    result = await parse_spf_record(record, domain)

    assert result["valid"] is True
    assert result["exists"] == ["example.org"]
    assert result["policy"] == "~all"


@pytest.mark.asyncio
async def test_parse_spf_record_with_ptr():
    record = "v=spf1 ptr ptr:example.org -all"
    domain = "example.com"
    result = await parse_spf_record(record, domain)

    assert result["valid"] is True
    assert result["ptr_records"] == ["example.com", "example.org"]
    assert result["policy"] == "-all"


@pytest.mark.asyncio
async def test_parse_spf_record_no_record():
    result = await parse_spf_record("", "example.com")

    assert result["valid"] is False
    assert result["error"] == "No SPF record found"


@pytest.mark.asyncio
async def test_parse_spf_record_invalid_format():
    record = "not-an-spf-record"
    result = await parse_spf_record(record, "example.com")

    assert result["valid"] is False
    assert result["error"] == "Invalid SPF record format"


@pytest.mark.asyncio
async def test_count_dns_lookups_basic():
    spf_info = {
        "valid": True,
        "policy": "-all",
        "redirect": None,
        "includes": ["example.org"],
        "a_records": ["mail.example.com"],
        "mx_records": ["example.com"],
        "ptr_records": [],
        "exists": [],
    }

    with patch("standards.spf.get_spf_record", AsyncMock(return_value=None)):
        lookup_count, policy, redirect_info = await count_dns_lookups(
            spf_info, "example.com"
        )

        assert lookup_count == 3
        assert policy == "-all"


@pytest.mark.asyncio
async def test_count_dns_lookups_with_includes():
    spf_info = {
        "valid": True,
        "policy": "-all",
        "redirect": None,
        "includes": ["sub1.example.org", "sub2.example.org"],
        "a_records": [],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
    }
    sub1_record = "v=spf1 include:sub3.example.org -all"
    sub1_info = {
        "valid": True,
        "policy": "-all",
        "redirect": None,
        "includes": ["sub3.example.org"],
        "a_records": [],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
    }
    sub2_record = "v=spf1 a:mail.example.org -all"
    sub2_info = {
        "valid": True,
        "policy": "-all",
        "redirect": None,
        "includes": [],
        "a_records": ["mail.example.org"],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
    }

    async def mock_get_spf_record(domain):
        if domain == "sub1.example.org":
            return sub1_record
        elif domain == "sub2.example.org":
            return sub2_record
        else:
            return None

    async def mock_parse_spf_record(record, domain):
        if domain == "sub1.example.org":
            return sub1_info
        elif domain == "sub2.example.org":
            return sub2_info
        else:
            return {"valid": False}

    with (
        patch("standards.spf.get_spf_record", mock_get_spf_record),
        patch("standards.spf.parse_spf_record", mock_parse_spf_record),
    ):
        lookup_count, policy, redirect_info = await count_dns_lookups(
            spf_info, "example.com"
        )

        assert lookup_count == 4
        assert policy == "-all"


@pytest.mark.asyncio
async def test_count_dns_lookups_with_redirect():
    spf_info = {
        "valid": True,
        "policy": "?all",
        "redirect": "spf.example.org",
        "includes": [],
        "a_records": [],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
    }
    redirect_record = "v=spf1 ip4:192.0.2.0/24 -all"
    redirect_info = {
        "valid": True,
        "policy": "-all",
        "redirect": None,
        "includes": [],
        "a_records": [],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
    }

    async def mock_get_spf_record(domain):
        if domain == "spf.example.org":
            return redirect_record
        else:
            return None

    async def mock_parse_spf_record(record, domain):
        if domain == "spf.example.org":
            return redirect_info
        else:
            return {"valid": False}

    with (
        patch("standards.spf.get_spf_record", mock_get_spf_record),
        patch("standards.spf.parse_spf_record", mock_parse_spf_record),
    ):
        lookup_count, policy, redirect_info = await count_dns_lookups(
            spf_info, "example.com"
        )

        assert lookup_count == 0
        assert policy == "-all"


@pytest.mark.asyncio
async def test_count_dns_lookups_exceeds_limit():
    spf_info = {
        "valid": True,
        "policy": "-all",
        "redirect": None,
        "includes": [f"sub{i}.example.org" for i in range(MAX_DNS_LOOKUPS + 1)],
        "a_records": [],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
    }

    with patch("standards.spf.get_spf_record", AsyncMock(return_value=None)):
        lookup_count, policy, redirect_info = await count_dns_lookups(
            spf_info, "example.com"
        )

        assert lookup_count > MAX_DNS_LOOKUPS
        assert policy == "-all"


@pytest.mark.asyncio
async def test_count_dns_lookups_with_macros():
    spf_info = {
        "valid": True,
        "policy": "-all",
        "redirect": "spf.%{d}.example.org",
        "includes": ["include.%{s}.example.org"],
        "a_records": [],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
    }

    with patch("standards.spf.get_spf_record", AsyncMock(return_value=None)):
        lookup_count, policy, redirect_info = await count_dns_lookups(
            spf_info, "example.com"
        )

        assert lookup_count == 1
        assert policy == "-all"


def test_check_policy_strictness():
    assert check_policy_strictness("~all") is True
    assert check_policy_strictness("-all") is True
    assert check_policy_strictness("+all") is False
    assert check_policy_strictness("?all") is False
    assert check_policy_strictness("all") is False


@pytest.mark.asyncio
async def test_check_spf_no_record():
    domain = "example.com"
    with patch("standards.spf.get_spf_record", AsyncMock(return_value=None)):
        result = await check_spf(domain)

        assert result["domain"] == domain
        assert result["has_spf"] is False
        assert result["valid"] is False
        assert result["error"] == "No SPF record found"


@pytest.mark.asyncio
async def test_check_spf_invalid_record():
    domain = "example.com"
    invalid_record = "not-an-spf-record"

    with (
        patch("standards.spf.get_spf_record", AsyncMock(return_value=invalid_record)),
        patch(
            "standards.spf.parse_spf_record",
            AsyncMock(
                return_value={"valid": False, "error": "Invalid SPF record format"}
            ),
        ),
    ):
        result = await check_spf(domain)

        assert result["domain"] == domain
        assert result["has_spf"] is True
        assert result["valid"] is False
        assert result["error"] == "Invalid SPF record format"
        assert result["record"] == invalid_record


@pytest.mark.asyncio
async def test_check_spf_valid_strict_record():
    domain = "example.com"
    record = "v=spf1 ip4:192.0.2.0/24 -all"

    spf_info = {
        "valid": True,
        "policy": "-all",
        "redirect": None,
        "includes": [],
        "a_records": [],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
        "record": record,
    }

    with (
        patch("standards.spf.get_spf_record", AsyncMock(return_value=record)),
        patch("standards.spf.parse_spf_record", AsyncMock(return_value=spf_info)),
        patch(
            "standards.spf.count_dns_lookups", AsyncMock(return_value=(2, "-all", None))
        ),
    ):
        result = await check_spf(domain)

        assert result["domain"] == domain
        assert result["has_spf"] is True
        assert result["valid"] is True
        assert result["record"] == record
        assert result["policy"] == "-all"
        assert result["policy_sufficiently_strict"] is True
        assert result["dns_lookups"] == 2
        assert result["exceeds_lookup_limit"] is False


@pytest.mark.asyncio
async def test_check_spf_valid_not_strict_record():
    domain = "example.com"
    record = "v=spf1 ip4:192.0.2.0/24 ?all"

    spf_info = {
        "valid": True,
        "policy": "?all",
        "redirect": None,
        "includes": [],
        "a_records": [],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
        "record": record,
    }

    with (
        patch("standards.spf.get_spf_record", AsyncMock(return_value=record)),
        patch("standards.spf.parse_spf_record", AsyncMock(return_value=spf_info)),
        patch(
            "standards.spf.count_dns_lookups", AsyncMock(return_value=(2, "?all", None))
        ),
    ):
        result = await check_spf(domain)

        assert result["domain"] == domain
        assert result["has_spf"] is True
        assert result["valid"] is False
        assert result["record"] == record
        assert result["policy"] == "?all"
        assert result["policy_sufficiently_strict"] is False
        assert result["dns_lookups"] == 2
        assert result["exceeds_lookup_limit"] is False
        assert "not sufficiently strict" in result["error"]


@pytest.mark.asyncio
async def test_check_spf_exceeds_lookup_limit():
    domain = "example.com"
    record = "v=spf1 ip4:192.0.2.0/24 -all"

    spf_info = {
        "valid": True,
        "policy": "-all",
        "redirect": None,
        "includes": [],
        "a_records": [],
        "mx_records": [],
        "ptr_records": [],
        "exists": [],
        "record": record,
    }

    with (
        patch("standards.spf.get_spf_record", AsyncMock(return_value=record)),
        patch("standards.spf.parse_spf_record", AsyncMock(return_value=spf_info)),
        patch(
            "standards.spf.count_dns_lookups",
            AsyncMock(return_value=(MAX_DNS_LOOKUPS + 1, "-all", None)),
        ),
    ):
        result = await check_spf(domain)

        assert result["domain"] == domain
        assert result["has_spf"] is True
        assert result["valid"] is False
        assert result["record"] == record
        assert result["policy"] == "-all"
        assert result["policy_sufficiently_strict"] is True
        assert result["dns_lookups"] == MAX_DNS_LOOKUPS + 1
        assert result["exceeds_lookup_limit"] is True
        assert "exceeds maximum DNS lookups" in result["error"]


@pytest.mark.asyncio
async def test_check_domains():
    domains = ["example.com", "example.org"]

    async def mock_check_spf(domain):
        if domain == "example.com":
            return {
                "domain": domain,
                "has_spf": True,
                "valid": True,
                "record": "v=spf1 -all",
                "policy": "-all",
                "policy_explanation": "Policy '-all' is sufficiently strict.",
                "policy_sufficiently_strict": True,
                "dns_lookups": 0,
                "exceeds_lookup_limit": False,
            }
        else:
            return {
                "domain": domain,
                "has_spf": False,
                "valid": False,
                "error": "No SPF record found",
            }

    with patch("standards.spf.check_spf", mock_check_spf):
        results = await check_domains(domains)

        assert len(results) == 2
        assert results["example.com"]["valid"] is True
        assert results["example.org"]["valid"] is False


@pytest.mark.asyncio
async def test_check_domains_with_exception():
    domains = ["example.com", "error-domain.com"]

    async def mock_check_spf(domain):
        if domain == "example.com":
            return {
                "domain": domain,
                "has_spf": True,
                "valid": True,
                "record": "v=spf1 -all",
                "policy": "-all",
                "policy_explanation": "Policy '-all' is sufficiently strict.",
                "policy_sufficiently_strict": True,
                "dns_lookups": 0,
                "exceeds_lookup_limit": False,
            }
        else:
            raise Exception("Test exception")

    with patch("standards.spf.check_spf", mock_check_spf):
        results = await check_domains(domains)

        assert len(results) == 2
        assert results["example.com"]["valid"] is True
        assert results["error-domain.com"]["valid"] is False
        assert "Error: Test exception" in results["error-domain.com"]["error"]
