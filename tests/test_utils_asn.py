# tests/test_utils_asn.py

import pytest
from unittest.mock import patch, MagicMock
from core.utils import get_asn_and_prefix, translate_server_type, process_domain


@pytest.mark.asyncio
async def test_get_asn_and_prefix_success():
    mock_result = {"asn": "15169", "asn_cidr": "8.8.8.0/24"}

    mock_net = MagicMock()
    mock_net.address = "8.8.8.8"
    mock_ipwhois = MagicMock()
    mock_ipwhois.net = mock_net

    async def mock_run_in_executor(*args):
        return mock_result

    loop_mock = MagicMock()
    loop_mock.run_in_executor = mock_run_in_executor

    with (
        patch("ipwhois.IPWhois", return_value=mock_ipwhois),
        patch("asyncio.get_event_loop", return_value=loop_mock),
    ):
        asn, prefix = await get_asn_and_prefix("8.8.8.8")
        assert asn == "15169"
        assert prefix == "8.8.8.0/24"


@pytest.mark.asyncio
async def test_get_asn_and_prefix_retry_success():
    mock_result = {"asn": "15169", "asn_cidr": "8.8.8.0/24"}
    mock_net = MagicMock(address="8.8.8.8")
    mock_ipwhois = MagicMock(net=mock_net)

    first_call = True

    async def mock_run_in_executor(*args):
        nonlocal first_call
        if first_call:
            first_call = False
            raise Exception("Temporary failure")
        return mock_result

    loop_mock = MagicMock()
    loop_mock.run_in_executor = mock_run_in_executor

    with (
        patch("ipwhois.IPWhois", return_value=mock_ipwhois),
        patch("asyncio.get_event_loop", return_value=loop_mock),
        patch("asyncio.sleep"),
    ):
        asn, prefix = await get_asn_and_prefix("8.8.8.8")
        assert asn == "15169"
        assert prefix == "8.8.8.0/24"


@pytest.mark.asyncio
async def test_get_asn_and_prefix_all_retries_fail():
    mock_net = MagicMock(address="8.8.8.8")
    mock_ipwhois = MagicMock(net=mock_net)

    async def mock_run_in_executor(*args):
        raise Exception("Persistent failure")

    loop_mock = MagicMock()
    loop_mock.run_in_executor = mock_run_in_executor

    with (
        patch("ipwhois.IPWhois", return_value=mock_ipwhois),
        patch("asyncio.get_event_loop", return_value=loop_mock),
        patch("asyncio.sleep"),
    ):
        asn, prefix = await get_asn_and_prefix("8.8.8.8")
        assert asn is None
        assert prefix is None


@pytest.mark.asyncio
async def test_translate_server_type():
    test_cases = [
        ("domain_ns", "Nameserver of Domain"),
        ("domain_mx", "Mail Server of Domain"),
        ("mailserver_ns", "Nameserver of Mail Server"),
        ("unknown_type", "Unknown Server Type"),
    ]

    for server_type, expected in test_cases:
        result = await translate_server_type(server_type)
        assert result == expected


@pytest.mark.asyncio
async def test_process_domain_valid(sample_domain):
    with (
        patch("core.utils.validate_hostname", return_value=True),
        patch("core.utils.resolve_nameservers", return_value=["ns1.example.com"]),
        patch("core.utils.get_mx_records", return_value=["mail.example.com"]),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain(sample_domain)
        assert domain_ns == ["ns1.example.com"]
        assert domain_mx == ["mail.example.com"]
        assert isinstance(mail_ns, list)


@pytest.mark.asyncio
async def test_process_domain_invalid():
    with patch("core.utils.validate_hostname", return_value=False):
        domain_ns, domain_mx, mail_ns = await process_domain("invalid@domain")
        assert domain_ns is None
        assert domain_mx is None
        assert mail_ns is None


@pytest.mark.asyncio
async def test_process_domain_email_input(sample_domain):
    with (
        patch("core.utils.validate_hostname", return_value=True),
        patch("core.utils.resolve_nameservers", return_value=["ns1.example.com"]),
        patch("core.utils.get_mx_records", return_value=["mail.example.com"]),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain(f"user@{sample_domain}")
        assert domain_ns == ["ns1.example.com"]
        assert domain_mx == ["mail.example.com"]
        assert isinstance(mail_ns, list)


@pytest.mark.asyncio
async def test_process_domain_ip_input():
    with (
        patch("core.utils.is_valid_ip", return_value=True),
        patch(
            "core.utils.get_asn_and_prefix", return_value=("12345", "192.168.0.0/24")
        ),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain("192.168.1.1")
        assert domain_ns == ["192.168.1.1"]
        assert domain_mx is None
        assert mail_ns is None


@pytest.mark.asyncio
async def test_process_domain_dns_failure():
    with (
        patch("core.utils.validate_hostname", return_value=True),
        patch("core.utils.resolve_nameservers", return_value=[]),
        patch("core.utils.get_mx_records", return_value=None),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain("example.com")
        assert domain_ns == []
        assert domain_mx is None
        assert mail_ns is None
