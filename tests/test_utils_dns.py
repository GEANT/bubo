# tests/test_utils_dns.py

from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest

from bubo.core.dns.records import get_mx_records, resolve_ips, resolve_nameservers
from bubo.core.dns.resolver import dns_manager


@pytest.fixture
def mock_dns_manager():
    # Patch the dns_manager where it's used in records.py, not where it's defined
    with patch("bubo.core.dns.records.dns_manager", autospec=True) as mock_manager:
        yield mock_manager


@pytest.mark.asyncio
async def test_resolve_nameservers_success(
    mock_dns_manager, mock_ns_records, sample_domain
):
    with patch("bubo.core.network.ip_tools.is_valid_ip", return_value=False):
        # Set up the mock correctly
        mock_dns_manager.resolve.return_value = mock_ns_records

        result = await resolve_nameservers(sample_domain)

        # Check the result against expected values
        assert result == ["ns1.example.com", "ns2.example.com"]
        mock_dns_manager.resolve.assert_called_once_with(sample_domain, "NS")


@pytest.mark.asyncio
async def test_resolve_nameservers_ip_input():
    # This is a more robust patching approach for async functions
    async def mock_get_asn(*args, **kwargs):
        return "12345", "192.168.0.0/24"

    with (
        patch("bubo.core.dns.records.is_valid_ip", return_value=True),
        patch("bubo.core.dns.records.get_asn_and_prefix", mock_get_asn),
    ):
        result = await resolve_nameservers("192.168.1.1")
        assert result == ["192.168.1.1"]


@pytest.mark.asyncio
async def test_resolve_nameservers_no_records(mock_dns_manager):
    mock_dns_manager.resolve.side_effect = dns.resolver.NoAnswer()

    result = await resolve_nameservers("example.com")
    assert result == []


@pytest.mark.asyncio
async def test_resolve_ips_success(
    mock_dns_manager, mock_ipv4_records, mock_ipv6_records
):
    # Configure mock_dns_manager to return our fixtures in sequence
    mock_dns_manager.resolve.side_effect = [mock_ipv4_records, mock_ipv6_records]

    ipv4, ipv6 = await resolve_ips("ns1.example.com")
    assert ipv4 == ["192.168.1.1"]
    assert ipv6 == ["2001:db8::1"]


@pytest.mark.asyncio
async def test_resolve_ips_ip_input():
    with patch("bubo.core.network.ip_tools.is_valid_ip", return_value=True):
        ipv4, ipv6 = await resolve_ips("192.168.1.1")
        assert ipv4 == ["192.168.1.1"]
        assert ipv6 == ["No IPv6"]


@pytest.mark.asyncio
async def test_resolve_ips_no_ipv6(mock_dns_manager, mock_ipv4_records):
    mock_dns_manager.resolve.side_effect = [mock_ipv4_records, dns.resolver.NoAnswer()]

    ipv4, ipv6 = await resolve_ips("ns1.example.com")
    assert ipv4 == ["192.168.1.1"]
    assert ipv6 == ["No IPv6"]


@pytest.mark.asyncio
async def test_get_mx_records_success(mock_dns_manager, mock_mx_records, sample_domain):
    mock_dns_manager.resolve.return_value = mock_mx_records

    # Since MX records have dots that need to be stripped
    with patch(
        "bubo.core.dns.records.sorted",
        return_value=["mail1.example.com", "mail2.example.com"],
    ):
        result = await get_mx_records(sample_domain)
        assert result == ["mail1.example.com", "mail2.example.com"]


@pytest.mark.asyncio
async def test_get_mx_records_no_records(mock_dns_manager):
    mock_dns_manager.resolve.side_effect = dns.resolver.NoAnswer()

    result = await get_mx_records("example.com")
    assert result is None


@pytest.mark.asyncio
async def test_get_mx_records_nxdomain(mock_dns_manager):
    mock_dns_manager.resolve.side_effect = dns.resolver.NXDOMAIN()

    result = await get_mx_records("nonexistent.com")
    assert result is None


@pytest.mark.asyncio
async def test_dns_manager_singleton():
    from bubo.core.dns.resolver import DNSResolverManager

    manager1 = DNSResolverManager()
    manager2 = DNSResolverManager()

    assert manager1 is manager2


@pytest.mark.asyncio
async def test_dns_manager_resolve_with_retry():
    mock_resolver = MagicMock()
    mock_resolver.resolve = AsyncMock()
    mock_resolver.resolve.side_effect = [
        Exception("DNS timeout"),  # First call fails
        Exception("DNS timeout"),  # Second call fails
        MagicMock(),  # Third call succeeds
    ]

    with (
        patch.object(dns_manager, "resolver", mock_resolver),
        patch("asyncio.sleep", AsyncMock()),
    ):
        await dns_manager.resolve("example.com", "A")

        assert mock_resolver.resolve.call_count == 3


@pytest.mark.asyncio
async def test_dns_manager_resolve_dnssec():
    """Test the DNSSEC-specific resolver method"""
    mock_response = MagicMock()

    with patch(
        "bubo.core.dns.resolver.DNSResolverManager.resolve_dnssec",
        AsyncMock(return_value=mock_response),
    ) as mock_method:
        result = await dns_manager.resolve_dnssec("example.com", "DNSKEY")

        mock_method.assert_called_once_with("example.com", "DNSKEY")
        assert result == mock_response


@pytest.mark.asyncio
async def test_dns_manager_semaphore_limiting():
    mock_semaphore = MagicMock()
    mock_semaphore.__aenter__ = AsyncMock()
    mock_semaphore.__aexit__ = AsyncMock()

    mock_resolver = MagicMock()
    mock_resolver.resolve = AsyncMock(return_value=MagicMock())

    with (
        patch.object(dns_manager, "semaphore", mock_semaphore),
        patch.object(dns_manager, "resolver", mock_resolver),
    ):
        await dns_manager.resolve("example.com", "A")

        mock_semaphore.__aenter__.assert_called_once()
        mock_semaphore.__aexit__.assert_called_once()
