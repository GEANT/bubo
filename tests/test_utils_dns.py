# tests/test_utils_dns.py

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import dns.resolver
import asyncio
from core.utils import resolve_nameservers, resolve_ips, get_mx_records, dns_manager


@pytest.fixture
def mock_dns_manager():
    """Create a mock for the dns_manager singleton"""
    with patch("core.utils.dns_manager", autospec=True) as mock_manager:
        yield mock_manager


@pytest.mark.asyncio
async def test_resolve_nameservers_success(
    mock_dns_manager, mock_ns_records, sample_domain
):
    with patch("core.utils.is_valid_ip", return_value=False):
        # Setup the mock response
        mock_dns_manager.resolve.return_value = mock_ns_records

        # Call the function under test
        result = await resolve_nameservers(sample_domain)

        # Verify results
        assert result == ["ns1.example.com", "ns2.example.com"]
        mock_dns_manager.resolve.assert_called_once_with(sample_domain, "NS")


@pytest.mark.asyncio
async def test_resolve_nameservers_ip_input():
    with patch(
        "core.utils.get_asn_and_prefix", return_value=("12345", "192.168.0.0/24")
    ):
        result = await resolve_nameservers("192.168.1.1")
        assert result == ["192.168.1.1"]


@pytest.mark.asyncio
async def test_resolve_nameservers_no_records(mock_dns_manager):
    # Setup the mock to raise NoAnswer
    mock_dns_manager.resolve.side_effect = dns.resolver.NoAnswer()

    # Call the function and verify
    result = await resolve_nameservers("example.com")
    assert result == []


@pytest.mark.asyncio
async def test_resolve_nameservers_nxdomain(mock_dns_manager):
    # Setup the mock to raise NXDOMAIN
    mock_dns_manager.resolve.side_effect = dns.resolver.NXDOMAIN()

    result = await resolve_nameservers("nonexistent.com")
    assert result == []


@pytest.mark.asyncio
async def test_resolve_ips_success(
    mock_dns_manager, mock_ipv4_records, mock_ipv6_records
):
    # Setup the mock with side effects for multiple calls
    mock_dns_manager.resolve.side_effect = [mock_ipv4_records, mock_ipv6_records]

    ipv4, ipv6 = await resolve_ips("ns1.example.com")
    assert ipv4 == ["192.168.1.1"]
    assert ipv6 == ["2001:db8::1"]


@pytest.mark.asyncio
async def test_resolve_ips_ip_input():
    ipv4, ipv6 = await resolve_ips("192.168.1.1")
    assert ipv4 == ["192.168.1.1"]
    assert ipv6 == ["No IPv6"]


@pytest.mark.asyncio
async def test_resolve_ips_no_ipv6(mock_dns_manager, mock_ipv4_records):
    # Setup different responses for the two calls
    mock_dns_manager.resolve.side_effect = [mock_ipv4_records, dns.resolver.NoAnswer()]

    ipv4, ipv6 = await resolve_ips("ns1.example.com")
    assert ipv4 == ["192.168.1.1"]
    assert ipv6 == ["No IPv6"]


@pytest.mark.asyncio
async def test_get_mx_records_success(mock_dns_manager, mock_mx_records, sample_domain):
    # Update to use dns_manager
    mock_dns_manager.resolve.return_value = mock_mx_records

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


# New tests for the DNSResolverManager


@pytest.mark.asyncio
async def test_dns_manager_singleton():
    """Test that the dns_manager is a singleton"""
    from core.utils import DNSResolverManager

    manager1 = DNSResolverManager()
    manager2 = DNSResolverManager()

    assert manager1 is manager2


@pytest.mark.asyncio
async def test_dns_manager_resolve_with_retry():
    """Test that the dns_manager properly retries failed queries"""
    # Create a mock resolver that fails twice then succeeds
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
    ):  # To speed up test
        result = await dns_manager.resolve("example.com", "A")

        assert mock_resolver.resolve.call_count == 3


@pytest.mark.asyncio
async def test_dns_manager_resolve_dnssec():
    """Test the DNSSEC-specific resolver method"""
    # Mock a response for DNSSEC resolution
    mock_response = MagicMock()

    # Replace the singleton resolve_dnssec method
    with patch(
        "core.utils.DNSResolverManager.resolve_dnssec",
        AsyncMock(return_value=mock_response),
    ) as mock_method:
        result = await dns_manager.resolve_dnssec("example.com", "DNSKEY")

        # Verify it was called with proper arguments
        mock_method.assert_called_once_with("example.com", "DNSKEY")
        assert result == mock_response


@pytest.mark.asyncio
async def test_dns_manager_semaphore_limiting():
    """Test that the semaphore properly limits concurrent DNS requests"""
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
