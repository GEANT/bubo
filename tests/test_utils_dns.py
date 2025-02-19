# tests/test_utils_dns.py

import pytest
from unittest.mock import patch, AsyncMock
import dns.resolver
from core.utils import resolve_nameservers, resolve_ips, get_mx_records

@pytest.mark.asyncio
async def test_resolve_nameservers_success(mock_dns_resolver, mock_ns_records, sample_domain):
    with patch('core.utils.is_valid_ip', return_value=False), \
         patch('dns.asyncresolver.Resolver', return_value=mock_dns_resolver), \
         patch('asyncio.sleep', new_callable=AsyncMock):
        mock_dns_resolver.resolve.return_value = mock_ns_records
        result = await resolve_nameservers(sample_domain)
        assert result == ["ns1.example.com", "ns2.example.com"]
        mock_dns_resolver.resolve.assert_called_once_with(sample_domain, 'NS')

@pytest.mark.asyncio
async def test_resolve_nameservers_ip_input():
    with patch('core.utils.get_asn_and_prefix', return_value=("12345", "192.168.0.0/24")):
        result = await resolve_nameservers("192.168.1.1")
        assert result == ["192.168.1.1"]

@pytest.mark.asyncio
async def test_resolve_nameservers_no_records(mock_dns_resolver):
    with patch('dns.asyncresolver.Resolver', return_value=mock_dns_resolver):
        mock_dns_resolver.resolve.side_effect = dns.resolver.NoAnswer
        result = await resolve_nameservers("example.com")
        assert result == []

@pytest.mark.asyncio
async def test_resolve_nameservers_nxdomain(mock_dns_resolver):
    with patch('dns.asyncresolver.Resolver', return_value=mock_dns_resolver):
        mock_dns_resolver.resolve.side_effect = dns.resolver.NXDOMAIN
        result = await resolve_nameservers("nonexistent.com")
        assert result == []

@pytest.mark.asyncio
async def test_resolve_ips_success(mock_dns_resolver, mock_ipv4_records, mock_ipv6_records):
    with patch('dns.asyncresolver.Resolver.resolve', side_effect=[
        mock_ipv4_records,
        mock_ipv6_records
    ]):
        ipv4, ipv6 = await resolve_ips("ns1.example.com")
        assert ipv4 == ["192.168.1.1"]
        assert ipv6 == ["2001:db8::1"]

@pytest.mark.asyncio
async def test_resolve_ips_ip_input():
    ipv4, ipv6 = await resolve_ips("192.168.1.1")
    assert ipv4 == ["192.168.1.1"]
    assert ipv6 == ["No IPv6"]

@pytest.mark.asyncio
async def test_resolve_ips_no_ipv6(mock_dns_resolver, mock_ipv4_records):
    with patch('dns.asyncresolver.Resolver.resolve', side_effect=[
        mock_ipv4_records,
        dns.resolver.NoAnswer
    ]):
        ipv4, ipv6 = await resolve_ips("ns1.example.com")
        assert ipv4 == ["192.168.1.1"]
        assert ipv6 == ["No IPv6"]

@pytest.mark.asyncio
async def test_resolve_ips_no_records(mock_dns_resolver):
    with patch('dns.asyncresolver.Resolver.resolve', side_effect=dns.resolver.NoAnswer):
        ipv4, ipv6 = await resolve_ips("ns1.example.com")
        assert ipv4 == []
        assert ipv6 == ["No IPv6"]

@pytest.mark.asyncio
async def test_get_mx_records_success(mock_mx_records, sample_domain):
    with patch('dns.resolver.resolve', return_value=mock_mx_records):
        result = await get_mx_records(sample_domain)
        assert result == ["mail1.example.com", "mail2.example.com"]

@pytest.mark.asyncio
async def test_get_mx_records_no_records():
    with patch('dns.resolver.resolve', side_effect=dns.resolver.NoAnswer):
        result = await get_mx_records("example.com")
        assert result is None

@pytest.mark.asyncio
async def test_get_mx_records_nxdomain():
    with patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
        result = await get_mx_records("nonexistent.com")
        assert result is None
