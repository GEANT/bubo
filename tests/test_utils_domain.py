# tests/test_utils_domain.py

import pytest

from core.network.ip_tools import is_valid_ip
from core.validators.sanitizer import validate_hostname


@pytest.mark.asyncio
async def test_validate_hostname_valid(sample_domain):
    valid_hostnames = [
        sample_domain,
        f"sub.{sample_domain}",
        f"sub-domain.{sample_domain}",
        "example-domain.com",
        "a" * 63 + ".com",  # Max length label
        "xn--domain.com",  # Punycode domain
    ]

    for hostname in valid_hostnames:
        assert await validate_hostname(hostname) is True


@pytest.mark.asyncio
async def test_validate_hostname_invalid():
    invalid_hostnames = [
        "",  # Empty string
        "example",  # No TLD
        "-example.com",  # Starts with hyphen
        "example-.com",  # Ends with hyphen
        "exam ple.com",  # Contains space
        "a" * 64 + ".com",  # Label too long
        "." * 256,  # Total length too long
        "@example.com",  # Invalid character
        "example..com",  # Double dot
        None,  # None value
        "example.c",  # Single char TLD
    ]

    for hostname in invalid_hostnames:
        assert await validate_hostname(hostname) is False


def test_is_valid_ip_v4():
    valid_ipv4 = [
        "192.168.1.1",
        "10.0.0.0",
        "172.16.254.1",
        "0.0.0.0",
        "255.255.255.255",
    ]

    for ip in valid_ipv4:
        assert is_valid_ip(ip) is True


def test_is_valid_ip_v6():
    valid_ipv6 = [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "::1",
        "fe80::1",
        "::",
        "2001:db8::",
        "fe80::217:f2ff:fe07:ed62",
    ]

    for ip in valid_ipv6:
        assert is_valid_ip(ip) is True


def test_is_valid_ip_invalid():
    invalid_ips = [
        "256.256.256.256",  # Invalid IPv4
        "192.168.1",  # Incomplete IPv4
        "192.168.1.1.1",  # Extra octet
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334:",  # Invalid IPv6
        "example.com",  # Domain name
        "",  # Empty string
        None,  # None value
        "192.168.1.1/24",  # CIDR notation
        ":::",  # Invalid IPv6
        "2001::ff::ff",  # Double compression
    ]

    for ip in invalid_ips:
        assert is_valid_ip(ip) is False


def test_is_valid_ip_edge_cases():
    edge_cases = [
        "0.0.0.0",  # Minimum IPv4
        "255.255.255.255",  # Maximum IPv4
        "::",  # Minimum IPv6
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  # Maximum IPv6
    ]

    for ip in edge_cases:
        assert is_valid_ip(ip) is True
