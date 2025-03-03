# tests/test_utils_asn.py
from datetime import timedelta

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from core.utils import get_asn_and_prefix, translate_server_type, process_domain


@pytest.mark.asyncio
async def test_get_asn_and_prefix_cached():
    """Test when result is found in cache."""
    # Mock the cache instance
    mock_cache = MagicMock()
    mock_cache.get_result.return_value = ("12345", "192.168.0.0/24")

    # Patch the global _ipwhois_cache variable
    with patch("core.utils._ipwhois_cache", mock_cache):
        # Call the function
        asn, prefix = await get_asn_and_prefix("192.168.0.1")

        # Verify results
        assert asn == "12345"
        assert prefix == "192.168.0.0/24"

        # Verify that get_result was called with the right parameters
        mock_cache.get_result.assert_called_once_with("192.168.0.1", False)

        # Verify that save_result was not called (since we returned cached result)
        mock_cache.save_result.assert_not_called()


@pytest.mark.asyncio
async def test_get_asn_and_prefix_lookup_success():
    """Test when result is not in cache but lookup is successful."""
    # Mock the cache instance
    mock_cache = MagicMock()
    mock_cache.get_result.return_value = None  # No cached result

    # Mock the IPWhois instance and its lookup_rdap method
    mock_ipwhois = MagicMock()
    mock_ipwhois.lookup_rdap.return_value = {
        "asn": "12345 Some ASN description",
        "asn_cidr": "192.168.0.0/24",
    }

    # Set up patches
    with (
        patch("core.utils._ipwhois_cache", mock_cache),
        patch("core.utils.IPWhois", return_value=mock_ipwhois),
        patch("core.utils.asyncio.get_event_loop") as mock_loop,
    ):
        # Mock run_in_executor to actually call the function passed to it
        async def mock_run_in_executor(executor, func, *args, **kwargs):
            # This simulates calling the function in another thread
            return func()

        mock_loop.return_value.run_in_executor = AsyncMock(
            side_effect=mock_run_in_executor
        )

        # Call the function
        asn, prefix = await get_asn_and_prefix("192.168.0.1")

        # Verify results
        assert asn == "12345"
        assert prefix == "192.168.0.0/24"

        # Verify that cache was checked
        mock_cache.get_result.assert_called_once_with("192.168.0.1", False)

        # Verify that IPWhois was used with the correct IP
        mock_ipwhois.lookup_rdap.assert_called_once()

        # Verify that run_in_executor was called
        mock_loop.return_value.run_in_executor.assert_called_once_with(
            None, mock_ipwhois.lookup_rdap
        )

        # Verify that result was saved to cache
        mock_cache.save_result.assert_called_once_with(
            "192.168.0.1", "12345", "192.168.0.0/24"
        )


@pytest.mark.asyncio
async def test_get_asn_and_prefix_ignore_cache():
    """Test when ignore_cache is True."""
    # Mock the cache instance
    mock_cache = MagicMock()
    # Even if there's a cached result, the function should ignore it
    mock_cache.get_result.return_value = None

    # Mock the IPWhois instance
    mock_ipwhois = MagicMock()
    mock_ipwhois.lookup_rdap.return_value = {
        "asn": "67890 Some other ASN description",
        "asn_cidr": "10.0.0.0/8",
    }

    # Set up patches
    with (
        patch("core.utils._ipwhois_cache", mock_cache),
        patch("core.utils.IPWhois", return_value=mock_ipwhois),
        patch("core.utils.asyncio.get_event_loop") as mock_loop,
    ):
        # Mock run_in_executor
        mock_loop.return_value.run_in_executor = AsyncMock(
            return_value=mock_ipwhois.lookup_rdap.return_value
        )

        # Call the function with ignore_cache=True
        asn, prefix = await get_asn_and_prefix("192.168.0.1", ignore_cache=True)

        # Verify results
        assert asn == "67890"
        assert prefix == "10.0.0.0/8"

        # Verify that get_result was called with ignore_cache=True
        mock_cache.get_result.assert_called_once_with("192.168.0.1", True)

        # Verify that result was saved to cache
        mock_cache.save_result.assert_called_once_with(
            "192.168.0.1", "67890", "10.0.0.0/8"
        )


@pytest.mark.asyncio
async def test_get_asn_and_prefix_init_cache():
    """Test when _ipwhois_cache is None and needs to be initialized."""
    # Mock the IPWhoisCache class and instance
    mock_cache_class = MagicMock()
    mock_cache_instance = MagicMock()
    mock_cache_class.return_value = mock_cache_instance
    mock_cache_instance.get_result.return_value = None  # No cached result

    # Mock the IPWhois instance
    mock_ipwhois = MagicMock()
    mock_ipwhois.lookup_rdap.return_value = {
        "asn": "12345 Some ASN description",
        "asn_cidr": "192.168.0.0/24",
    }

    # Set up patches
    with (
        patch("core.utils._ipwhois_cache", None),
        patch("core.utils.IPWhoisCache", mock_cache_class),
        patch("core.utils.IPWhois", return_value=mock_ipwhois),
        patch("core.utils.asyncio.get_event_loop") as mock_loop,
        patch("core.utils.os.path.dirname", return_value="/mock/path"),
        patch("core.utils.os.path.join", return_value="/mock/path/cache"),
    ):
        # Mock run_in_executor
        mock_loop.return_value.run_in_executor = AsyncMock(
            return_value=mock_ipwhois.lookup_rdap.return_value
        )

        # Call the function
        asn, prefix = await get_asn_and_prefix("192.168.0.1")

        # Verify results
        assert asn == "12345"
        assert prefix == "192.168.0.0/24"

        # Verify that IPWhoisCache was initialized correctly
        mock_cache_class.assert_called_once_with("/mock/path/cache", timedelta(days=30))

        # Verify that the rest of the process worked as expected
        mock_cache_instance.get_result.assert_called_once_with("192.168.0.1", False)
        mock_cache_instance.save_result.assert_called_once_with(
            "192.168.0.1", "12345", "192.168.0.0/24"
        )


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
