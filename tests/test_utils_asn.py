# tests/test_utils_asn.py
from datetime import timedelta

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from core.network.ip_tools import get_asn_and_prefix
from core.dns.records import translate_server_type, process_domain


@pytest.mark.asyncio
async def test_get_asn_and_prefix_cached():
    """Test when result is found in cache_manager."""
    # Mock the cache_manager instance
    mock_cache = MagicMock()
    mock_cache.get_result.return_value = ("12345", "192.168.0.0/24")

    # Patch the global _ipwhois_cache variable
    with patch("core.network.ip_tools._ipwhois_cache", mock_cache):
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
    """Test when result is not in cache_manager but lookup is successful."""
    # Mock the cache_manager instance
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
        patch("core.network.ip_tools._ipwhois_cache", mock_cache),
        patch("core.network.ip_tools.IPWhois", return_value=mock_ipwhois),
        patch("core.network.ip_tools.asyncio.get_event_loop") as mock_loop,
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

        # Verify that cache_manager was checked
        mock_cache.get_result.assert_called_once_with("192.168.0.1", False)

        # Verify that IPWhois was used with the correct IP
        mock_ipwhois.lookup_rdap.assert_called_once()

        # Verify that run_in_executor was called
        mock_loop.return_value.run_in_executor.assert_called_once_with(
            None, mock_ipwhois.lookup_rdap
        )

        # Verify that result was saved to cache_manager
        mock_cache.save_result.assert_called_once_with(
            "192.168.0.1", "12345", "192.168.0.0/24"
        )


@pytest.mark.asyncio
async def test_get_asn_and_prefix_ignore_cache():
    """Test when ignore_cache is True."""
    # Mock the IPWhoisCache class
    mock_cache = MagicMock()
    # Note: get_result is never called when ignore_cache=True in the actual implementation

    # Setup direct patching
    with (
        patch("core.network.ip_tools._ipwhois_cache", mock_cache),
        patch("core.network.ip_tools.logger"),
        patch("core.network.ip_tools.asyncio.sleep", AsyncMock()),
    ):
        # Create a mock IPWhois that returns our controlled data
        mock_ipwhois = MagicMock()
        with patch("core.network.ip_tools.IPWhois", return_value=mock_ipwhois):
            # Hook the actual executor to return our controlled data
            async def mock_executor(executor, func, *args):
                # Return the data we want without calling the real function
                return {"asn": "67890 Some description", "asn_cidr": "10.0.0.0/8"}

            # Mock the event loop
            mock_loop = MagicMock()
            mock_loop.run_in_executor = AsyncMock(side_effect=mock_executor)

            with patch("asyncio.get_event_loop", return_value=mock_loop):
                # Import after patching to ensure we use mocked versions
                from core.network.ip_tools import get_asn_and_prefix

                # Execute the function
                asn, prefix = await get_asn_and_prefix("192.168.0.1", ignore_cache=True)

                # Check results
                assert asn == "67890"
                assert prefix == "10.0.0.0/8"

                # When ignore_cache=True, get_result should NOT be called
                mock_cache.get_result.assert_not_called()

                # verify IPWhois was constructed correctly
                mock_ipwhois.lookup_rdap.assert_not_called()  # Not called directly, but via executor

                # Verify the result was saved to cache
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
        patch("core.network.ip_tools._ipwhois_cache", None),
        patch("core.network.ip_tools.IPWhoisCache", mock_cache_class),
        patch("core.network.ip_tools.IPWhois", return_value=mock_ipwhois),
        patch("core.network.ip_tools.asyncio.get_event_loop") as mock_loop,
        patch("core.network.ip_tools.os.path.dirname", return_value="/mock/path"),
        patch(
            "core.network.ip_tools.os.path.join",
            return_value="/mock/path/cache_manager",
        ),
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
        mock_cache_class.assert_called_once_with(
            "/mock/path/cache_manager", timedelta(days=30)
        )

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
        patch("core.validators.sanitizer.validate_hostname", return_value=True),
        patch("core.dns.records.resolve_nameservers", return_value=["ns1.example.com"]),
        patch("core.dns.records.get_mx_records", return_value=["mail.example.com"]),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain(sample_domain)
        assert domain_ns == ["ns1.example.com"]
        assert domain_mx == ["mail.example.com"]
        assert isinstance(mail_ns, list)


@pytest.mark.asyncio
async def test_process_domain_invalid():
    with patch("core.validators.sanitizer.validate_hostname", return_value=False):
        domain_ns, domain_mx, mail_ns = await process_domain("invalid@domain")
        assert domain_ns is None
        assert domain_mx is None
        assert mail_ns is None


@pytest.mark.asyncio
async def test_process_domain_email_input(sample_domain):
    with (
        patch("core.validators.sanitizer.validate_hostname", return_value=True),
        patch("core.dns.records.resolve_nameservers", return_value=["ns1.example.com"]),
        patch("core.dns.records.get_mx_records", return_value=["mail.example.com"]),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain(f"user@{sample_domain}")
        assert domain_ns == ["ns1.example.com"]
        assert domain_mx == ["mail.example.com"]
        assert isinstance(mail_ns, list)


@pytest.mark.asyncio
async def test_process_domain_ip_input():
    """Test processing a domain when input is an IP address."""
    # Patch at the location where process_domain imports these functions
    with patch("core.dns.records.is_valid_ip", return_value=True) as mock_is_valid_ip:
        # Create async mock for get_asn_and_prefix
        mock_get_asn = AsyncMock(return_value=("12345", "192.168.0.0/24"))

        with patch("core.dns.records.get_asn_and_prefix", mock_get_asn):
            # Import the function after patching
            from core.dns.records import process_domain

            # Call the function with an IP
            domain_ns, domain_mx, mail_ns = await process_domain("192.168.1.1")

            # Verify results
            assert domain_ns == ["192.168.1.1"]
            assert domain_mx is None
            assert mail_ns is None

            # Verify the mocks were called correctly
            mock_is_valid_ip.assert_called_with("192.168.1.1")
            mock_get_asn.assert_called_once_with("192.168.1.1", ignore_cache=False)


@pytest.mark.asyncio
async def test_process_domain_dns_failure():
    with (
        patch("core.validators.sanitizer.validate_hostname", return_value=True),
        patch("core.dns.records.resolve_nameservers", return_value=[]),
        patch("core.dns.records.get_mx_records", return_value=None),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain("example.com")
        assert domain_ns == []
        assert domain_mx is None
        assert mail_ns is None
