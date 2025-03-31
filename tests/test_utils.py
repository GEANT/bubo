import os
import pytest
import tempfile
from unittest.mock import patch, AsyncMock
import dns.resolver

from core.utils import (
    DNSResolverManager,
    process_file,
    process_domain,
)


@pytest.fixture
def temp_txt_file():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as temp:
        temp.write(b"example.com\ndomain.org\ntest.net\n")
    yield temp.name
    os.unlink(temp.name)


@pytest.fixture
def temp_csv_file():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as temp:
        temp.write(b"Domain,Country,Institution\n")
        temp.write(b"example.com,US,Example Inc\n")
        temp.write(b"domain.org,UK,Domain Org\n")
        temp.write(b"test.net,DE,Test Network\n")
        temp.write(b",,,\n")  # Empty row to test handling
    yield temp.name
    os.unlink(temp.name)


@pytest.fixture
def temp_csv_file_no_domain_column():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as temp:
        temp.write(b"Name,Country,Institution\n")
        temp.write(b"Example,US,Example Inc\n")
    yield temp.name
    os.unlink(temp.name)


@pytest.fixture
def sample_email():
    return "user@example.com"


@pytest.mark.asyncio
async def test_process_file_txt(temp_txt_file):
    result = await process_file(temp_txt_file)

    assert len(result) == 3
    assert result[0]["Domain"] == "example.com"
    assert result[1]["Domain"] == "domain.org"
    assert result[2]["Domain"] == "test.net"

    # Check default values for other fields
    assert result[0]["Country"] == ""
    assert result[0]["Institution"] == ""


@pytest.mark.asyncio
async def test_process_file_csv(temp_csv_file):
    result = await process_file(temp_csv_file)

    assert len(result) == 3  # Should skip the empty row
    assert result[0]["Domain"] == "test.net"
    assert result[0]["Country"] == "DE"
    assert result[0]["Institution"] == "Test Network"

    assert result[1]["Domain"] == "domain.org"
    assert result[1]["Country"] == "UK"

    assert result[2]["Domain"] == "example.com"
    assert result[2]["Institution"] == "Example Inc"


@pytest.mark.asyncio
async def test_process_file_invalid_format():
    file_path = (
        "test_only_filename.docx"  # Use a name that won't be confused with real files
    )
    mock_abs_path = os.path.join(tempfile.gettempdir(), file_path)

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=mock_abs_path),
        patch("os.path.normpath", return_value=mock_abs_path),
    ):
        with pytest.raises(Exception) as excinfo:
            await process_file(file_path)

        assert "Invalid file format" in str(excinfo.value)


@pytest.mark.asyncio
async def test_process_file_file_not_found():
    file_path = "nonexistent_test_file.txt"
    mock_abs_path = os.path.join(tempfile.gettempdir(), file_path)

    with (
        patch("os.path.isfile", return_value=False),
        patch("os.path.abspath", return_value=mock_abs_path),
        patch("os.path.normpath", return_value=mock_abs_path),
    ):
        with pytest.raises(Exception) as excinfo:
            await process_file(file_path)

        assert "File does not exist" in str(excinfo.value)


@pytest.mark.asyncio
async def test_dns_resolver_manager_resolve_exception_handling():
    manager = DNSResolverManager()

    # Test handling of NoNameservers exception
    with patch.object(
        manager.resolver, "resolve", AsyncMock(side_effect=dns.resolver.NoNameservers())
    ):
        with pytest.raises(dns.resolver.NoNameservers):
            await manager.resolve("example.com", "A")

    # Test handling of NXDOMAIN exception
    with patch.object(
        manager.resolver, "resolve", AsyncMock(side_effect=dns.resolver.NXDOMAIN())
    ):
        with pytest.raises(dns.resolver.NXDOMAIN):
            await manager.resolve("example.com", "A")

    # Test handling of NoAnswer exception
    with patch.object(
        manager.resolver, "resolve", AsyncMock(side_effect=dns.resolver.NoAnswer())
    ):
        with pytest.raises(dns.resolver.NoAnswer):
            await manager.resolve("example.com", "A")


@pytest.mark.asyncio
async def test_process_domain_email_extraction(sample_email):
    with (
        patch("core.utils.validate_hostname", return_value=True),
        patch(
            "core.utils.resolve_nameservers",
            AsyncMock(return_value=["ns1.example.com"]),
        ),
        patch("core.utils.get_mx_records", AsyncMock(return_value=None)),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain(sample_email)

        # Check that the email was processed as "example.com"
        assert domain_ns == ["ns1.example.com"]


@pytest.mark.asyncio
async def test_process_domain_mail_nameservers():
    with (
        patch("core.utils.validate_hostname", return_value=True),
        patch(
            "core.utils.resolve_nameservers",
            side_effect=[
                ["ns1.example.com"],  # First call for domain nameservers
                ["ns1.mail-domain.com"],  # Second call for mail server's domain
            ],
        ),
        patch(
            "core.utils.get_mx_records",
            AsyncMock(return_value=["mail.mail-domain.com"]),
        ),
        patch("core.utils.is_valid_ip", return_value=False),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain("example.com")

        assert domain_ns == ["ns1.example.com"]
        assert domain_mx == ["mail.mail-domain.com"]
        assert mail_ns == [["ns1.mail-domain.com"]]


@pytest.mark.asyncio
async def test_process_domain_all_empty_mail_nameservers():
    with (
        patch("core.utils.validate_hostname", return_value=True),
        patch(
            "core.utils.resolve_nameservers",
            side_effect=[
                ["ns1.example.com"],  # First call for domain nameservers
                [],  # Empty result for first mail server
                [],  # Empty result for second mail server
            ],
        ),
        patch(
            "core.utils.get_mx_records",
            AsyncMock(return_value=["mail1.example.com", "mail2.example.com"]),
        ),
        patch("core.utils.is_valid_ip", return_value=False),
    ):
        domain_ns, domain_mx, mail_ns = await process_domain("example.com")

        assert domain_ns == ["ns1.example.com"]
        assert domain_mx == ["mail1.example.com", "mail2.example.com"]
        assert mail_ns is None  # Should be None if all mail nameserver lists are empty


@pytest.mark.asyncio
async def test_process_domain_exception_in_mail_nameservers():
    with (
        patch("core.utils.validate_hostname", return_value=True),
        patch(
            "core.utils.resolve_nameservers",
            side_effect=[
                ["ns1.example.com"],  # First call for domain nameservers
                Exception("DNS error"),  # Exception during mail nameserver resolution
            ],
        ),
        patch(
            "core.utils.get_mx_records", AsyncMock(return_value=["mail.example.com"])
        ),
        patch("core.utils.is_valid_ip", return_value=False),
        patch("core.utils.logger.error"),
    ):  # Mock logger to prevent actual logging
        domain_ns, domain_mx, mail_ns = await process_domain("example.com")

        assert domain_ns == ["ns1.example.com"]
        assert domain_mx == ["mail.example.com"]
        assert mail_ns is None  # Should be None due to the exception


@pytest.mark.asyncio
async def test_process_domain_exception_in_domain_nameservers():
    with (
        patch("core.utils.validate_hostname", return_value=True),
        patch("core.utils.resolve_nameservers", side_effect=Exception("DNS error")),
        patch(
            "core.utils.get_mx_records", AsyncMock(return_value=["mail.example.com"])
        ),
        patch("core.utils.logger.error"),
    ):  # Mock logger to prevent actual logging
        domain_ns, domain_mx, mail_ns = await process_domain("example.com")

        assert domain_ns is None
        assert domain_mx == ["mail.example.com"]
        assert mail_ns is None


@pytest.mark.asyncio
async def test_process_domain_exception_in_mx_records():
    with (
        patch("core.utils.validate_hostname", return_value=True),
        patch(
            "core.utils.resolve_nameservers",
            AsyncMock(return_value=["ns1.example.com"]),
        ),
        patch("core.utils.get_mx_records", side_effect=Exception("DNS error")),
        patch("core.utils.logger.error"),
    ):  # Mock logger to prevent actual logging
        domain_ns, domain_mx, mail_ns = await process_domain("example.com")

        assert domain_ns == ["ns1.example.com"]
        assert domain_mx is None
        assert mail_ns is None
