# tests/test_file_processing.py

import pytest
from unittest.mock import patch, mock_open
from core.io.file_processor import process_file


@pytest.mark.asyncio
async def test_process_file_csv():
    """Test processing a CSV file with mock_open."""
    file_path = "nrens.csv"
    file_content = "Domain,Country,Institution\nexample.com,US,Example Inc\ndomain.org,UK,Domain Org\ntest.net,DE,Test Network\n"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=file_content)),
    ):
        result = await process_file(file_path)

        assert len(result) == 3
        assert result[0]["Domain"] == "test.net"
        assert result[0]["Institution"] == "Test Network"
        assert result[1]["Domain"] == "domain.org"
        assert result[1]["Country"] == "UK"
        assert result[2]["Domain"] == "example.com"
        assert result[2]["Institution"] == "Example Inc"


@pytest.mark.asyncio
async def test_process_txt_file():
    file_path = "domains.txt"
    txt_content = "example.com\nexample.org\n"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=txt_content)),
    ):
        result = await process_file(file_path)
        assert len(result) == 2
        assert result[0]["Domain"] == "example.com"
        assert result[1]["Domain"] == "example.org"


@pytest.mark.asyncio
async def test_process_invalid_file():
    with pytest.raises(Exception), patch("pathlib.Path.exists", return_value=False):
        await process_file("nonexistent.xyz")


@pytest.mark.asyncio
async def test_process_file_txt():
    """Test processing a TXT file with mock_open."""
    file_path = "domains.txt"
    file_content = "example.com\ndomain.org\ntest.net\n"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=file_content)),
    ):
        result = await process_file(file_path)

        assert len(result) == 3
        assert result[0]["Domain"] == "example.com"
        assert result[1]["Domain"] == "domain.org"
        assert result[2]["Domain"] == "test.net"


@pytest.mark.asyncio
async def test_process_file_txt_empty_lines():
    """Test processing a TXT file with empty lines."""
    file_path = "domains.txt"
    file_content = "example.com\n\ndomain.org\n\ntest.net\n"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=file_content)),
    ):
        result = await process_file(file_path)

        assert len(result) == 3  # Should skip empty lines
        assert result[0]["Domain"] == "example.com"
        assert result[1]["Domain"] == "domain.org"
        assert result[2]["Domain"] == "test.net"


@pytest.mark.asyncio
async def test_process_file_csv_missing_columns():
    """Test processing a CSV file with missing optional columns."""
    file_path = "domains.csv"
    file_content = "Domain\nexample.com\ndomain.org\ntest.net\n"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=file_content)),
    ):
        result = await process_file(file_path)

        assert len(result) == 3
        assert result[0]["Domain"] == "example.com"
        assert result[0]["Country"] == ""  # Default value for missing column
        assert result[0]["Institution"] == ""  # Default value for missing column


@pytest.mark.asyncio
async def test_process_file_csv_no_domain_column():
    """Test processing a CSV file without a Domain column."""
    file_path = "domains.csv"
    file_content = "Name,Country,Institution\nExample,US,Example Inc\n"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=file_content)),
    ):
        with pytest.raises(Exception) as excinfo:
            await process_file(file_path)

        assert "CSV file must contain a 'Domain' column" in str(excinfo.value)


@pytest.mark.asyncio
async def test_process_file_csv_empty_domain():
    """Test processing a CSV file with empty Domain values."""
    file_path = "domains.csv"
    file_content = "Domain,Country,Institution\nexample.com,US,Example Inc\n,UK,Domain Org\ntest.net,DE,Test Network\n"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=file_content)),
    ):
        result = await process_file(file_path)

        assert len(result) == 2  # Should skip the row with empty Domain
        assert any(r["Domain"] == "test.net" for r in result)
        assert any(r["Domain"] == "example.com" for r in result)


@pytest.mark.asyncio
async def test_process_file_sort_by_country():
    """Test sorting by Country."""
    file_path = "domains.csv"
    file_content = "Domain,Country,Institution\nexample.com,US,Example Inc\ndomain.org,UK,Domain Org\ntest.net,DE,Test Network\n"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=file_content)),
    ):
        result = await process_file(file_path, sort_by="Country")

        # Should be sorted by Country (DE comes first alphabetically)
        assert result[0]["Country"] == "DE"
        assert result[1]["Country"] == "UK"
        assert result[2]["Country"] == "US"


@pytest.mark.asyncio
async def test_process_file_sort_by_nonexistent_column():
    """Test sorting by a column that doesn't exist."""
    file_path = "domains.csv"
    file_content = "Domain,Country,Institution\nexample.com,US,Example Inc\ndomain.org,UK,Domain Org\ntest.net,DE,Test Network\n"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=file_content)),
    ):
        # Should not raise an error, just ignore the sort
        result = await process_file(file_path, sort_by="NonexistentColumn")

        # Check that we got all domains
        domains = [r["Domain"] for r in result]
        assert "example.com" in domains
        assert "domain.org" in domains
        assert "test.net" in domains


@pytest.mark.asyncio
async def test_process_file_unsupported_extension():
    """Test with an unsupported file extension."""
    file_path = "domains.xlsx"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
    ):
        with pytest.raises(Exception) as excinfo:
            await process_file(file_path)

        assert "Invalid file format" in str(excinfo.value)


@pytest.mark.asyncio
async def test_process_file_file_not_found():
    """Test with a file that doesn't exist."""
    file_path = "nonexistent.txt"

    # Simulate os.path.isfile check failing
    with (
        patch("os.path.isfile", return_value=False),
        patch("os.path.abspath", return_value=file_path),
    ):
        with pytest.raises(Exception) as excinfo:
            await process_file(file_path)

        assert "File does not exist" in str(excinfo.value)


@pytest.mark.asyncio
async def test_process_file_permission_error():
    """Test with a file that can't be opened due to permissions."""
    file_path = "protected.txt"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", side_effect=PermissionError("Permission denied")),
    ):
        with pytest.raises(Exception) as excinfo:
            await process_file(file_path)

        assert "Error processing file" in str(excinfo.value)


@pytest.mark.asyncio
async def test_process_file_csv_invalid_format():
    """Test with a CSV file that has invalid format."""
    file_path = "invalid.csv"
    file_content = "This is not a valid CSV file"

    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.abspath", return_value=file_path),
        patch("builtins.open", mock_open(read_data=file_content)),
    ):
        with pytest.raises(Exception) as excinfo:
            await process_file(file_path)

        assert "Error processing" in str(excinfo.value)
