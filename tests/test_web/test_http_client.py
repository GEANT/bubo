from unittest.mock import MagicMock, patch

import pytest

from bubo.core.web.headers import USER_AGENT
from bubo.core.web.http_client import fetch_headers


class AsyncContextManagerMock:
    def __init__(self, return_value):
        self.return_value = return_value

    async def __aenter__(self):
        return self.return_value

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.mark.asyncio
async def test_fetch_headers_non_standard_port():
    """Test that non-standard ports are included in the URL."""

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {"Server": "nginx"}

    url_called = []

    mock_session = MagicMock()
    mock_session.get = lambda url, **kwargs: (
        url_called.append(url),
        AsyncContextManagerMock(mock_response),
    )[1]

    with patch(
        "aiohttp.ClientSession", return_value=AsyncContextManagerMock(mock_session)
    ):
        await fetch_headers("example.com", 8443, 10)

        assert len(url_called) == 1
        assert url_called[0] == "https://example.com:8443"


@pytest.mark.asyncio
async def test_fetch_headers_generic_exception():
    """Test handling of unexpected exceptions."""

    class ExceptionContextManager:
        async def __aenter__(self):
            raise Exception("Unexpected error")

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    mock_session = MagicMock()
    mock_session.get = lambda *_args, **_kwargs: ExceptionContextManager()

    with (
        patch(
            "aiohttp.ClientSession", return_value=AsyncContextManagerMock(mock_session)
        ),
        patch("bubo.core.web.http_client.logger.error") as mock_logger,
        patch("asyncio.sleep") as mock_sleep,  # Mock sleep to avoid delays
    ):
        result = await fetch_headers("example.com", 443, 10)

        assert result is None

        assert mock_logger.call_count == 3

        for call in mock_logger.call_args_list:
            assert "Unexpected error" in call[0][0]
            assert call[1].get("exc_info") is True

        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(1)
        mock_sleep.assert_any_call(2)


@pytest.mark.asyncio
async def test_fetch_headers_correct_timeout_usage():
    """Test that the timeout parameter is used correctly."""

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {}

    mock_session = MagicMock()
    mock_session.get = lambda _url, **_kwargs: AsyncContextManagerMock(mock_response)

    mock_timeout = MagicMock()

    with (
        patch(
            "aiohttp.ClientSession", return_value=AsyncContextManagerMock(mock_session)
        ),
        patch("aiohttp.ClientTimeout", return_value=mock_timeout) as mock_timeout_class,
    ):
        await fetch_headers("example.com", 443, 5)

        mock_timeout_class.assert_called_once_with(total=5)


@pytest.mark.asyncio
async def test_fetch_headers_uses_correct_headers():
    """Test that the function sends the expected request headers."""

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {}

    called_kwargs = {}

    mock_session = MagicMock()
    mock_session.get = lambda _url, **kwargs: (
        called_kwargs.update(kwargs),
        AsyncContextManagerMock(mock_response),
    )[1]

    with patch(
        "aiohttp.ClientSession", return_value=AsyncContextManagerMock(mock_session)
    ):
        await fetch_headers("example.com", 443, 10)

        headers = called_kwargs.get("headers", {})
        assert headers["User-Agent"] == USER_AGENT
        assert "text/html" in headers["Accept"]
        assert headers["Connection"] == "keep-alive"


@pytest.mark.asyncio
async def test_fetch_headers_ssl_disabled():
    """Test that SSL verification is disabled."""

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {}

    called_kwargs = {}

    mock_session = MagicMock()
    mock_session.get = lambda _url, **kwargs: (
        called_kwargs.update(kwargs),
        AsyncContextManagerMock(mock_response),
    )[1]

    with patch(
        "aiohttp.ClientSession", return_value=AsyncContextManagerMock(mock_session)
    ):
        await fetch_headers("example.com", 443, 10)

        assert called_kwargs.get("ssl") is False
