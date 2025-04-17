import pytest
import asyncio
import ssl
import socket
from unittest.mock import patch, MagicMock

from core.tls.protocols import (
    check_protocol_with_socket,
    check_protocol_with_openssl,
    check_protocol,
    process_protocol_results,
)
from core.tls.models import (
    TLSProtocol,
    TLSProtocolResult,
    TLSCheckConfig,
)


@pytest.mark.asyncio
async def test_socket_check_successful_connection():
    with (
        patch("socket.socket") as mock_socket,
        patch("ssl.SSLContext") as mock_context,
        patch("asyncio.to_thread"),
        patch("asyncio.wait_for") as mock_wait_for,
    ):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.version.return_value = "TLSv1.2"

        mock_ctx = MagicMock()
        mock_context.return_value = mock_ctx

        mock_wait_for.side_effect = [mock_sock, mock_ssl_sock]

        result, error = await check_protocol_with_socket(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is True
        assert error is None
        mock_socket.assert_called_once()
        mock_context.assert_called_once()


@pytest.mark.asyncio
async def test_socket_check_connection_timeout():
    with (
        patch("socket.socket") as mock_socket,
        patch("asyncio.wait_for") as mock_wait_for,
    ):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock

        mock_wait_for.side_effect = asyncio.TimeoutError()

        result, error = await check_protocol_with_socket(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is False
        assert "Connection timeout" in error


@pytest.mark.asyncio
async def test_socket_check_connection_error():
    with (
        patch("socket.socket") as mock_socket,
        patch("asyncio.wait_for") as mock_wait_for,
    ):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock

        mock_wait_for.side_effect = socket.error("Connection refused")

        result, error = await check_protocol_with_socket(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is False
        assert "Connection error" in error


@pytest.mark.asyncio
async def test_socket_check_handshake_timeout():
    with (
        patch("socket.socket") as mock_socket,
        patch("ssl.SSLContext") as mock_context,
        patch("asyncio.wait_for") as mock_wait_for,
    ):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_context.return_value = mock_ctx

        mock_wait_for.side_effect = [mock_sock, asyncio.TimeoutError()]

        result, error = await check_protocol_with_socket(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is False
        assert "TLS handshake timeout" in error


@pytest.mark.asyncio
async def test_socket_check_protocol_not_supported():
    with (
        patch("socket.socket") as mock_socket,
        patch("ssl.SSLContext") as mock_context,
        patch("asyncio.wait_for") as mock_wait_for,
    ):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_context.return_value = mock_ctx

        mock_wait_for.side_effect = [mock_sock, ssl.SSLError("wrong version")]

        result, error = await check_protocol_with_socket(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is False
        assert "Protocol not supported" in error


@pytest.mark.asyncio
async def test_socket_check_protocol_mismatch():
    with (
        patch("socket.socket") as mock_socket,
        patch("ssl.SSLContext") as mock_context,
        patch("asyncio.wait_for") as mock_wait_for,
    ):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.version.return_value = "TLSv1.1"

        mock_ctx = MagicMock()
        mock_context.return_value = mock_ctx

        mock_wait_for.side_effect = [mock_sock, mock_ssl_sock]

        result, error = await check_protocol_with_socket(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is False
        assert "Protocol mismatch" in error


@pytest.mark.asyncio
async def test_socket_check_application_data_after_close():
    with (
        patch("socket.socket") as mock_socket,
        patch("ssl.SSLContext") as mock_context,
        patch("asyncio.wait_for") as mock_wait_for,
    ):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_context.return_value = mock_ctx

        mock_wait_for.side_effect = [
            mock_sock,
            ssl.SSLError("application data after close notify"),
        ]

        result, error = await check_protocol_with_socket(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is True
        assert error is None


@pytest.mark.asyncio
async def test_openssl_check_successful():
    with (
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
        patch("core.tls.protocols.run_openssl_command") as mock_run_command,
    ):
        mock_has_openssl.return_value = True

        mock_run_command.return_value = (
            "Protocol  : TLSv1.2\nCipher    : ECDHE-RSA-AES256-GCM-SHA384",
            0,
        )

        result, error = await check_protocol_with_openssl(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is True
        assert error is None
        mock_run_command.assert_called_once()


@pytest.mark.asyncio
async def test_openssl_check_not_available():
    with patch("core.tls.protocols.has_openssl") as mock_has_openssl:
        mock_has_openssl.return_value = False

        result, error = await check_protocol_with_openssl(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is False
        assert "OpenSSL not found" in error


@pytest.mark.asyncio
async def test_openssl_check_handshake_failure():
    with (
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
        patch("core.tls.protocols.run_openssl_command") as mock_run_command,
    ):
        mock_has_openssl.return_value = True

        mock_run_command.return_value = ("sslv3 alert handshake failure", 1)

        result, error = await check_protocol_with_openssl(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is False
        assert "Protocol not supported" in error


@pytest.mark.asyncio
async def test_openssl_check_no_cipher():
    with (
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
        patch("core.tls.protocols.run_openssl_command") as mock_run_command,
    ):
        mock_has_openssl.return_value = True

        mock_run_command.return_value = ("Protocol  : TLSv1.2\nCipher    : (NONE)", 0)

        result, error = await check_protocol_with_openssl(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is False
        assert "Protocol not supported" in error


@pytest.mark.asyncio
async def test_openssl_check_new_cipher_format():
    with (
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
        patch("core.tls.protocols.run_openssl_command") as mock_run_command,
    ):
        mock_has_openssl.return_value = True

        mock_run_command.return_value = (
            "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384",
            0,
        )

        result, error = await check_protocol_with_openssl(
            "example.com", 443, TLSProtocol.TLSv1_2, 10
        )

        assert result is True
        assert error is None


@pytest.mark.asyncio
async def test_check_protocol_socket_success():
    with (
        patch("core.tls.protocols.check_protocol_with_socket") as mock_socket_check,
        patch("core.tls.protocols.check_protocol_with_openssl") as mock_openssl_check,
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
    ):
        mock_socket_check.return_value = (True, None)
        mock_has_openssl.return_value = True

        config = TLSCheckConfig(
            use_openssl=True, timeout_connect=10, timeout_command=10
        )
        result = await check_protocol("example.com", 443, TLSProtocol.TLSv1_2, config)

        assert result.supported is True
        assert result.protocol_name == "TLSv1.2"
        assert result.secure is True
        assert result.error is None

        mock_socket_check.assert_called_once()
        mock_openssl_check.assert_not_called()


@pytest.mark.asyncio
async def test_check_protocol_socket_fails_openssl_succeeds():
    with (
        patch("core.tls.protocols.check_protocol_with_socket") as mock_socket_check,
        patch("core.tls.protocols.check_protocol_with_openssl") as mock_openssl_check,
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
    ):
        mock_socket_check.return_value = (False, "Protocol not supported")
        mock_openssl_check.return_value = (True, None)
        mock_has_openssl.return_value = True

        config = TLSCheckConfig(
            use_openssl=True, timeout_connect=10, timeout_command=10
        )
        result = await check_protocol("example.com", 443, TLSProtocol.TLSv1_2, config)

        assert result.supported is True
        assert result.protocol_name == "TLSv1.2"
        assert result.secure is True
        assert result.error is None

        mock_socket_check.assert_called_once()
        mock_openssl_check.assert_called_once()


@pytest.mark.asyncio
async def test_check_protocol_both_methods_fail_for_tls12():
    with (
        patch("core.tls.protocols.check_protocol_with_socket") as mock_socket_check,
        patch("core.tls.protocols.check_protocol_with_openssl") as mock_openssl_check,
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
    ):
        mock_socket_check.return_value = (False, "Protocol not supported")
        mock_openssl_check.return_value = (False, "Protocol not supported")
        mock_has_openssl.return_value = True

        config = TLSCheckConfig(
            use_openssl=True, timeout_connect=10, timeout_command=10
        )
        result = await check_protocol("example.com", 443, TLSProtocol.TLSv1_2, config)

        assert result.supported is False
        assert result.protocol_name == "TLSv1.2"
        assert result.secure is True
        assert "Security issue" in result.error
        assert "TLSv1.2" in result.error

        mock_socket_check.assert_called_once()
        mock_openssl_check.assert_called_once()


@pytest.mark.asyncio
async def test_check_protocol_both_methods_fail_for_tls13():
    with (
        patch("core.tls.protocols.check_protocol_with_socket") as mock_socket_check,
        patch("core.tls.protocols.check_protocol_with_openssl") as mock_openssl_check,
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
    ):
        mock_socket_check.return_value = (False, "Protocol not supported")
        mock_openssl_check.return_value = (False, "Protocol not supported")
        mock_has_openssl.return_value = True

        config = TLSCheckConfig(
            use_openssl=True, timeout_connect=10, timeout_command=10
        )
        result = await check_protocol("example.com", 443, TLSProtocol.TLSv1_3, config)

        assert result.supported is False
        assert result.protocol_name == "TLSv1.3"
        assert result.secure is True
        assert "Security issue" in result.error
        assert "TLSv1.3" in result.error

        mock_socket_check.assert_called_once()
        mock_openssl_check.assert_called_once()


@pytest.mark.asyncio
async def test_check_protocol_unsupported_old_protocols():
    with (
        patch("core.tls.protocols.check_protocol_with_socket") as mock_socket_check,
        patch("core.tls.protocols.check_protocol_with_openssl") as mock_openssl_check,
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
    ):
        mock_socket_check.return_value = (False, "Protocol not supported")
        mock_openssl_check.return_value = (False, "Protocol not supported")
        mock_has_openssl.return_value = True

        config = TLSCheckConfig(
            use_openssl=True, timeout_connect=10, timeout_command=10
        )

        # TLSv1.0
        result = await check_protocol("example.com", 443, TLSProtocol.TLSv1_0, config)
        assert result.supported is False
        assert result.protocol_name == "TLSv1.0"
        assert result.secure is False
        assert result.error is None  # No error for unsupported TLSv1.0 (good)

        # TLSv1.1
        mock_socket_check.reset_mock()
        mock_openssl_check.reset_mock()
        result = await check_protocol("example.com", 443, TLSProtocol.TLSv1_1, config)
        assert result.supported is False
        assert result.protocol_name == "TLSv1.1"
        assert result.secure is False
        assert result.error is None  # No error for unsupported TLSv1.1 (good)


@pytest.mark.asyncio
async def test_check_protocol_openssl_disabled():
    with (
        patch("core.tls.protocols.check_protocol_with_socket") as mock_socket_check,
        patch("core.tls.protocols.check_protocol_with_openssl") as mock_openssl_check,
        patch("core.tls.protocols.has_openssl") as mock_has_openssl,
    ):
        mock_socket_check.return_value = (False, "Protocol not supported")
        mock_has_openssl.return_value = True

        config = TLSCheckConfig(
            use_openssl=False, timeout_connect=10, timeout_command=10
        )
        result = await check_protocol("example.com", 443, TLSProtocol.TLSv1_2, config)

        assert result.supported is False
        assert result.protocol_name == "TLSv1.2"
        assert "Security issue" in result.error

        mock_socket_check.assert_called_once()
        mock_openssl_check.assert_not_called()


def test_process_protocol_results_successful():
    results = [
        TLSProtocolResult(protocol_name="TLSv1.2", supported=True, secure=True),
        TLSProtocolResult(protocol_name="TLSv1.3", supported=True, secure=True),
        TLSProtocolResult(protocol_name="TLSv1.0", supported=False, secure=False),
    ]
    protocols = [TLSProtocol.TLSv1_2, TLSProtocol.TLSv1_3, TLSProtocol.TLSv1_0]

    processed_results, supported_protocols = process_protocol_results(
        results, protocols
    )

    assert len(processed_results) == 3
    assert len(supported_protocols) == 2
    assert supported_protocols == [TLSProtocol.TLSv1_2, TLSProtocol.TLSv1_3]


def test_process_protocol_results_with_exceptions():
    results = [
        TLSProtocolResult(protocol_name="TLSv1.2", supported=True, secure=True),
        Exception("Test error"),
        TLSProtocolResult(protocol_name="TLSv1.0", supported=False, secure=False),
    ]
    protocols = [TLSProtocol.TLSv1_2, TLSProtocol.TLSv1_3, TLSProtocol.TLSv1_0]

    processed_results, supported_protocols = process_protocol_results(
        results, protocols
    )

    assert len(processed_results) == 3
    assert len(supported_protocols) == 1
    assert supported_protocols == [TLSProtocol.TLSv1_2]
    assert processed_results[1].protocol_name == "TLSv1.3"
    assert processed_results[1].supported is False
    assert "Error: Test error" in processed_results[1].error


def test_process_protocol_results_no_supported_protocols():
    results = [
        TLSProtocolResult(protocol_name="TLSv1.2", supported=False, secure=True),
        TLSProtocolResult(protocol_name="TLSv1.3", supported=False, secure=True),
        TLSProtocolResult(protocol_name="TLSv1.0", supported=False, secure=False),
    ]
    protocols = [TLSProtocol.TLSv1_2, TLSProtocol.TLSv1_3, TLSProtocol.TLSv1_0]

    processed_results, supported_protocols = process_protocol_results(
        results, protocols
    )

    assert len(processed_results) == 3
    assert len(supported_protocols) == 0
