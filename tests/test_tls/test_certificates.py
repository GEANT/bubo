import asyncio
import datetime
import socket
from unittest.mock import MagicMock, patch

import pytest

from core.tls.certificates import (
    check_certificate,
    check_certificate_chain,
    check_certificate_with_socket,
)
from core.tls.models import (
    CertificateResult,
    KeyInfo,
    SANInfo,
    SignatureAlgorithmInfo,
    SignatureAlgorithmSecurity,
    TLSCheckConfig,
)


@pytest.fixture
def tls_check_config():
    return TLSCheckConfig(
        check_certificate=True,
        verify_chain=True,
        check_key_info=True,
        check_signature_algorithm=True,
        check_san=True,
        use_openssl=True,
        timeout_connect=5,
        timeout_command=10,
    )


@pytest.fixture
def mock_utils():
    with (
        patch("core.tls.certificates.has_openssl") as mock_has_openssl,
        patch("core.tls.certificates.run_openssl_command") as mock_run_openssl,
        patch("core.tls.certificates.create_error_cert_result") as mock_error_result,
        patch("core.tls.certificates.extract_key_info") as mock_key_info,
        patch("core.tls.certificates.extract_signature_algorithm") as mock_sig_algo,
        patch("core.tls.certificates.extract_san_info") as mock_san_info,
        patch("core.tls.certificates.format_x509_name") as mock_format_name,
        patch("core.tls.certificates.format_serial_number") as mock_serial,
    ):
        mock_has_openssl.return_value = True
        mock_run_openssl.return_value = (
            "Verify return code: 0 (ok)\n"
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDzTCCArWgAwIBAgIUJ2xF7kw4a2tQx2yZl8zrxpEd8KAwDQYJKoZIhvcNAQEL\n"
            "-----END CERTIFICATE-----\n",
            0,
        )

        mock_error_result.return_value = CertificateResult(
            subject="Unknown",
            issuer="Unknown",
            valid_from="1970-01-01T00:00:00",
            valid_until="1970-01-01T00:00:00",
            is_valid=False,
            is_expired=True,
            days_until_expiry=-365,
            is_self_signed=False,
            validation_error="Mock error",
            connection_error=False,
        )

        mock_key_info.return_value = KeyInfo(type="RSA", length=2048, secure=True)

        mock_sig_algo.return_value = SignatureAlgorithmInfo(
            name="sha256WithRSAEncryption", security=SignatureAlgorithmSecurity.STRONG
        )

        mock_san_info.return_value = SANInfo(
            names=["DNS:example.com", "DNS:www.example.com"], contains_domain=True
        )

        mock_format_name.side_effect = (
            lambda x: "CN=example.com,O=Example Org"
            if "example.com" in str(x)
            else "CN=Example CA,O=Example CA Org"
        )
        mock_serial.return_value = "DEADBEEF"

        yield {
            "has_openssl": mock_has_openssl,
            "run_openssl_command": mock_run_openssl,
            "create_error_cert_result": mock_error_result,
            "extract_key_info": mock_key_info,
            "extract_signature_algorithm": mock_sig_algo,
            "extract_san_info": mock_san_info,
            "format_x509_name": mock_format_name,
            "format_serial_number": mock_serial,
        }


class TestCertificateWithSocket:
    @pytest.mark.asyncio
    async def test_check_certificate_with_socket_connection_timeout(
        self, tls_check_config, mock_utils
    ):
        """Test connection timeout during certificate check."""
        domain = "example.com"
        port = 443
        timeout = 5

        with patch("socket.socket") as mock_socket_create:
            mock_sock = MagicMock()
            mock_socket_create.return_value = mock_sock

            connection_error_result = CertificateResult(
                subject="Unknown",
                issuer="Unknown",
                valid_from="1970-01-01T00:00:00",
                valid_until="1970-01-01T00:00:00",
                is_valid=False,
                is_expired=True,
                days_until_expiry=-365,
                is_self_signed=False,
                validation_error="Connection timeout to example.com:443",
                connection_error=True,
            )
            mock_utils[
                "create_error_cert_result"
            ].return_value = connection_error_result

            result = await check_certificate_with_socket(
                domain, port, timeout, tls_check_config
            )

            assert result.is_valid is False
            assert "Connection timeout" in result.validation_error
            assert result.connection_error is True

    @pytest.mark.asyncio
    async def test_check_certificate_with_socket_handshake_timeout(
        self, tls_check_config, mock_utils
    ):
        """Test TLS handshake timeout during certificate check."""
        domain = "example.com"
        port = 443
        timeout = 5

        with patch("socket.socket") as mock_socket_create:
            mock_sock = MagicMock()
            mock_socket_create.return_value = mock_sock

            mock_sock.connect.return_value = None

            async def mock_wait_for(coro, timeout):
                if mock_wait_for.call_count == 1:
                    mock_wait_for.call_count += 1
                    return await coro
                else:
                    raise asyncio.TimeoutError()

            mock_wait_for.call_count = 0

            with patch("asyncio.wait_for", side_effect=mock_wait_for):
                handshake_error_result = CertificateResult(
                    subject="Unknown",
                    issuer="Unknown",
                    valid_from="1970-01-01T00:00:00",
                    valid_until="1970-01-01T00:00:00",
                    is_valid=False,
                    is_expired=True,
                    days_until_expiry=-365,
                    is_self_signed=False,
                    validation_error="TLS handshake timeout",
                    connection_error=True,
                )
                mock_utils[
                    "create_error_cert_result"
                ].return_value = handshake_error_result

                result = await check_certificate_with_socket(
                    domain, port, timeout, tls_check_config
                )

                assert result.is_valid is False
                assert "TLS handshake timeout" in result.validation_error
                assert result.connection_error is True

    @pytest.mark.asyncio
    async def test_certificate_parsing_error_handling(self, tls_check_config):
        """Test correct handling of certificate parsing errors while still returning basic cert data."""
        domain = "example.com"
        port = 443

        async def mock_socket_check(domain, port, timeout, config):
            result = CertificateResult(
                subject="example.com",
                issuer="Example CA",
                valid_from="2023-01-01T00:00:00",
                valid_until="2025-01-01T00:00:00",
                is_valid=True,
                is_expired=False,
                days_until_expiry=365,
                is_self_signed=False,
                validation_error=None,
            )

            if config.check_key_info:
                result.key_info = None

            if config.check_signature_algorithm:
                result.signature_algorithm = None

            if config.check_san:
                result.subject_alternative_names = None

            return result

        with patch(
            "core.tls.certificates.check_certificate_with_socket",
            side_effect=mock_socket_check,
        ) as mock_check:
            result = await check_certificate(domain, port, tls_check_config)

            assert result.is_valid is True
            assert result.subject == "example.com"
            assert result.issuer == "Example CA"

            assert result.key_info is None
            assert result.signature_algorithm is None
            assert result.subject_alternative_names is None

            mock_check.assert_called_once_with(
                domain, port, tls_check_config.timeout_connect, tls_check_config
            )

    @pytest.mark.asyncio
    async def test_check_certificate_with_socket_self_signed_detection(
        self, tls_check_config
    ):
        """Test that check_certificate correctly preserves the self-signed certificate status."""
        domain = "example.com"
        port = 443

        self_signed_cert = CertificateResult(
            subject="example.com",
            issuer="example.com",
            valid_from="2023-01-01T00:00:00",
            valid_until="2025-01-01T00:00:00",
            is_valid=True,
            is_expired=False,
            days_until_expiry=365,
            is_self_signed=True,
            validation_error=None,
        )

        with patch(
            "core.tls.certificates.check_certificate_with_socket",
            return_value=self_signed_cert,
        ) as mock_check:
            result = await check_certificate(domain, port, tls_check_config)

            assert result.is_valid is True
            assert result.is_self_signed is True
            assert result.subject == "example.com"
            assert result.issuer == "example.com"

            mock_check.assert_called_once_with(
                domain, port, tls_check_config.timeout_connect, tls_check_config
            )

    @pytest.mark.asyncio
    async def test_socket_timeout_error(self, tls_check_config):
        """Test handling of socket timeout errors."""
        domain = "example.com"
        port = 443
        timeout = 5

        with patch("socket.socket") as mock_socket:
            mock_socket_instance = MagicMock()
            mock_socket.return_value = mock_socket_instance

            mock_socket_instance.connect.side_effect = socket.timeout(
                "Connection timed out"
            )

            result = await check_certificate_with_socket(
                domain, port, timeout, tls_check_config
            )

            assert result.is_valid is False
            assert f"Connection timeout to {domain}:{port}" in result.validation_error
            assert result.connection_error is True

    @pytest.mark.asyncio
    async def test_no_certificate_data(self, tls_check_config, mock_utils):
        """Test handling of no certificate data being received."""
        domain = "example.com"
        port = 443
        timeout = 5

        error_result = CertificateResult(
            subject="Unknown",
            issuer="Unknown",
            valid_from="Unknown",
            valid_until="Unknown",
            is_valid=False,
            is_expired=True,
            days_until_expiry=None,
            is_self_signed=False,
            validation_error="No certificate data received",
            connection_error=False,
        )
        mock_utils["create_error_cert_result"].return_value = error_result

        with (
            patch("socket.socket") as mock_socket,
            patch("ssl.create_default_context") as mock_ssl_context,
            patch("asyncio.wait_for") as mock_wait_for,
            patch("asyncio.create_task") as mock_create_task,
        ):
            mock_sock = MagicMock()
            mock_socket.return_value = mock_sock

            mock_create_task.side_effect = lambda coro: coro

            async def mock_wait_for_impl(coro, timeout):
                return await coro

            mock_wait_for.side_effect = mock_wait_for_impl

            mock_ssl_sock = MagicMock()
            mock_ssl_sock.getpeercert.return_value = None

            async def mock_to_thread(func, *args, **kwargs):
                if func == mock_sock.connect:
                    return None
                elif func == mock_ssl_context.return_value.wrap_socket:
                    return mock_ssl_sock
                return None

            with patch("asyncio.to_thread", side_effect=mock_to_thread):
                result = await check_certificate_with_socket(
                    domain, port, timeout, tls_check_config
                )

                assert result.is_valid is False
                assert "No certificate data received" in result.validation_error

                mock_utils["create_error_cert_result"].assert_called_once_with(
                    "No certificate data received"
                )


class TestCertificateChain:
    @pytest.mark.asyncio
    async def test_chain_with_partial_parsing_failures(self, mock_utils):
        """Test certificate chain with some parsing failures."""
        domain = "example.com"
        port = 443
        timeout = 10

        mock_output = (
            "Verify return code: 0 (ok)\n"
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDzTCCArWgAwIBAgIUJ2xF7kw4a2tQx2yZl8zrxpEd8KAwDQYJKoZIhvcNAQEL\n"
            "-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\n"
            "INVALID_CERT_DATA\n"
            "-----END CERTIFICATE-----\n"
        )
        mock_utils["run_openssl_command"].return_value = (mock_output, 0)

        with patch("cryptography.x509.load_pem_x509_certificate") as mock_load_pem:
            cert1 = MagicMock()
            cert1.subject = MagicMock()
            cert1.issuer = MagicMock()
            cert1.not_valid_before_utc = datetime.datetime(2023, 1, 1)
            cert1.not_valid_after_utc = datetime.datetime(2025, 1, 1)
            cert1.extensions.get_extension_for_oid.return_value = None

            mock_load_pem.side_effect = [cert1, Exception("Invalid certificate format")]

            (
                is_trusted,
                is_valid,
                chain_length,
                chain_info,
                error_message,
            ) = await check_certificate_chain(domain, port, timeout)

            assert is_trusted is True
            assert is_valid is True
            assert chain_length == 2
            assert len(chain_info) == 2
            assert "position" in chain_info[0]
            assert "position" in chain_info[1]
            assert "parsing_error" in chain_info[1]

    @pytest.mark.asyncio
    async def test_chain_with_no_certificates_but_depth_info(self, mock_utils):
        """Test certificate chain with no PEM certificates but depth info present."""
        domain = "example.com"
        port = 443
        timeout = 10

        mock_output = (
            "Verify return code: 0 (ok)\n"
            "depth=2 CN = Root CA\n"
            "verify return:1\n"
            "depth=1 CN = Intermediate CA\n"
            "verify return:1\n"
            "depth=0 CN = example.com\n"
            "verify return:1\n"
        )
        mock_utils["run_openssl_command"].return_value = (mock_output, 0)

        (
            is_trusted,
            is_valid,
            chain_length,
            chain_info,
            error_message,
        ) = await check_certificate_chain(domain, port, timeout)

        assert is_trusted is True
        assert is_valid is True
        assert chain_length == 3
        assert len(chain_info) == 3
        assert chain_info[0]["position"] == "0"
        assert "subject" in chain_info[0]

    @pytest.mark.asyncio
    async def test_chain_with_verify_return_depths(self, mock_utils):
        """Test certificate chain with verify return depth information only."""
        domain = "example.com"
        port = 443
        timeout = 10

        mock_output = (
            "depth=2 O = Root CA\n"
            "verify return:1\n"
            "depth=1 O = Intermediate CA\n"
            "verify return:1\n"
            "depth=0 CN = example.com\n"
            "verify return:0\n"
            "Verify return code: 0 (ok)\n"
        )
        mock_utils["run_openssl_command"].return_value = (mock_output, 0)

        (
            is_trusted,
            is_valid,
            chain_length,
            chain_info,
            error_message,
        ) = await check_certificate_chain(domain, port, timeout)

        assert is_trusted is True
        assert is_valid is True
        assert chain_length == 3
        assert len(chain_info) > 0

    @pytest.mark.asyncio
    async def test_check_certificate_chain_exception(self, mock_utils):
        """Test exception handling during certificate chain check."""
        domain = "example.com"
        port = 443
        timeout = 10

        mock_utils["run_openssl_command"].side_effect = Exception(
            "OpenSSL command failed"
        )

        (
            is_trusted,
            is_valid,
            chain_length,
            chain_info,
            error_message,
        ) = await check_certificate_chain(domain, port, timeout)

        assert is_trusted is False
        assert is_valid is False
        assert chain_length == 0
        assert len(chain_info) == 0
        assert error_message is not None
        assert "Error checking certificate chain" in error_message
        assert mock_utils["run_openssl_command"].called

    @pytest.mark.asyncio
    async def test_check_certificate_chain_success(self, mock_utils):
        """Test successful certificate chain verification."""
        domain = "example.com"
        port = 443
        timeout = 10

        mock_output = (
            "Verify return code: 0 (ok)\n"
            "depth=2 CN = Root CA\n"
            "verify return:1\n"
            "depth=1 CN = Intermediate CA\n"
            "verify return:1\n"
            "depth=0 CN = example.com\n"
            "verify return:1\n"
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDzTCCArWgAwIBAgIUJ2xF7kw4a2tQx2yZl8zrxpEd8KAwDQYJKoZIhvcNAQEL\n"
            "-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\n"
            "ABCDzTCCArWgAwIBAgIUJ2xF7kw4a2tQx2yZl8zrxpEd8KAwDQYJKoZIhvcNAQEL\n"
            "-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\n"
            "XYZDzTCCArWgAwIBAgIUJ2xF7kw4a2tQx2yZl8zrxpEd8KAwDQYJKoZIhvcNAQEL\n"
            "-----END CERTIFICATE-----\n"
        )
        mock_utils["run_openssl_command"].return_value = (mock_output, 0)

        with patch("cryptography.x509.load_pem_x509_certificate") as mock_load_pem:
            mock_certs = []
            for i, name in enumerate(["example.com", "Intermediate CA", "Root CA"]):
                mock_cert = MagicMock()
                mock_cert.subject = f"CN={name}"
                mock_cert.issuer = (
                    f"CN={'Root CA' if i == 2 else ['Intermediate CA', 'Root CA'][i]}"
                )
                mock_cert.not_valid_before_utc = datetime.datetime(2023, 1, 1)
                mock_cert.not_valid_after_utc = datetime.datetime(2025, 1, 1)
                mock_certs.append(mock_cert)

            mock_load_pem.side_effect = mock_certs

            (
                is_trusted,
                is_valid,
                chain_length,
                chain_info,
                error_message,
            ) = await check_certificate_chain(domain, port, timeout)

            assert is_trusted is True
            assert is_valid is True
            assert chain_length == 3
            assert len(chain_info) == 3
            assert error_message is None

    @pytest.mark.asyncio
    async def test_check_certificate_chain_self_signed(self, mock_utils):
        """Test certificate chain with self-signed certificate."""
        domain = "example.com"
        port = 443
        timeout = 10

        mock_output = (
            "Verify return code: 19 (self signed certificate in certificate chain)\n"
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDzTCCArWgAwIBAgIUJ2xF7kw4a2tQx2yZl8zrxpEd8KAwDQYJKoZIhvcNAQEL\n"
            "-----END CERTIFICATE-----\n"
        )
        mock_utils["run_openssl_command"].return_value = (mock_output, 1)

        with patch("cryptography.x509.load_pem_x509_certificate") as mock_load_pem:
            mock_cert = MagicMock()
            mock_cert.subject = "CN=example.com, O=Example Org"
            mock_cert.issuer = "CN=example.com, O=Example Org"
            mock_cert.not_valid_before_utc = datetime.datetime(2023, 1, 1)
            mock_cert.not_valid_after_utc = datetime.datetime(2025, 1, 1)

            mock_load_pem.return_value = mock_cert

            mock_utils["format_x509_name"].side_effect = lambda x: x

            (
                is_trusted,
                is_valid,
                chain_length,
                chain_info,
                error_message,
            ) = await check_certificate_chain(domain, port, timeout)

            assert is_trusted is False
            assert is_valid is False
            assert chain_length == 1
            assert len(chain_info) == 1
            assert chain_info[0].get("is_self_signed", False) is True
            assert error_message is not None
            assert (
                "self signed" in error_message.lower() or "Self-signed" in error_message
            )


class TestCertificate:
    @pytest.mark.asyncio
    async def test_check_certificate_with_failed_chain_validation(
        self, tls_check_config
    ):
        """Test certificate check with valid cert but failed chain validation."""
        domain = "example.com"
        port = 443

        with (
            patch(
                "core.tls.certificates.check_certificate_with_socket"
            ) as mock_check_socket,
            patch("core.tls.certificates.has_openssl") as mock_has_openssl,
            patch("core.tls.certificates.check_certificate_chain") as mock_check_chain,
        ):
            mock_check_socket.return_value = CertificateResult(
                subject="example.com",
                issuer="Example CA",
                valid_from="2023-01-01T00:00:00",
                valid_until="2025-01-01T00:00:00",
                is_valid=True,
                is_expired=False,
                days_until_expiry=365,
                is_self_signed=False,
                validation_error=None,
            )

            mock_has_openssl.return_value = True

            mock_check_chain.return_value = (
                False,
                False,
                2,
                [
                    {"position": 0, "subject": "CN=example.com"},
                    {"position": 1, "subject": "CN=Example CA"},
                ],
                "Chain validation failed: unable to get local issuer certificate",
            )

            result = await check_certificate(domain, port, tls_check_config)

            assert result.is_valid is True
            assert result.chain_trusted is False
            assert result.chain_valid is False
            assert result.chain_length == 2
            assert len(result.chain_info) == 2
            assert (
                result.chain_error
                == "Chain validation failed: unable to get local issuer certificate"
            )

    @pytest.mark.asyncio
    async def test_check_certificate_with_openssl_disabled(self, tls_check_config):
        """Test certificate check with OpenSSL disabled in config."""
        domain = "example.com"
        port = 443

        config = TLSCheckConfig(
            check_certificate=True,
            verify_chain=True,
            check_key_info=True,
            check_signature_algorithm=True,
            check_san=True,
            use_openssl=False,
            timeout_connect=5,
            timeout_command=10,
        )

        with (
            patch(
                "core.tls.certificates.check_certificate_with_socket"
            ) as mock_check_socket,
            patch("core.tls.certificates.has_openssl") as mock_has_openssl,
            patch("core.tls.certificates.check_certificate_chain") as mock_check_chain,
        ):
            mock_check_socket.return_value = CertificateResult(
                subject="example.com",
                issuer="Example CA",
                valid_from="2023-01-01T00:00:00",
                valid_until="2025-01-01T00:00:00",
                is_valid=True,
                is_expired=False,
                days_until_expiry=365,
                is_self_signed=False,
                validation_error=None,
            )

            mock_has_openssl.return_value = True

            result = await check_certificate(domain, port, config)

            assert result.is_valid is True

            assert result.chain_trusted is False
            assert result.chain_valid is False
            assert result.chain_length == 0
            assert len(result.chain_info) == 0
            assert result.chain_error is None

            mock_check_chain.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_certificate_success_without_openssl(self, tls_check_config):
        """Test successful certificate check without OpenSSL verification."""
        domain = "example.com"
        port = 443
        config = TLSCheckConfig(
            check_certificate=True,
            verify_chain=False,
            check_key_info=True,
            check_signature_algorithm=True,
            check_san=True,
            use_openssl=False,
            timeout_connect=5,
            timeout_command=10,
        )

        with (
            patch(
                "core.tls.certificates.check_certificate_with_socket"
            ) as mock_check_socket,
            patch("core.tls.certificates.has_openssl") as mock_has_openssl,
        ):
            mock_check_socket.return_value = CertificateResult(
                subject="example.com",
                issuer="Example CA",
                valid_from="2023-01-01T00:00:00",
                valid_until="2025-01-01T00:00:00",
                is_valid=True,
                is_expired=False,
                days_until_expiry=365,
                is_self_signed=False,
                validation_error=None,
            )

            mock_has_openssl.return_value = True

            result = await check_certificate(domain, port, config)

            assert result.is_valid is True
            assert result.subject == "example.com"
            assert result.issuer == "Example CA"
            mock_check_socket.assert_called_once_with(
                domain, port, config.timeout_connect, config
            )

    @pytest.mark.asyncio
    async def test_check_certificate_openssl_not_available(self, tls_check_config):
        """Test certificate check when OpenSSL is enabled but not available."""
        domain = "example.com"
        port = 443
        config = TLSCheckConfig(
            check_certificate=True,
            verify_chain=True,
            check_key_info=True,
            check_signature_algorithm=True,
            check_san=True,
            use_openssl=True,
            timeout_connect=5,
            timeout_command=10,
        )

        with (
            patch(
                "core.tls.certificates.check_certificate_with_socket"
            ) as mock_check_socket,
            patch("core.tls.certificates.has_openssl") as mock_has_openssl,
        ):
            mock_check_socket.return_value = CertificateResult(
                subject="example.com",
                issuer="Example CA",
                valid_from="2023-01-01T00:00:00",
                valid_until="2025-01-01T00:00:00",
                is_valid=True,
                is_expired=False,
                days_until_expiry=365,
                is_self_signed=False,
                validation_error=None,
            )

            mock_has_openssl.return_value = False

            result = await check_certificate(domain, port, config)

            assert result.is_valid is True
            assert result.chain_trusted is False
            assert result.chain_valid is False
            assert result.chain_info == []
            mock_check_socket.assert_called_once_with(
                domain, port, config.timeout_connect, config
            )

    @pytest.mark.asyncio
    async def test_check_certificate_with_successful_chain_validation(
        self, tls_check_config
    ):
        """Test certificate check with successful chain validation."""
        domain = "example.com"
        port = 443
        config = TLSCheckConfig(
            check_certificate=True,
            verify_chain=True,
            check_key_info=True,
            check_signature_algorithm=True,
            check_san=True,
            use_openssl=True,
            timeout_connect=5,
            timeout_command=10,
        )

        with (
            patch(
                "core.tls.certificates.check_certificate_with_socket"
            ) as mock_check_socket,
            patch("core.tls.certificates.has_openssl") as mock_has_openssl,
            patch("core.tls.certificates.check_certificate_chain") as mock_check_chain,
        ):
            mock_check_socket.return_value = CertificateResult(
                subject="example.com",
                issuer="Example CA",
                valid_from="2023-01-01T00:00:00",
                valid_until="2025-01-01T00:00:00",
                is_valid=True,
                is_expired=False,
                days_until_expiry=365,
                is_self_signed=False,
                validation_error=None,
            )

            mock_has_openssl.return_value = True

            chain_info = [
                {
                    "subject": "CN=example.com",
                    "issuer": "CN=Intermediate CA",
                    "position": 0,
                },
                {
                    "subject": "CN=Intermediate CA",
                    "issuer": "CN=Root CA",
                    "position": 1,
                },
                {"subject": "CN=Root CA", "issuer": "CN=Root CA", "position": 2},
            ]
            mock_check_chain.return_value = (True, True, 3, chain_info, None)

            result = await check_certificate(domain, port, config)

            assert result.is_valid is True
            assert result.chain_trusted is True
            assert result.chain_valid is True
            assert result.chain_length == 3
            assert len(result.chain_info) == 3
            assert result.chain_error is None
            mock_check_socket.assert_called_once_with(
                domain, port, config.timeout_connect, config
            )
            mock_check_chain.assert_called_once_with(
                domain, port, config.timeout_command
            )

    @pytest.mark.asyncio
    async def test_check_certificate_disabled(self):
        """Test behavior when certificate checking is disabled."""
        domain = "example.com"
        port = 443
        config = TLSCheckConfig(
            check_certificate=False,
            verify_chain=True,
            check_key_info=True,
            check_signature_algorithm=True,
            check_san=True,
            use_openssl=True,
            timeout_connect=5,
            timeout_command=10,
        )

        with patch(
            "core.tls.certificates.create_error_cert_result"
        ) as mock_error_result:
            mock_error_result.return_value = CertificateResult(
                subject="Unknown",
                issuer="Unknown",
                valid_from="1970-01-01T00:00:00",
                valid_until="1970-01-01T00:00:00",
                is_valid=False,
                is_expired=True,
                days_until_expiry=-365,
                is_self_signed=False,
                validation_error="Certificate checking disabled",
                connection_error=False,
            )

            result = await check_certificate(domain, port, config)

            assert result.is_valid is False
            assert result.validation_error == "Certificate checking disabled"
            mock_error_result.assert_called_once_with("Certificate checking disabled")
