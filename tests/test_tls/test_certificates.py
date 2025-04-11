import datetime
import pytest
from unittest.mock import MagicMock, patch

from cryptography import x509

from core.tls.certificates import (
    check_certificate_with_socket,
    check_certificate_chain,
    check_certificate,
)
from core.tls.models import (
    CertificateResult,
    TLSCheckConfig,
    KeyInfo,
    SignatureAlgorithmInfo,
    SignatureAlgorithmSecurity,
    SANInfo,
)


@pytest.fixture
def mock_ssl_context():
    context = MagicMock()
    return context


@pytest.fixture
def mock_ssl_socket():
    ssl_sock = MagicMock()

    cert_data = {
        "subject": [((("commonName", "example.com"),),)],
        "issuer": [((("commonName", "Example CA"),),)],
        "notBefore": "Jan 01 00:00:00 2023 GMT",
        "notAfter": "Jan 01 00:00:00 2025 GMT",
    }
    ssl_sock.getpeercert.side_effect = (
        lambda binary_form=False: cert_data if not binary_form else b"mock_der_cert"
    )
    return ssl_sock


@pytest.fixture
def mock_x509_certificate():
    cert = MagicMock()

    subject = MagicMock()
    subject.rfc4514_string.return_value = "CN=example.com,O=Example Org"
    cert.subject = subject

    issuer = MagicMock()
    issuer.rfc4514_string.return_value = "CN=Example CA,O=Example CA Org"
    cert.issuer = issuer

    cert.not_valid_before_utc = datetime.datetime(2023, 1, 1)
    cert.not_valid_after_utc = datetime.datetime(2025, 1, 1)

    cert.serial_number = 123456789

    mock_extension = MagicMock()
    mock_san_value = MagicMock()
    mock_san_value.get_values_for_type.side_effect = (
        lambda x: ["example.com", "www.example.com"]
        if x == x509.DNSName
        else ["192.0.2.1"]
        if x == x509.IPAddress
        else []
    )
    mock_extension.value = mock_san_value

    extensions = MagicMock()
    extensions.get_extension_for_oid.return_value = mock_extension
    cert.extensions = extensions

    return cert


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


class TestCertificateChain:
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


class TestCertificate:
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
