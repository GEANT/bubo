import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from bubo.core.tls.models import (
    CipherStrength,
    SignatureAlgorithmSecurity,
)
from bubo.core.tls.utils import (
    categorize_cipher_strength,
    categorize_signature_algorithm,
    clean_ssl_error_message,
    create_error_cert_result,
    extract_key_info,
    extract_san_info,
    extract_signature_algorithm,
    format_serial_number,
    format_x509_name,
    get_openssl_version,
    has_openssl,
    retry_async,
    run_openssl_command,
    with_retries,
)


class TestRetryFunctions:
    @pytest.mark.asyncio
    async def test_with_retries_success_first_attempt(self):
        mock_func = AsyncMock(return_value="success")

        result = await with_retries(mock_func, "arg1", arg2="value", retries=3)

        assert result == "success"
        mock_func.assert_called_once_with("arg1", arg2="value")

    @pytest.mark.asyncio
    async def test_with_retries_success_after_retry(self):
        mock_func = AsyncMock(side_effect=[Exception("Error"), "success"])

        result = await with_retries(mock_func, retries=3, backoff_factor=0.1)

        assert result == "success"
        assert mock_func.call_count == 2

    @pytest.mark.asyncio
    async def test_with_retries_max_retries_exceeded(self):
        mock_func = AsyncMock(side_effect=Exception("Persistent error"))

        with pytest.raises(Exception, match="Persistent error"):
            await with_retries(mock_func, retries=2, backoff_factor=0.1)

        assert mock_func.call_count == 3

    @pytest.mark.asyncio
    async def test_with_retries_fatal_exception_no_retry(self):
        class FatalError(Exception):
            pass

        mock_func = AsyncMock(side_effect=FatalError("Fatal"))

        with pytest.raises(FatalError, match="Fatal"):
            await with_retries(mock_func, retries=3, fatal_exceptions=(FatalError,))

        mock_func.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_async_decorator(self):
        mock_impl = AsyncMock(side_effect=[Exception("Error"), "success"])

        @retry_async(retries=3, backoff_factor=0.1)
        async def test_func():
            return await mock_impl()

        result = await test_func()

        assert result == "success"
        assert mock_impl.call_count == 2


class TestOpenSSLUtilities:
    def test_has_openssl_available(self):
        with patch("shutil.which", return_value="/usr/bin/openssl"):
            assert has_openssl() is True

    def test_has_openssl_not_available(self):
        with patch("shutil.which", return_value=None):
            assert has_openssl() is False

    @pytest.mark.asyncio
    async def test_get_openssl_version_success(self):
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (b"OpenSSL 1.1.1k  25 Mar 2021", b"")

        with (
            patch("asyncio.create_subprocess_exec", return_value=process_mock),
            patch("bubo.core.tls.utils.has_openssl", return_value=True),
        ):
            version = await get_openssl_version()
            assert version == (1, 1, 1)

    @pytest.mark.asyncio
    async def test_get_openssl_version_parse_error(self):
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (b"Unknown format", b"")

        with (
            patch("asyncio.create_subprocess_exec", return_value=process_mock),
            patch("bubo.core.tls.utils.has_openssl", return_value=True),
        ):
            version = await get_openssl_version()
            assert version == (0, 0, 0)

    @pytest.mark.asyncio
    async def test_get_openssl_version_exception(self):
        with (
            patch(
                "asyncio.create_subprocess_exec", side_effect=Exception("Command error")
            ),
            patch("bubo.core.tls.utils.has_openssl", return_value=True),
        ):
            version = await get_openssl_version()
            assert version == (0, 0, 0)

    @pytest.mark.asyncio
    async def test_run_openssl_command_success(self):
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (b"OpenSSL output", b"")
        process_mock.returncode = 0

        with (
            patch("asyncio.create_subprocess_exec", return_value=process_mock),
            patch("bubo.core.tls.utils.has_openssl", return_value=True),
        ):
            output, return_code = await run_openssl_command(
                "example.com", 443, ["-tls1_2"], 10
            )

            assert output == "OpenSSL output"
            assert return_code == 0

    @pytest.mark.asyncio
    async def test_run_openssl_command_timeout(self):
        process_mock = AsyncMock()
        process_mock.communicate.side_effect = asyncio.TimeoutError()
        process_mock.kill = MagicMock()

        with (
            patch("asyncio.create_subprocess_exec", return_value=process_mock),
            patch("bubo.core.tls.utils.has_openssl", return_value=True),
        ):
            output, return_code = await run_openssl_command(
                "example.com", 443, ["-tls1_2"], 10, retries=0
            )

            assert "timed out" in output.lower()
            assert return_code == 1
            process_mock.kill.assert_called_once()


class TestCipherAndAlgorithmAnalysis:
    def test_categorize_cipher_strength_strong(self):
        strong_ciphers = [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "DHE-RSA-AES128-GCM-SHA256",
            "TLS_AES_256_GCM_SHA384",
        ]

        for cipher in strong_ciphers:
            assert categorize_cipher_strength(cipher) == CipherStrength.STRONG

    def test_categorize_cipher_strength_medium(self):
        medium_ciphers = [
            "AES128-GCM-SHA256",
            "DHE-RSA-AES256-SHA256",
        ]

        for cipher in medium_ciphers:
            assert categorize_cipher_strength(cipher) == CipherStrength.MEDIUM

    def test_categorize_cipher_strength_weak(self):
        weak_ciphers = [
            "RC4-SHA",
            "DES-CBC3-SHA",
            "NULL-SHA256",
            "EXPORT-RSA-RC4-MD5",
        ]

        for cipher in weak_ciphers:
            assert categorize_cipher_strength(cipher) == CipherStrength.WEAK

    def test_categorize_cipher_strength_unknown(self):
        unknown_cipher = "CUSTOM-UNKNOWN-CIPHER"
        assert categorize_cipher_strength(unknown_cipher) == CipherStrength.UNKNOWN

    def test_categorize_signature_algorithm_strong(self):
        strong_algorithms = [
            "sha256WithRSAEncryption",
            "ecdsa-with-SHA384",
            "ed25519",
        ]

        for alg in strong_algorithms:
            assert (
                categorize_signature_algorithm(alg) == SignatureAlgorithmSecurity.STRONG
            )

    def test_categorize_signature_algorithm_acceptable(self):
        assert (
            categorize_signature_algorithm("sha224WithRSAEncryption")
            == SignatureAlgorithmSecurity.ACCEPTABLE
        )

    def test_categorize_signature_algorithm_weak(self):
        weak_algorithms = [
            "sha1WithRSAEncryption",
            "md5WithRSAEncryption",
        ]

        for alg in weak_algorithms:
            assert (
                categorize_signature_algorithm(alg) == SignatureAlgorithmSecurity.WEAK
            )


class TestCertificateErrorHandling:
    def test_clean_ssl_error_message_self_signed(self):
        error = "self-signed certificate in certificate chain"
        result = clean_ssl_error_message(error)
        assert result == "Self-signed certificate detected"

    def test_clean_ssl_error_message_expired(self):
        error = "certificate has expired"
        result = clean_ssl_error_message(error)
        assert result == "Certificate has expired"

    def test_clean_ssl_error_message_hostname_mismatch(self):
        error = "hostname doesn't match"
        result = clean_ssl_error_message(error)
        assert result == "Certificate hostname verification failed"

    def test_clean_ssl_error_message_incomplete_chain(self):
        error = "unable to get local issuer certificate"
        result = clean_ssl_error_message(error)
        assert (
            result
            == "Certificate chain incomplete - unable to verify with a trusted root"
        )

    def test_clean_ssl_error_message_verify_failed(self):
        error = "certificate verify failed"
        result = clean_ssl_error_message(error)
        assert result == "Certificate verification failed"

    def test_clean_ssl_error_message_cleaned_format(self):
        error = "certificate verify failed: (openssl.py:123) [SSL: CERTIFICATE_VERIFY_FAILED] some error"
        result = clean_ssl_error_message(error)

        assert "Certificate verification failed" in result
        assert "(openssl.py:123)" not in result
        assert "[SSL: CERTIFICATE_VERIFY_FAILED]" not in result

    def test_create_error_cert_result_connection_error(self):
        result = create_error_cert_result(
            "Connection refused", is_connection_error=True
        )

        assert result.subject == "Unknown"
        assert not result.is_valid
        assert result.connection_error is True

    def test_create_error_cert_result_self_signed(self):
        result = create_error_cert_result("self-signed certificate")

        assert not result.is_valid
        assert result.is_self_signed
        assert result.validation_error == "Self-signed certificate detected"


class TestCertificateAnalysis:
    @pytest.fixture
    def mock_rsa_cert(self):
        cert = MagicMock(spec=x509.Certificate)

        public_key = MagicMock(spec=rsa.RSAPublicKey)
        type(public_key).__name__ = "RSAPublicKey"
        public_key.key_size = 2048
        cert.public_key.return_value = public_key

        cert.signature_algorithm_oid = MagicMock()
        cert.signature_algorithm_oid._name = "sha256WithRSAEncryption"

        return cert

    @pytest.fixture
    def mock_ec_cert(self):
        cert = MagicMock(spec=x509.Certificate)

        public_key = MagicMock(spec=ec.EllipticCurvePublicKey)
        type(public_key).__name__ = "EllipticCurvePublicKey"
        public_key.key_size = 256
        public_key.curve = MagicMock()
        public_key.curve.name = "secp256r1"
        cert.public_key.return_value = public_key

        cert.signature_algorithm_oid = MagicMock()
        cert.signature_algorithm_oid._name = "ecdsa-with-SHA256"

        return cert

    def test_extract_key_info_rsa(self, mock_rsa_cert):
        key_info = extract_key_info(mock_rsa_cert)

        assert key_info.type == "RSA"
        assert key_info.length == 2048
        assert key_info.secure is True

    def test_extract_key_info_ec(self, mock_ec_cert):
        key_info = extract_key_info(mock_ec_cert)

        assert key_info.type == "EC"
        assert key_info.length == 256
        assert key_info.secure is True

    def test_extract_key_info_ec_from_curve(self):
        cert = MagicMock(spec=x509.Certificate)

        public_key = MagicMock(spec=ec.EllipticCurvePublicKey)
        type(public_key).__name__ = "EllipticCurvePublicKey"
        del public_key.key_size
        public_key.curve = MagicMock()
        public_key.curve.name = "secp256r1"
        cert.public_key.return_value = public_key

        key_info = extract_key_info(cert)

        assert key_info.type == "EC"
        assert key_info.length == 256

    def test_extract_key_info_ed25519(self):
        cert = MagicMock(spec=x509.Certificate)

        public_key = MagicMock(spec=ed25519.Ed25519PublicKey)
        type(public_key).__name__ = "Ed25519PublicKey"
        cert.public_key.return_value = public_key

        key_info = extract_key_info(cert)

        assert key_info.type == "Ed25519"
        assert key_info.length == 256
        assert key_info.secure is True

    def test_extract_key_info_ec_curve_error(self):
        cert = MagicMock(spec=x509.Certificate)

        public_key = MagicMock(spec=ec.EllipticCurvePublicKey)
        type(public_key).__name__ = "EllipticCurvePublicKey"
        del public_key.key_size
        public_key.curve = MagicMock()
        public_key.curve.name = MagicMock(side_effect=Exception("Curve error"))
        cert.public_key.return_value = public_key

        key_info = extract_key_info(cert)

        assert key_info.type == "EC"
        assert key_info.length == 0

    def test_extract_signature_algorithm(self, mock_rsa_cert):
        sig_info = extract_signature_algorithm(mock_rsa_cert)

        assert sig_info.name == "sha256WithRSAEncryption"
        assert sig_info.security == SignatureAlgorithmSecurity.STRONG

    def test_extract_san_info_with_matching_domain(self):
        cert = MagicMock(spec=x509.Certificate)

        extensions = MagicMock()
        san_ext = MagicMock()
        san_value = MagicMock()

        san_value.get_values_for_type.side_effect = lambda t: (
            ["example.com", "www.example.com"] if t == x509.DNSName else []
        )

        san_ext.value = san_value
        extensions.get_extension_for_oid.return_value = san_ext
        cert.extensions = extensions

        san_info = extract_san_info(cert, "example.com")

        assert san_info.names == ["DNS:example.com", "DNS:www.example.com"]
        assert san_info.contains_domain is True

    def test_extract_san_info_with_wildcard(self):
        cert = MagicMock(spec=x509.Certificate)

        extensions = MagicMock()
        san_ext = MagicMock()
        san_value = MagicMock()

        san_value.get_values_for_type.side_effect = lambda t: (
            ["*.example.com"] if t == x509.DNSName else []
        )

        san_ext.value = san_value
        extensions.get_extension_for_oid.return_value = san_ext
        cert.extensions = extensions

        san_info = extract_san_info(cert, "sub.example.com")

        assert san_info.names == ["DNS:*.example.com"]
        assert san_info.contains_domain is True

    def test_extract_san_info_with_ip(self):
        cert = MagicMock(spec=x509.Certificate)

        extensions = MagicMock()
        san_ext = MagicMock()
        san_value = MagicMock()

        ip_mock = MagicMock()
        ip_mock.__str__.return_value = "192.168.1.1"

        san_value.get_values_for_type.side_effect = lambda t: (
            [ip_mock] if t == x509.IPAddress else []
        )

        san_ext.value = san_value
        extensions.get_extension_for_oid.return_value = san_ext
        cert.extensions = extensions

        san_info = extract_san_info(cert, "192.168.1.1")

        assert san_info.names == ["IP:192.168.1.1"]
        assert san_info.contains_domain is True

    def test_extract_san_info_extension_error(self):
        cert = MagicMock(spec=x509.Certificate)
        extensions = MagicMock()
        extensions.get_extension_for_oid.side_effect = Exception("Extension error")
        cert.extensions = extensions

        san_info = extract_san_info(cert, "example.com")

        assert san_info.names == []
        assert san_info.contains_domain is False


class TestFormattingFunctions:
    def test_format_x509_name(self):
        attr1 = MagicMock()
        attr1.oid._name = "commonName"
        attr1.value = "example.com"

        attr2 = MagicMock()
        attr2.oid._name = "organizationName"
        attr2.value = "Example Inc"

        name = [attr1, attr2]

        result = format_x509_name(name)

        assert result == "commonName=example.com, organizationName=Example Inc"

    def test_format_x509_name_dotted_string(self):
        attr = MagicMock()
        attr.oid = MagicMock()
        del attr.oid._name
        attr.oid.dotted_string = "2.5.4.3"
        attr.value = "example.com"

        name = [attr]

        result = format_x509_name(name)

        assert result == "2.5.4.3=example.com"

    def test_format_serial_number_even_length(self):
        serial = 0x1A2B3C4D
        result = format_serial_number(serial)
        assert result == "1a:2b:3c:4d"

    def test_format_serial_number_odd_length(self):
        serial = 0xA2B3C
        result = format_serial_number(serial)
        assert result == "0a:2b:3c"
