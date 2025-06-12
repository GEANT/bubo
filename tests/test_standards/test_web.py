from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bubo.core.tls.models import (
    CertificateResult,
    KeyInfo,
    SANInfo,
    SignatureAlgorithmInfo,
    SignatureAlgorithmSecurity,
    TLSCheckConfig,
    TLSProtocol,
    TLSProtocolResult,
)
from bubo.standards import web


@pytest.fixture
def sample_certificate_result():
    """Create a sample certificate result for testing."""
    return CertificateResult(
        subject="CN=example.com",
        issuer="CN=Example CA",
        valid_from="2023-01-01",
        valid_until="2024-01-01",
        is_valid=True,
        is_expired=False,
        days_until_expiry=100,
        is_self_signed=False,
        validation_error=None,
        chain_trusted=True,
        chain_valid=True,
        chain_length=2,
        chain_error=None,
        connection_error=False,
        key_info=KeyInfo(type="RSA", length=2048, secure=True),
        signature_algorithm=SignatureAlgorithmInfo(
            name="sha256WithRSAEncryption", security=SignatureAlgorithmSecurity.STRONG
        ),
        subject_alternative_names=SANInfo(
            names=["example.com", "www.example.com"], contains_domain=True
        ),
        chain_info=[{"CN": "Example CA"}, {"CN": "Root CA"}],
    )


@pytest.fixture
def sample_protocol_results():
    """Create sample protocol results for testing."""
    return [
        TLSProtocolResult(
            protocol_name="TLSv1.0",
            supported=True,
            secure=False,
            error=None,
        ),
        TLSProtocolResult(
            protocol_name="TLSv1.1",
            supported=True,
            secure=False,
            error=None,
        ),
        TLSProtocolResult(
            protocol_name="TLSv1.2",
            supported=True,
            secure=True,
            error=None,
        ),
        TLSProtocolResult(
            protocol_name="TLSv1.3",
            supported=True,
            secure=True,
            error=None,
        ),
    ]


@pytest.fixture
def sample_ciphers_by_protocol():
    """Create sample ciphers by protocol for testing."""
    return {
        "TLSv1.2": [
            {"name": "ECDHE-RSA-AES256-GCM-SHA384", "strength": "strong", "bits": 256},
            {"name": "ECDHE-RSA-AES128-GCM-SHA256", "strength": "strong", "bits": 128},
        ],
        "TLSv1.3": [
            {"name": "TLS_AES_256_GCM_SHA384", "strength": "strong", "bits": 256},
            {"name": "TLS_AES_128_GCM_SHA256", "strength": "strong", "bits": 128},
        ],
    }


@pytest.fixture
def sample_cipher_strength():
    """Create sample cipher strength for testing."""
    return {
        "strong": [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
        ],
        "weak": [],
    }


@pytest.mark.asyncio
async def test_run_protocol_checks():
    """Test run_protocol_checks function."""
    with patch(
        "bubo.standards.web.check_protocol", new_callable=AsyncMock
    ) as mock_check_protocol:
        mock_check_protocol.side_effect = [
            TLSProtocolResult(
                protocol_name="TLSv1.0",
                supported=True,
                secure=False,
                error=None,
            ),
            TLSProtocolResult(
                protocol_name="TLSv1.1",
                supported=True,
                secure=False,
                error=None,
            ),
            TLSProtocolResult(
                protocol_name="TLSv1.2",
                supported=True,
                secure=True,
                error=None,
            ),
            TLSProtocolResult(
                protocol_name="TLSv1.3",
                supported=True,
                secure=True,
                error=None,
            ),
        ]

        with patch("bubo.standards.web.process_protocol_results") as mock_process:
            mock_process.return_value = (
                [
                    TLSProtocolResult(
                        protocol_name="TLSv1.0",
                        supported=True,
                        secure=False,
                        error=None,
                    ),
                    TLSProtocolResult(
                        protocol_name="TLSv1.1",
                        supported=True,
                        secure=False,
                        error=None,
                    ),
                    TLSProtocolResult(
                        protocol_name="TLSv1.2",
                        supported=True,
                        secure=True,
                        error=None,
                    ),
                    TLSProtocolResult(
                        protocol_name="TLSv1.3",
                        supported=True,
                        secure=True,
                        error=None,
                    ),
                ],
                [
                    TLSProtocol.TLSv1_0,
                    TLSProtocol.TLSv1_1,
                    TLSProtocol.TLSv1_2,
                    TLSProtocol.TLSv1_3,
                ],
            )

            domain = "example.com"
            port = 443
            config = TLSCheckConfig()

            results, supported_protocols = await web.run_protocol_checks(
                domain, port, config
            )

            assert mock_check_protocol.call_count == 4

            mock_process.assert_called_once()

            assert len(results) == 4
            assert len(supported_protocols) == 4
            assert results[0].protocol_name == "TLSv1.0"
            assert results[1].protocol_name == "TLSv1.1"
            assert results[2].protocol_name == "TLSv1.2"
            assert results[3].protocol_name == "TLSv1.3"


@pytest.mark.asyncio
async def test_run_cipher_checks():
    """Test run_cipher_checks function."""
    with patch(
        "bubo.standards.web.check_ciphers", new_callable=AsyncMock
    ) as mock_check_ciphers:
        mock_check_ciphers.side_effect = [
            [{"name": "ECDHE-RSA-AES256-GCM-SHA384", "protocol": "TLSv1.2"}],
            [{"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3"}],
        ]

        with patch("bubo.standards.web.process_cipher_results") as mock_process:
            mock_process.return_value = (
                {
                    "TLSv1.2": [
                        {
                            "name": "ECDHE-RSA-AES256-GCM-SHA384",
                            "strength": "strong",
                            "bits": 256,
                        }
                    ],
                    "TLSv1.3": [
                        {
                            "name": "TLS_AES_256_GCM_SHA384",
                            "strength": "strong",
                            "bits": 256,
                        }
                    ],
                },
                {
                    "strong": ["ECDHE-RSA-AES256-GCM-SHA384", "TLS_AES_256_GCM_SHA384"],
                    "weak": [],
                },
            )

            domain = "example.com"
            port = 443
            supported_protocols = [TLSProtocol.TLSv1_2, TLSProtocol.TLSv1_3]
            config = TLSCheckConfig()

            ciphers_by_protocol, cipher_strength = await web.run_cipher_checks(
                domain, port, supported_protocols, config
            )

            assert mock_check_ciphers.call_count == 2

            mock_process.assert_called_once()

            assert "TLSv1.2" in ciphers_by_protocol
            assert "TLSv1.3" in ciphers_by_protocol
            assert "strong" in cipher_strength
            assert "weak" in cipher_strength
            assert len(cipher_strength["strong"]) == 2
            assert len(cipher_strength["weak"]) == 0


def test_build_certificate_dict(sample_certificate_result):
    """Test build_certificate_dict function."""
    cert_dict = web.build_certificate_dict(sample_certificate_result)

    assert cert_dict["subject"] == "CN=example.com"
    assert cert_dict["issuer"] == "CN=Example CA"
    assert cert_dict["valid_from"] == "2023-01-01"
    assert cert_dict["valid_until"] == "2024-01-01"
    assert cert_dict["is_valid"] is True
    assert cert_dict["is_expired"] is False
    assert cert_dict["days_until_expiry"] == 100
    assert cert_dict["is_self_signed"] is False
    assert cert_dict["validation_error"] is None
    assert cert_dict["chain_trusted"] is True
    assert cert_dict["chain_valid"] is True
    assert cert_dict["chain_length"] == 2
    assert cert_dict["chain_error"] is None
    assert cert_dict["connection_error"] is False

    assert cert_dict["key_info"]["type"] == "RSA"
    assert cert_dict["key_info"]["length"] == 2048
    assert cert_dict["key_info"]["secure"] is True

    assert cert_dict["signature_algorithm"]["name"] == "sha256WithRSAEncryption"
    assert cert_dict["signature_algorithm"]["security"] == "strong"

    assert cert_dict["subject_alternative_names"]["names"] == [
        "example.com",
        "www.example.com",
    ]
    assert cert_dict["subject_alternative_names"]["contains_domain"] is True

    assert cert_dict["chain_info"] == [{"CN": "Example CA"}, {"CN": "Root CA"}]


def test_extract_protocol_status(sample_protocol_results):
    """Test extract_protocol_status function."""
    secure_protocols, insecure_protocols = web.extract_protocol_status(
        sample_protocol_results
    )

    assert secure_protocols == ["TLSv1.2", "TLSv1.3"]
    assert insecure_protocols == ["TLSv1.0", "TLSv1.1"]


def test_build_protocol_dict(sample_protocol_results):
    """Test build_protocol_dict function."""
    secure_protocols = ["TLSv1.2", "TLSv1.3"]
    insecure_protocols = ["TLSv1.0", "TLSv1.1"]

    protocol_dict = web.build_protocol_dict(
        sample_protocol_results, secure_protocols, insecure_protocols
    )

    assert len(protocol_dict["protocols"]) == 4
    assert protocol_dict["has_insecure_protocols"] is True
    assert protocol_dict["has_secure_protocols"] is True
    assert protocol_dict["insecure_protocols"] == ["TLSv1.0", "TLSv1.1"]
    assert protocol_dict["secure_protocols"] == ["TLSv1.2", "TLSv1.3"]

    assert protocol_dict["protocols"][0]["name"] == "TLSv1.0"
    assert protocol_dict["protocols"][0]["supported"] is True
    assert protocol_dict["protocols"][0]["secure"] is False

    assert protocol_dict["protocols"][2]["name"] == "TLSv1.2"
    assert protocol_dict["protocols"][2]["supported"] is True
    assert protocol_dict["protocols"][2]["secure"] is True


def test_build_cipher_dict(sample_ciphers_by_protocol, sample_cipher_strength):
    """Test build_cipher_dict function."""
    cipher_dict = web.build_cipher_dict(
        sample_ciphers_by_protocol, sample_cipher_strength
    )

    assert "by_protocol" in cipher_dict
    assert "by_strength" in cipher_dict
    assert "has_weak_ciphers" in cipher_dict
    assert "has_strong_ciphers" in cipher_dict

    assert "TLSv1.2" in cipher_dict["by_protocol"]
    assert "TLSv1.3" in cipher_dict["by_protocol"]
    assert len(cipher_dict["by_protocol"]["TLSv1.2"]) == 2
    assert len(cipher_dict["by_protocol"]["TLSv1.3"]) == 2

    assert "strong" in cipher_dict["by_strength"]
    assert "weak" in cipher_dict["by_strength"]
    assert len(cipher_dict["by_strength"]["strong"]) == 4
    assert len(cipher_dict["by_strength"]["weak"]) == 0

    assert cipher_dict["has_weak_ciphers"] is False
    assert cipher_dict["has_strong_ciphers"] is True


@pytest.mark.asyncio
async def test_run_success(
    sample_domain, sample_certificate_result, sample_protocol_results
):
    """Test run function with successful execution."""
    with (
        patch(
            "bubo.standards.web.resolve_domain", new_callable=AsyncMock
        ) as mock_resolve,
        patch(
            "bubo.standards.web.run_protocol_checks", new_callable=AsyncMock
        ) as mock_protocol_checks,
        patch(
            "bubo.standards.web.run_http_security_checks", new_callable=AsyncMock
        ) as mock_http_checks,
        patch(
            "bubo.standards.web.run_cipher_checks", new_callable=AsyncMock
        ) as mock_cipher_checks,
        patch("bubo.standards.web.build_security_assessment") as mock_assessment,
    ):
        mock_resolve.return_value = (sample_certificate_result, sample_domain)

        mock_protocol_checks.return_value = (
            sample_protocol_results,
            [TLSProtocol.TLSv1_2, TLSProtocol.TLSv1_3],
        )

        mock_http_checks.return_value = (
            MagicMock(enabled=True, max_age=31536000),
            MagicMock(content_type_options="nosniff"),
        )

        mock_cipher_checks.return_value = (
            {
                "TLSv1.2": [
                    {"name": "ECDHE-RSA-AES256-GCM-SHA384", "strength": "strong"}
                ],
                "TLSv1.3": [{"name": "TLS_AES_256_GCM_SHA384", "strength": "strong"}],
            },
            {
                "strong": ["ECDHE-RSA-AES256-GCM-SHA384", "TLS_AES_256_GCM_SHA384"],
                "weak": [],
            },
        )

        mock_assessment.return_value = {
            "rating": "A+",
            "issues": [],
            "issues_count": 0,
        }

        results, state = await web.run(sample_domain)

        mock_resolve.assert_called_once()
        mock_protocol_checks.assert_called_once()
        mock_http_checks.assert_called_once()
        mock_cipher_checks.assert_called_once()
        mock_assessment.assert_called_once()

        assert sample_domain in results
        assert "protocol_support" in results[sample_domain]
        assert "certificate" in results[sample_domain]
        assert "ciphers" in results[sample_domain]
        assert "security_assessment" in results[sample_domain]
        assert "timestamp" in results[sample_domain]
        assert "hsts" in results[sample_domain]
        assert "security_headers" in results[sample_domain]

        assert sample_domain in state
        assert "tls_secure" in state[sample_domain]
        assert "rating" in state[sample_domain]
        assert "cert_valid" in state[sample_domain]
        assert "issues_count" in state[sample_domain]
        assert "uses_secure_protocols" in state[sample_domain]


@pytest.mark.asyncio
async def test_run_with_connection_error(sample_domain):
    """Test run function with connection error."""
    with patch(
        "bubo.standards.web.resolve_domain", new_callable=AsyncMock
    ) as mock_resolve:
        error_cert = CertificateResult(
            subject=None,
            issuer=None,
            valid_from=None,
            valid_until=None,
            is_valid=False,
            is_expired=False,
            days_until_expiry=None,
            is_self_signed=False,
            validation_error="Connection refused",
            chain_trusted=False,
            chain_valid=False,
            chain_length=0,
            chain_error=None,
            connection_error=True,
        )

        mock_resolve.return_value = (error_cert, sample_domain)

        results, state = await web.run(sample_domain)

        mock_resolve.assert_called_once()

        assert sample_domain in results
        assert "connectivity_error" in results[sample_domain]
        assert results[sample_domain]["connectivity_error"] is True
        assert results[sample_domain]["error_message"] == "Connection refused"

        assert sample_domain in state
        assert "connectivity_error" in state[sample_domain]
        assert state[sample_domain]["connectivity_error"] is True
        assert (
            state[sample_domain]["connectivity_error_message"] == "Connection refused"
        )
        assert state[sample_domain]["tls_secure"] is False


@pytest.mark.asyncio
async def test_run_with_exception(sample_domain):
    """Test run function with an exception."""
    with patch(
        "bubo.standards.web.resolve_domain", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.side_effect = Exception("Test exception")

        results, state = await web.run(sample_domain)

        mock_resolve.assert_called_once()

        assert sample_domain in results
        assert "error" in results[sample_domain]
        assert "Test exception" in results[sample_domain]["error"]
        assert results[sample_domain]["security_assessment"]["rating"] == "error"
        assert results[sample_domain]["security_assessment"]["issues_count"] == 1

        assert sample_domain in state
        assert "error" in state[sample_domain]
        assert "Test exception" in state[sample_domain]["error"]
        assert state[sample_domain]["rating"] == "error"
        assert state[sample_domain]["tls_secure"] is False
        assert state[sample_domain]["connectivity_error"] is True
