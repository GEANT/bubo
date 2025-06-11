from unittest.mock import patch

import pytest

from bubo.core.tls import cipher_utils
from bubo.core.tls.models import (
    CipherResult,
    CipherStrength,
    TLSCheckConfig,
    TLSProtocol,
)


class AsyncMockWithReturnValue:
    def __init__(self, return_value):
        self.return_value = return_value

    def __call__(self, *_args, **_kwargs):
        return self

    def __await__(self):
        async def async_return():
            return self.return_value

        return async_return().__await__()


with (
    patch("bubo.core.tls.utils.has_openssl"),
    patch("bubo.core.tls.utils.run_openssl_command"),
    patch("bubo.core.tls.models.TLSProtocol", TLSProtocol),
    patch("bubo.core.tls.models.CipherResult", CipherResult),
    patch("bubo.core.tls.models.CipherStrength", CipherStrength),
    patch("bubo.core.tls.models.TLSCheckConfig", TLSCheckConfig),
    patch("bubo.core.tls.ciphers.has_openssl"),
    patch("bubo.core.tls.ciphers.run_openssl_command"),
):
    from bubo.core.tls.ciphers import check_ciphers, process_cipher_results


@pytest.fixture
def mock_cipher_info_tls1_0():
    """Sample cipher info for TLSv1.0."""
    return {
        "name": "ECDHE-RSA-AES256-SHA",
        "protocol": "TLSv1.0",
        "strength": CipherStrength.MEDIUM,
        "bits": 256,
    }


@pytest.fixture
def mock_cipher_info_tls1_2():
    """Sample cipher info for TLSv1.2."""
    return {
        "name": "ECDHE-RSA-AES256-GCM-SHA384",
        "protocol": "TLSv1.2",
        "strength": CipherStrength.STRONG,
        "bits": 256,
    }


@pytest.fixture
def mock_cipher_info_tls1_3():
    """Sample cipher info for TLSv1.3."""
    return {
        "name": "TLS_AES_256_GCM_SHA384",
        "protocol": "TLSv1.3",
        "strength": CipherStrength.STRONG,
        "bits": 256,
    }


@pytest.mark.asyncio
async def test_check_cipher_success():
    """Test successful cipher check."""

    with (
        patch("bubo.core.tls.ciphers.has_openssl", return_value=True),
    ):
        openssl_output = """
        SSL-Session:
            Protocol  : TLSv1.2
            Cipher    : ECDHE-RSA-AES256-GCM-SHA384
        New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
        """
        openssl_mock = AsyncMockWithReturnValue((openssl_output, 0))

        await cipher_utils.initialize()

        with (
            patch("bubo.core.tls.ciphers.run_openssl_command", openssl_mock),
            patch(
                "bubo.core.tls.ciphers.test_cipher",
                return_value=CipherResult(
                    name="ECDHE-RSA-AES256-GCM-SHA384",
                    protocol="TLSv1.2",
                    strength=CipherStrength.STRONG,
                    bits=256,
                ),
            ),
        ):
            domain = "example.com"
            port = 443
            protocol = TLSProtocol.TLSv1_2
            config = TLSCheckConfig(check_ciphers=True)

            result = await check_ciphers(domain, port, protocol, config)

            assert result is not None
            assert isinstance(result, list)
            assert len(result) > 0
            assert result[0].name == "ECDHE-RSA-AES256-GCM-SHA384"
            assert result[0].protocol == "TLSv1.2"
            assert result[0].strength == CipherStrength.STRONG
            assert result[0].bits == 256


@pytest.mark.asyncio
async def test_check_cipher_no_openssl():
    """Test cipher check when OpenSSL is not available."""

    with (
        patch(
            "bubo.core.tls.ciphers.has_openssl", return_value=False
        ) as mock_has_openssl,
    ):
        openssl_mock = AsyncMockWithReturnValue(("openssl output", 0))
        with patch("bubo.core.tls.ciphers.run_openssl_command", openssl_mock):
            domain = "example.com"
            port = 443
            protocol = TLSProtocol.TLSv1_2
            config = TLSCheckConfig(check_ciphers=True)

            result = await check_ciphers(domain, port, protocol, config)

            assert result is None

            mock_has_openssl.assert_called_once()


@pytest.mark.asyncio
async def test_check_cipher_disabled():
    """Test cipher check when disabled in config."""

    with (
        patch("bubo.core.tls.ciphers.has_openssl") as mock_has_openssl,
    ):
        openssl_mock = AsyncMockWithReturnValue(("openssl output", 0))
        with patch("bubo.core.tls.ciphers.run_openssl_command", openssl_mock):
            domain = "example.com"
            port = 443
            protocol = TLSProtocol.TLSv1_2
            config = TLSCheckConfig(check_ciphers=False)

            result = await check_ciphers(domain, port, protocol, config)

            assert result is None

            mock_has_openssl.assert_not_called()


@pytest.mark.asyncio
async def test_check_cipher_no_cipher_info():
    """Test cipher check when no cipher info can be extracted."""

    with (
        patch("bubo.core.tls.ciphers.has_openssl", return_value=True),
    ):
        openssl_mock = AsyncMockWithReturnValue(("openssl output", 0))
        with patch("bubo.core.tls.ciphers.run_openssl_command", openssl_mock):
            domain = "example.com"
            port = 443
            protocol = TLSProtocol.TLSv1_2
            config = TLSCheckConfig(check_ciphers=True)

            result = await check_ciphers(domain, port, protocol, config)

            assert result is None


def test_process_cipher_results_success():
    """Test processing successful cipher results."""

    cipher_results = [
        CipherResult(
            name="ECDHE-RSA-AES256-SHA",
            protocol="TLSv1.0",
            strength=CipherStrength.MEDIUM,
            bits=256,
        ),
        CipherResult(
            name="ECDHE-RSA-AES256-GCM-SHA384",
            protocol="TLSv1.2",
            strength=CipherStrength.STRONG,
            bits=256,
        ),
        None,
        CipherResult(
            name="TLS_AES_256_GCM_SHA384",
            protocol="TLSv1.3",
            strength=CipherStrength.STRONG,
            bits=256,
        ),
    ]

    protocols = [
        TLSProtocol.TLSv1_0,
        TLSProtocol.TLSv1_2,
        TLSProtocol.TLSv1_1,
        TLSProtocol.TLSv1_3,
    ]

    ciphers_by_protocol, cipher_strength = process_cipher_results(
        cipher_results, protocols
    )

    assert "TLSv1.0" in ciphers_by_protocol
    assert "TLSv1.2" in ciphers_by_protocol
    assert "TLSv1.3" in ciphers_by_protocol
    assert "TLSv1.1" not in ciphers_by_protocol

    assert len(ciphers_by_protocol["TLSv1.0"]) == 1
    assert ciphers_by_protocol["TLSv1.0"][0]["name"] == "ECDHE-RSA-AES256-SHA"
    assert ciphers_by_protocol["TLSv1.0"][0]["strength"] == "medium"
    assert ciphers_by_protocol["TLSv1.0"][0]["bits"] == 256

    assert "strong" in cipher_strength
    assert "medium" in cipher_strength
    assert len(cipher_strength["strong"]) == 2
    assert len(cipher_strength["medium"]) == 1
    assert "ECDHE-RSA-AES256-GCM-SHA384" in cipher_strength["strong"]
    assert "TLS_AES_256_GCM_SHA384" in cipher_strength["strong"]
    assert "ECDHE-RSA-AES256-SHA" in cipher_strength["medium"]


def test_process_cipher_results_exceptions():
    """Test processing cipher results with exceptions."""

    cipher_results = [
        Exception("Connection error"),
        None,
        CipherResult(
            name="ECDHE-RSA-AES256-GCM-SHA384",
            protocol="TLSv1.2",
            strength=CipherStrength.STRONG,
            bits=256,
        ),
    ]
    protocols = [TLSProtocol.TLSv1_0, TLSProtocol.TLSv1_1, TLSProtocol.TLSv1_2]

    ciphers_by_protocol, cipher_strength = process_cipher_results(
        cipher_results, protocols
    )

    assert "TLSv1.0" not in ciphers_by_protocol
    assert "TLSv1.1" not in ciphers_by_protocol
    assert "TLSv1.2" in ciphers_by_protocol

    assert len(ciphers_by_protocol) == 1
    assert len(cipher_strength["strong"]) == 1
    assert "ECDHE-RSA-AES256-GCM-SHA384" in cipher_strength["strong"]


def test_process_cipher_results_empty():
    """Test processing empty cipher results."""

    cipher_results = [None, None, None]
    protocols = [TLSProtocol.TLSv1_0, TLSProtocol.TLSv1_1, TLSProtocol.TLSv1_2]

    ciphers_by_protocol, cipher_strength = process_cipher_results(
        cipher_results, protocols
    )

    assert len(ciphers_by_protocol) == 0
    assert len(cipher_strength) == 0


@pytest.mark.asyncio
async def test_check_all_protocols():
    """Test checking all TLS protocol versions."""
    domain = "example.com"
    port = 443

    config = TLSCheckConfig(check_ciphers=True)

    mock_responses = {
        "-tls1": (
            """
            SSL-Session:
                Protocol  : TLSv1
                Cipher    : ECDHE-RSA-AES128-SHA
            New, TLSv1.0, Cipher is ECDHE-RSA-AES128-SHA
        """,
            0,
        ),
        "-tls1_1": (
            """
            SSL-Session:
                Protocol  : TLSv1.1
                Cipher    : ECDHE-RSA-AES256-SHA
            New, TLSv1.1, Cipher is ECDHE-RSA-AES256-SHA
        """,
            0,
        ),
        "-tls1_2": (
            """
            SSL-Session:
                Protocol  : TLSv1.2
                Cipher    : ECDHE-RSA-AES256-GCM-SHA384
            New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
        """,
            0,
        ),
        "-tls1_3": (
            """
            SSL-Session:
                Protocol  : TLSv1.3
                Cipher    : TLS_AES_256_GCM_SHA384
            New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
        """,
            0,
        ),
    }

    mock_cipher_info = {
        "TLSv1.0": {
            "name": "ECDHE-RSA-AES128-SHA",
            "protocol": "TLSv1.0",
            "strength": CipherStrength.MEDIUM,
            "bits": 128,
        },
        "TLSv1.1": {
            "name": "ECDHE-RSA-AES256-SHA",
            "protocol": "TLSv1.1",
            "strength": CipherStrength.MEDIUM,
            "bits": 256,
        },
        "TLSv1.2": {
            "name": "ECDHE-RSA-AES256-GCM-SHA384",
            "protocol": "TLSv1.2",
            "strength": CipherStrength.STRONG,
            "bits": 256,
        },
        "TLSv1.3": {
            "name": "TLS_AES_256_GCM_SHA384",
            "protocol": "TLSv1.3",
            "strength": CipherStrength.STRONG,
            "bits": 256,
        },
    }

    with (
        patch("bubo.core.tls.ciphers.has_openssl", return_value=True),
    ):

        def extract_cipher_side_effect(output, protocol_str):
            return mock_cipher_info.get(protocol_str)

        async def openssl_side_effect(domain, port, args, timeout):
            protocol_opt = args[0] if args else None
            return mock_responses.get(protocol_opt, ("", 1))

        def get_ciphers_side_effect(protocol):
            return ["MOCK_CIPHER"]

        with (
            patch(
                "bubo.core.tls.ciphers.run_openssl_command",
                side_effect=openssl_side_effect,
            ),
            patch(
                "bubo.core.tls.ciphers.get_ciphers_for_protocol",
                side_effect=get_ciphers_side_effect,
            ),
        ):
            results = []
            for protocol in TLSProtocol:
                result = await check_ciphers(domain, port, protocol, config)
                results.append(result)

            ciphers_by_protocol, cipher_strength = process_cipher_results(
                results, list(TLSProtocol)
            )

            assert len(results) == 4
            assert all(r is not None for r in results)

            for protocol in TLSProtocol:
                assert protocol.value in ciphers_by_protocol
                assert len(ciphers_by_protocol[protocol.value]) == 1


@pytest.mark.asyncio
async def test_cipher_check_with_disabled_config():
    """Test cipher checking with disabled configuration."""

    domain = "example.com"
    port = 443
    config = TLSCheckConfig(check_ciphers=False)

    with patch("bubo.core.tls.ciphers.has_openssl") as mock_has_openssl:
        openssl_mock = AsyncMockWithReturnValue(("openssl output", 0))
        with patch("bubo.core.tls.ciphers.run_openssl_command", openssl_mock):
            results = []
            for protocol in TLSProtocol:
                result = await check_ciphers(domain, port, protocol, config)
                results.append(result)

            assert all(r is None for r in results)

            mock_has_openssl.assert_not_called()


@pytest.mark.asyncio
async def test_cipher_check_without_openssl():
    """Test cipher checking when OpenSSL is not available."""

    domain = "example.com"
    port = 443
    config = TLSCheckConfig(check_ciphers=True)

    with patch(
        "bubo.core.tls.ciphers.has_openssl", return_value=False
    ) as mock_has_openssl:
        openssl_mock = AsyncMockWithReturnValue(("openssl output", 0))
        with patch("bubo.core.tls.ciphers.run_openssl_command", openssl_mock):
            results = []
            for protocol in TLSProtocol:
                result = await check_ciphers(domain, port, protocol, config)
                results.append(result)

            assert all(r is None for r in results)

            assert mock_has_openssl.call_count == 4


def test_process_mixed_results():
    """Test processing a mix of successful, failed, and error results."""

    results = [
        CipherResult(
            name="ECDHE-RSA-AES128-SHA",
            protocol="TLSv1.0",
            strength=CipherStrength.MEDIUM,
            bits=128,
        ),
        None,
        CipherResult(
            name="ECDHE-RSA-AES256-GCM-SHA384",
            protocol="TLSv1.2",
            strength=CipherStrength.STRONG,
            bits=256,
        ),
        Exception("Connection refused"),
    ]

    protocols = list(TLSProtocol)

    ciphers_by_protocol, cipher_strength = process_cipher_results(results, protocols)

    assert "TLSv1.0" in ciphers_by_protocol
    assert "TLSv1.2" in ciphers_by_protocol
    assert "TLSv1.1" not in ciphers_by_protocol
    assert "TLSv1.3" not in ciphers_by_protocol

    assert "medium" in cipher_strength
    assert "strong" in cipher_strength
    assert len(cipher_strength["medium"]) == 1
    assert len(cipher_strength["strong"]) == 1
