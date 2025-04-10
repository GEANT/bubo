import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from standards.email_security import (
    extract_dkim_key_info,
    get_txt_records,
    check_dmarc,
    run,
)


@pytest.fixture
def mock_dmarc_answer():
    record = MagicMock()
    record.strings = [
        b"v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:reports@example.com"
    ]
    return [record]


@pytest.fixture(autouse=True)
def mock_dns_manager():
    with patch(
        "core.dns.resolver.dns_manager.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.return_value = []
        yield mock_resolve


@pytest.fixture
def mock_dns_answer():
    record = MagicMock()
    record.strings = [b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"]
    return [record]


# Rest of the fixtures remain unchanged


@pytest.mark.asyncio
async def test_get_txt_records_success(mock_dns_answer):
    with patch(
        "standards.email_security.dns_manager.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.return_value = mock_dns_answer
        result = await get_txt_records("example.com")
        assert result == ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"]
        mock_resolve.assert_called_once_with("example.com", "TXT")


# Rest of the test functions remain unchanged


@pytest.mark.asyncio
async def test_run_with_vulnerable_dkim():
    """Test run function when DKIM key is vulnerable"""
    spf_result = {
        "domain": "example.com",
        "has_spf": True,
        "valid": True,
        "record": "v=spf1 include:_spf.example.com ~all",
        "dns_lookups": 1,
        "exceeds_lookup_limit": False,
        "policy": "~all",
        "policy_explanation": "Policy '~all' is sufficiently strict.",
        "policy_sufficiently_strict": True,
    }

    dkim_result = {
        "selectors_found": ["selector1"],
        "records": {
            "selector1": {
                "record": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
                "valid": True,
                "key_info": {
                    "key_type": "rsa",
                    "key_length": 512,
                    "strength": "vulnerable",
                    "strength_description": "RSA-512 is highly vulnerable. Can be cracked for less than $8 in the cloud.",
                    "error": None,
                },
            }
        },
        "valid": True,
        "key_info": {
            "selector1": {
                "key_type": "rsa",
                "key_length": 512,
                "strength": "vulnerable",
                "strength_description": "RSA-512 is highly vulnerable. Can be cracked for less than $8 in the cloud.",
                "error": None,
            }
        },
        "overall_key_strength": "vulnerable",
        "error": None,
    }

    dmarc_result = {
        "record_exists": True,
        "valid": True,
        "record": "v=DMARC1; p=reject; pct=100;",
        "policy": "reject",
        "sub_policy": "reject",
        "percentage": 100,
        "error": None,
        "warnings": [],
        "rua": None,
        "ruf": None,
    }

    with (
        patch("core.dns.resolver.dns_manager.resolve", new_callable=AsyncMock),
        patch("standards.email_security.check_spf", new_callable=AsyncMock) as mock_spf,
        patch(
            "standards.email_security.check_dkim", new_callable=AsyncMock
        ) as mock_dkim,
        patch(
            "standards.email_security.check_dmarc", new_callable=AsyncMock
        ) as mock_dmarc,
    ):
        mock_spf.return_value = spf_result
        mock_dkim.return_value = dkim_result
        mock_dmarc.return_value = dmarc_result

        results, state = await run("example.com")

        assert "example.com" in results
        assert results["example.com"]["spf"] == spf_result
        assert results["example.com"]["dkim"] == dkim_result
        assert results["example.com"]["dmarc"] == dmarc_result

        assert "example.com" in state
        assert state["example.com"]["SPF"] == "valid"
        assert state["example.com"]["DKIM"] == "critically-weak-key"
        assert state["example.com"]["DMARC"] == "valid"


@pytest.mark.asyncio
async def test_check_dmarc_valid(mock_dmarc_answer):
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = [
            "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:reports@example.com"
        ]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is True
        assert (
            result["record"]
            == "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:reports@example.com"
        )
        assert result["policy"] == "reject"
        assert result["sub_policy"] == "quarantine"
        assert result["percentage"] == 100
        assert result["error"] is None
        assert result["warnings"] == []


@pytest.mark.asyncio
async def test_check_dmarc_invalid_policy():
    """Test checking DMARC with 'none' policy."""
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; p=none; pct=100;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["policy"] == "none"
        assert (
            result["error"]
            == "Policy 'none' is insufficient to prevent domain abuse. It should be 'reject' or 'quarantine' to be effective and strict."
        )


@pytest.mark.asyncio
async def test_check_dmarc_partial_enforcement():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; p=quarantine; pct=50;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is True
        assert result["policy"] == "quarantine"
        assert result["percentage"] == 50
        assert (
            "Partial DMARC enforcement (50%) may reduce effectiveness"
            in result["warnings"]
        )


@pytest.mark.asyncio
async def test_check_dmarc_subdomain_none_policy():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; p=reject; sp=none; pct=100;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is True
        assert result["policy"] == "reject"
        assert result["sub_policy"] == "none"
        assert (
            "Subdomain policy 'none' may allow domain abuse via subdomains"
            in result["warnings"]
        )


@pytest.mark.asyncio
async def test_check_dmarc_missing_record():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = []

        result = await check_dmarc("example.com")

        assert result["record_exists"] is False
        assert result["valid"] is False
        assert result["error"] == "No DMARC record found"


@pytest.mark.asyncio
async def test_check_dmarc_multiple_records():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = [
            "v=DMARC1; p=reject; pct=100;",
            "v=DMARC1; p=quarantine; pct=100;",
        ]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["error"] == "Multiple DMARC records found"


@pytest.mark.asyncio
async def test_check_dmarc_invalid_syntax():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1 p=reject pct=100"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["error"] == "Invalid DMARC syntax"


@pytest.mark.asyncio
async def test_check_dmarc_missing_policy():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; pct=100;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["error"] == "Missing required policy (p) tag"


@pytest.mark.asyncio
async def test_check_dmarc_invalid_percentage():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; p=reject; pct=101;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["error"] == "Invalid percentage value: 101"


@pytest.mark.asyncio
async def test_check_dmarc_exception():
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.side_effect = Exception("Test exception")
        result = await check_dmarc("example.com")

        assert result["valid"] is False
        assert "Test exception" in result["error"]


@pytest.mark.asyncio
async def test_run_success():
    spf_result = {
        "domain": "example.com",
        "has_spf": True,
        "valid": True,
        "record": "v=spf1 include:_spf.example.com ~all",
        "dns_lookups": 1,
        "exceeds_lookup_limit": False,
        "policy": "~all",
        "policy_explanation": "Policy '~all' is sufficiently strict.",
        "policy_sufficiently_strict": True,
    }

    dkim_result = {
        "selectors_found": ["selector1"],
        "records": {
            "selector1": {
                "record": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
                "valid": True,
                "key_info": {
                    "key_type": "rsa",
                    "key_length": 2048,
                    "strength": "strong",
                    "strength_description": "RSA-2048 is the current recommended standard for DKIM keys.",
                    "error": None,
                },
            }
        },
        "valid": True,
        "key_info": {
            "selector1": {
                "key_type": "rsa",
                "key_length": 2048,
                "strength": "strong",
                "strength_description": "RSA-2048 is the current recommended standard for DKIM keys.",
                "error": None,
            }
        },
        "overall_key_strength": "strong",
        "error": None,
    }

    dmarc_result = {
        "record_exists": True,
        "valid": True,
        "record": "v=DMARC1; p=reject; pct=100;",
        "policy": "reject",
        "sub_policy": "reject",
        "percentage": 100,
        "error": None,
        "warnings": [],
        "rua": None,
        "ruf": None,
    }

    with (
        patch("core.dns.resolver.dns_manager.resolve", new_callable=AsyncMock),
        patch("standards.email_security.check_spf", new_callable=AsyncMock) as mock_spf,
        patch(
            "standards.email_security.check_dkim", new_callable=AsyncMock
        ) as mock_dkim,
        patch(
            "standards.email_security.check_dmarc", new_callable=AsyncMock
        ) as mock_dmarc,
    ):
        mock_spf.return_value = spf_result
        mock_dkim.return_value = dkim_result
        mock_dmarc.return_value = dmarc_result

        results, state = await run("example.com")

        assert "example.com" in results
        assert results["example.com"]["spf"] == spf_result
        assert results["example.com"]["dkim"] == dkim_result
        assert results["example.com"]["dmarc"] == dmarc_result

        assert "example.com" in state
        assert state["example.com"]["SPF"] == "valid"
        assert state["example.com"]["DKIM"] == "valid"
        assert state["example.com"]["DMARC"] == "valid"


@pytest.mark.asyncio
async def test_run_with_invalid_checks():
    spf_result = {"valid": False, "record": "v=spf1 -all"}
    dkim_result = {
        "selectors_found": [],
        "records": {},
        "valid": False,
        "error": "No DKIM records found with common selectors",
    }
    dmarc_result = {
        "record_exists": True,
        "valid": False,
        "record": "v=DMARC1; p=none;",
        "policy": "none",
        "sub_policy": "none",
        "percentage": 100,
        "error": "Policy 'none' is insufficient to prevent domain abuse",
        "warnings": [],
    }

    with (
        patch("standards.email_security.check_spf", new_callable=AsyncMock) as mock_spf,
        patch(
            "standards.email_security.check_dkim", new_callable=AsyncMock
        ) as mock_dkim,
        patch(
            "standards.email_security.check_dmarc", new_callable=AsyncMock
        ) as mock_dmarc,
    ):
        mock_spf.return_value = spf_result
        mock_dkim.return_value = dkim_result
        mock_dmarc.return_value = dmarc_result

        results, state = await run("example.com")

        assert state["example.com"]["SPF"] == "partially-valid"
        assert state["example.com"]["DKIM"] == "not-valid"
        assert state["example.com"]["DMARC"] == "partially-valid"


@pytest.mark.asyncio
async def test_run_exception():
    with patch(
        "standards.email_security.check_spf", new_callable=AsyncMock
    ) as mock_spf:
        mock_spf.side_effect = Exception("Test exception")
        results, state = await run("example.com")

        assert results == {}
        assert state == {
            "example.com": {
                "SPF": "not-valid",
                "DKIM": "not-valid",
                "DMARC": "not-valid",
            }
        }


@pytest.mark.asyncio
async def test_get_txt_records_exception_without_record_type():
    """Test get_txt_records with general exception and no record_type"""
    with patch(
        "standards.email_security.dns_manager.resolve", new_callable=AsyncMock
    ) as mock_resolve:
        mock_resolve.side_effect = Exception("Test general exception")
        result = await get_txt_records("example.com")
        assert result == []


def test_extract_dkim_key_info_ed25519():
    """Test extraction of Ed25519 key"""
    result = extract_dkim_key_info(
        "v=DKIM1; k=ed25519; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
    )

    assert result["key_type"] == "Ed25519"
    assert result["key_length"] == 256
    assert result["strength"] == "future-proof"
    assert "Ed25519" in result["strength_description"]
    assert result["error"] is None


def test_extract_dkim_key_info_unsupported_key_type():
    """Test extraction with unsupported key type"""
    result = extract_dkim_key_info(
        "v=DKIM1; k=unsupported; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
    )

    assert result["key_type"] == "unsupported"
    assert "Unsupported key type" in result["error"]


def test_extract_dkim_key_info_no_public_key():
    """Test extraction with missing public key"""
    result = extract_dkim_key_info("v=DKIM1; k=rsa;")

    assert result["key_type"] == "rsa"
    assert "No public key found" in result["error"]


def test_extract_dkim_key_info_empty_public_key():
    """Test extraction with empty public key"""
    result = extract_dkim_key_info("v=DKIM1; k=rsa; p=")

    assert result["key_type"] == "rsa"
    assert "No public key found" in result["error"]


def test_extract_dkim_key_info_general_exception():
    """Test general exception handling in extract_dkim_key_info"""
    with patch(
        "standards.email_security.re.search", side_effect=Exception("Regex failure")
    ):
        result = extract_dkim_key_info(
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
        )

        assert "Error extracting key info" in result["error"]


@pytest.mark.parametrize(
    "key_size,expected_strength,description_contains",
    [
        (512, "vulnerable", "highly vulnerable"),
        (1024, "acceptable", "acceptable"),
        (2048, "strong", "recommended standard"),
        (4096, "future-proof", "future-proofing"),
    ],
)
def test_extract_dkim_key_info_rsa_key_sizes(
    key_size, expected_strength, description_contains, monkeypatch
):
    """Test RSA key sizes by patching the cryptography module"""

    class MockKey:
        @property
        def key_size(self):
            return key_size

    mock_load_key = MagicMock(return_value=MockKey())

    import sys

    mock_serialization = MagicMock()
    mock_serialization.load_der_public_key = mock_load_key

    original_module = sys.modules.get(
        "cryptography.hazmat.primitives.serialization", None
    )

    try:
        sys.modules["cryptography.hazmat.primitives.serialization"] = mock_serialization

        with patch("base64.b64decode", return_value=b"test_key_bytes"):
            result = extract_dkim_key_info(
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
            )

        assert result["key_type"] == "rsa"
        assert result["key_length"] == key_size
        assert result["strength"] == expected_strength
        assert description_contains in result["strength_description"]
        assert result["error"] is None

    finally:
        if original_module:
            sys.modules["cryptography.hazmat.primitives.serialization"] = (
                original_module
            )
        else:
            sys.modules.pop("cryptography.hazmat.primitives.serialization", None)


def test_extract_dkim_key_info_fallback_parsing(monkeypatch):
    """Test fallback parsing when cryptography library fails"""

    mock_serialization = MagicMock()
    mock_serialization.load_der_public_key = MagicMock(
        side_effect=Exception("Cryptography failure")
    )

    import sys

    original_module = sys.modules.get(
        "cryptography.hazmat.primitives.serialization", None
    )

    try:
        sys.modules["cryptography.hazmat.primitives.serialization"] = mock_serialization

        with patch("base64.b64decode") as mock_b64decode:
            mock_b64decode.return_value = b"0" * 276

            result = extract_dkim_key_info(
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
            )

        assert result["key_type"] == "rsa"
        assert result["key_length"] == 2048
        assert result["strength"] == "unknown"
        assert "estimation" in result["strength_description"]

    finally:
        if original_module:
            sys.modules["cryptography.hazmat.primitives.serialization"] = (
                original_module
            )
        else:
            sys.modules.pop("cryptography.hazmat.primitives.serialization", None)


def test_extract_dkim_key_info_fallback_exception(monkeypatch):
    """Test when even fallback parsing fails"""

    mock_serialization = MagicMock()
    mock_serialization.load_der_public_key = MagicMock(
        side_effect=Exception("Cryptography failure")
    )

    import sys

    original_module = sys.modules.get(
        "cryptography.hazmat.primitives.serialization", None
    )

    try:
        sys.modules["cryptography.hazmat.primitives.serialization"] = mock_serialization

        with patch("base64.b64decode", side_effect=Exception("Base64 decode error")):
            result = extract_dkim_key_info("v=DKIM1; k=rsa; p=INVALID")

        assert "Failed to parse RSA key" in result["error"]

    finally:
        if original_module:
            sys.modules["cryptography.hazmat.primitives.serialization"] = (
                original_module
            )
        else:
            sys.modules.pop("cryptography.hazmat.primitives.serialization", None)


@pytest.mark.asyncio
async def test_check_dmarc_invalid_policy_value():
    """Test check_dmarc with an invalid policy value"""
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; p=invalid; pct=100;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is False
        assert result["policy"] == "invalid"
        assert "Invalid policy value" in result["error"]


@pytest.mark.asyncio
async def test_check_dmarc_valid_quarantine_policy():
    """Test check_dmarc with a valid quarantine policy"""
    with patch(
        "standards.email_security.get_txt_records", new_callable=AsyncMock
    ) as mock_get_txt:
        mock_get_txt.return_value = ["v=DMARC1; p=quarantine; pct=100;"]

        result = await check_dmarc("example.com")

        assert result["record_exists"] is True
        assert result["valid"] is True
        assert result["policy"] == "quarantine"
        assert result["sub_policy"] == "quarantine"
        assert result["error"] is None


@pytest.mark.asyncio
async def test_run_with_acceptable_dkim():
    """Test run function when DKIM key is of acceptable strength"""
    spf_result = {
        "domain": "example.com",
        "has_spf": True,
        "valid": True,
        "record": "v=spf1 include:_spf.example.com ~all",
        "dns_lookups": 1,
        "exceeds_lookup_limit": False,
        "policy": "~all",
        "policy_explanation": "Policy '~all' is sufficiently strict.",
        "policy_sufficiently_strict": True,
    }

    dkim_result = {
        "selectors_found": ["selector1"],
        "records": {
            "selector1": {
                "record": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
                "valid": True,
                "key_info": {
                    "key_type": "rsa",
                    "key_length": 1024,
                    "strength": "acceptable",
                    "strength_description": "RSA-1024 is considered acceptable by modern standards.",
                    "error": None,
                },
            }
        },
        "valid": True,
        "key_info": {
            "selector1": {
                "key_type": "rsa",
                "key_length": 1024,
                "strength": "acceptable",
                "strength_description": "RSA-1024 is considered acceptable by modern standards.",
                "error": None,
            }
        },
        "overall_key_strength": "acceptable",
        "error": None,
    }

    dmarc_result = {
        "record_exists": True,
        "valid": True,
        "record": "v=DMARC1; p=reject; pct=100;",
        "policy": "reject",
        "sub_policy": "reject",
        "percentage": 100,
        "error": None,
        "warnings": [],
        "rua": None,
        "ruf": None,
    }

    with (
        patch("standards.email_security.check_spf", new_callable=AsyncMock) as mock_spf,
        patch(
            "standards.email_security.check_dkim", new_callable=AsyncMock
        ) as mock_dkim,
        patch(
            "standards.email_security.check_dmarc", new_callable=AsyncMock
        ) as mock_dmarc,
    ):
        mock_spf.return_value = spf_result
        mock_dkim.return_value = dkim_result
        mock_dmarc.return_value = dmarc_result

        results, state = await run("example.com")

        assert "example.com" in results
        assert results["example.com"]["spf"] == spf_result
        assert results["example.com"]["dkim"] == dkim_result
        assert results["example.com"]["dmarc"] == dmarc_result

        assert "example.com" in state
        assert state["example.com"]["SPF"] == "valid"
        assert state["example.com"]["DKIM"] == "valid"
        assert state["example.com"]["DMARC"] == "valid"


@pytest.mark.asyncio
async def test_run_with_future_proof_dkim():
    """Test run function when DKIM key is future-proof strength"""
    spf_result = {
        "domain": "example.com",
        "has_spf": True,
        "valid": True,
        "record": "v=spf1 include:_spf.example.com ~all",
        "dns_lookups": 1,
        "exceeds_lookup_limit": False,
        "policy": "~all",
        "policy_explanation": "Policy '~all' is sufficiently strict.",
        "policy_sufficiently_strict": True,
    }

    dkim_result = {
        "selectors_found": ["selector1"],
        "records": {
            "selector1": {
                "record": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
                "valid": True,
                "key_info": {
                    "key_type": "rsa",
                    "key_length": 4096,
                    "strength": "future-proof",
                    "strength_description": "RSA-4096 exceeds current recommendations and provides future-proofing.",
                    "error": None,
                },
            }
        },
        "valid": True,
        "key_info": {
            "selector1": {
                "key_type": "rsa",
                "key_length": 4096,
                "strength": "future-proof",
                "strength_description": "RSA-4096 exceeds current recommendations and provides future-proofing.",
                "error": None,
            }
        },
        "overall_key_strength": "future-proof",
        "error": None,
    }

    dmarc_result = {
        "record_exists": True,
        "valid": True,
        "record": "v=DMARC1; p=reject; pct=100;",
        "policy": "reject",
        "sub_policy": "reject",
        "percentage": 100,
        "error": None,
        "warnings": [],
        "rua": None,
        "ruf": None,
    }

    with (
        patch("standards.email_security.check_spf", new_callable=AsyncMock) as mock_spf,
        patch(
            "standards.email_security.check_dkim", new_callable=AsyncMock
        ) as mock_dkim,
        patch(
            "standards.email_security.check_dmarc", new_callable=AsyncMock
        ) as mock_dmarc,
    ):
        mock_spf.return_value = spf_result
        mock_dkim.return_value = dkim_result
        mock_dmarc.return_value = dmarc_result

        results, state = await run("example.com")

        assert state["example.com"]["DKIM"] == "valid"
