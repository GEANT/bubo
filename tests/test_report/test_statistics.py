from bubo.core.report.statistics import (
    calculate_domain_score,
    count_status,
)


def test_count_status():
    """Test the count_status function."""
    statuses = ["valid", "valid", "partially-valid", "not-valid", "not-found"]
    valid_values = ["valid"]
    result = count_status(statuses, valid_values)

    assert result["valid"] == 2
    assert result["partially_valid"] == 1
    assert result["not_valid"] == 1
    assert result["not_found"] == 1


def test_count_status_with_multiple_valid_values():
    """Test count_status with multiple valid values."""
    statuses = ["valid", "good", "partially-valid", "not-valid", "not-found"]
    valid_values = ["valid", "good"]
    result = count_status(statuses, valid_values)

    assert result["valid"] == 2
    assert result["partially_valid"] == 1
    assert result["not_valid"] == 1
    assert result["not_found"] == 1


def test_calculate_domain_score():
    """Test the calculate_domain_score function."""
    domain = "example.com"
    dnssec_state = {"example.com": {"DNSSEC": True}}
    dane_state = {"example.com": {"Mail Server of Domain": "valid"}}
    email_state = {"example.com": {"SPF": "valid", "DKIM": "valid", "DMARC": "valid"}}
    rpki_state = {
        "example.com": {
            "Mail Server of Domain": "valid",
            "Nameserver of Domain": "valid",
            "Nameserver of Mail Server": "valid",
        }
    }
    web_state = {"example.com": {"rating": "excellent"}}

    score = calculate_domain_score(
        domain, dnssec_state, dane_state, email_state, rpki_state, web_state
    )

    assert score == 100
