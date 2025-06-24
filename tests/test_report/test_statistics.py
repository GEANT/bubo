from bubo.core.report.statistics import (
    calculate_domain_score,
    calculate_domain_scores,
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


def test_calculate_domain_score_partial():
    """Test calculate_domain_score with partial compliance."""
    domain = "example.com"
    dnssec_state = {"example.com": {"DNSSEC": False}}
    dane_state = {"example.com": {"Mail Server of Domain": "partially-valid"}}
    email_state = {
        "example.com": {"SPF": "valid", "DKIM": "not-valid", "DMARC": "partially-valid"}
    }
    rpki_state = {
        "example.com": {
            "Mail Server of Domain": "valid",
            "Nameserver of Domain": "not-valid",
        }
    }
    web_state = {"example.com": {"rating": "fair"}}

    score = calculate_domain_score(
        domain, dnssec_state, dane_state, email_state, rpki_state, web_state
    )

    assert 0 < score < 100


def test_calculate_domain_score_zero_max_score():
    """Test calculate_domain_score with zero max_score."""
    domain = "example.com"

    dnssec_state = {"example.com": {"DNSSEC": False}}
    dane_state = {"example.com": {}}
    email_state = {
        "example.com": {"SPF": "not-valid", "DKIM": "not-valid", "DMARC": "not-valid"}
    }
    rpki_state = {"example.com": {}}
    web_state = {"example.com": {"rating": "poor"}}

    score = calculate_domain_score(
        domain, dnssec_state, dane_state, email_state, rpki_state, web_state
    )

    assert score == 0


def test_calculate_domain_scores():
    """Test the calculate_domain_scores function."""
    dnssec_state = {
        "example.com": {"DNSSEC": True},
        "example.org": {"DNSSEC": False},
    }
    dane_state = {
        "example.com": {"Mail Server of Domain": "valid"},
        "example.org": {"Mail Server of Domain": "not-valid"},
    }
    email_state = {
        "example.com": {"SPF": "valid", "DKIM": "valid", "DMARC": "valid"},
        "example.org": {"SPF": "not-valid", "DKIM": "not-valid", "DMARC": "not-valid"},
    }
    rpki_state = {
        "example.com": {
            "Mail Server of Domain": "valid",
            "Nameserver of Domain": "valid",
        },
        "example.org": {
            "Mail Server of Domain": "not-valid",
            "Nameserver of Domain": "not-valid",
        },
    }
    web_state = {
        "example.com": {"rating": "excellent"},
        "example.org": {"rating": "poor"},
    }

    scores = calculate_domain_scores(
        dnssec_state, dane_state, email_state, rpki_state, web_state
    )

    assert len(scores) == 2
    assert scores[0][0] == "example.com"
    assert scores[1][0] == "example.org"
    assert scores[0][1] > scores[1][1]
