from bubo.core.report.statistics import (
    analyze_dmarc_policies,
    analyze_spf_policies,
    calculate_domain_score,
    calculate_domain_scores,
    count_status,
    count_valid_statuses,
    get_common_web_issues,
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


def test_count_valid_statuses():
    """Test the count_valid_statuses function."""
    state_dict = {
        "example.com": {"category1": "valid", "category2": "valid"},
        "example.org": {"category1": "not-valid", "category2": "valid"},
        "example.net": {"category1": "not-valid", "category2": "not-valid"},
    }

    result = count_valid_statuses(state_dict, "category1")
    assert result == 1

    result = count_valid_statuses(state_dict, "category2")
    assert result == 2

    result = count_valid_statuses(state_dict)
    assert result == 1


def test_get_common_web_issues():
    """Test the get_common_web_issues function."""
    web_results = {
        "example.com": {"security_assessment": {"issues": ["Issue1", "Issue2"]}},
        "example.org": {"security_assessment": {"issues": ["Issue1", "Issue3"]}},
        "example.net": {"security_assessment": {"issues": ["Issue3"]}},
        "example.edu": {},
    }

    common_issues = get_common_web_issues(web_results)

    assert len(common_issues) == 3

    assert common_issues[0][0] == "Issue1"
    assert common_issues[0][1] == 2

    assert common_issues[1][0] == "Issue3"
    assert common_issues[1][1] == 2

    assert common_issues[2][0] == "Issue2"
    assert common_issues[2][1] == 1


def test_analyze_spf_policies():
    """Test the analyze_spf_policies function."""
    email_results = {
        "example.com": {"spf": {"has_spf": True, "policy": "~all"}},
        "example.org": {"spf": {"has_spf": True, "policy": "-all"}},
        "example.net": {"spf": {"has_spf": False}},
        "example.edu": {"spf": {"has_spf": True, "policy": "?all"}},
    }

    policy_counts = analyze_spf_policies(email_results)

    assert policy_counts["~all"] == 1
    assert policy_counts["-all"] == 1
    assert policy_counts["none"] == 2


def test_analyze_dmarc_policies():
    """Test the analyze_dmarc_policies function."""
    email_results = {
        "example.com": {"dmarc": {"record_exists": True, "policy": "reject"}},
        "example.org": {"dmarc": {"record_exists": True, "policy": "quarantine"}},
        "example.net": {"dmarc": {"record_exists": True, "policy": "none"}},
        "example.edu": {"dmarc": {"record_exists": False}},
    }

    policy_counts = analyze_dmarc_policies(email_results)

    assert policy_counts["reject"] == 1
    assert policy_counts["quarantine"] == 1
    assert policy_counts["none"] == 1
    assert policy_counts["no_record"] == 1
