from bubo.core.report.statistics import (
    analyze_dane_stats,
    analyze_dmarc_policies,
    analyze_dnssec_stats,
    analyze_email_stats,
    analyze_rpki_stats,
    analyze_spf_policies,
    analyze_tls_protocol_support,
    calculate_domain_score,
    calculate_domain_scores,
    count_status,
    count_valid_statuses,
    extract_dane_statuses,
    extract_email_statuses,
    extract_rpki_statuses,
    extract_web_security_issues,
    get_common_web_issues,
    get_domain_web_detail,
    get_top_domain_by_category,
    get_top_email_domain,
    get_web_rating_counts,
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


def test_get_web_rating_counts():
    """Test the get_web_rating_counts function."""
    web_state = {
        "example.com": {"rating": "excellent"},
        "example.org": {"rating": "good"},
        "example.net": {"rating": "fair"},
        "example.edu": {"rating": "poor"},
        "example.gov": {"rating": "unknown"},
    }

    rating_counts = get_web_rating_counts(web_state)

    assert rating_counts["excellent"] == 1
    assert rating_counts["good"] == 1
    assert rating_counts["fair"] == 1
    assert rating_counts["poor"] == 1


def test_get_top_email_domain():
    """Test the get_top_email_domain function."""
    email_state = {
        "example.com": {"SPF": "valid", "DKIM": "valid", "DMARC": "valid"},
        "example.org": {"SPF": "valid", "DKIM": "valid", "DMARC": "not-valid"},
        "example.net": {"SPF": "valid", "DKIM": "not-valid", "DMARC": "not-valid"},
    }

    top_domain, score = get_top_email_domain(email_state)

    assert top_domain == "example.com"
    assert score == 100.0


def test_get_top_domain_by_category():
    """Test the get_top_domain_by_category function."""
    category_state = {
        "example.com": {"criteria": "valid"},
        "example.org": {"criteria": "not-valid"},
        "example.net": {"criteria": "not-valid"},
    }

    domain = get_top_domain_by_category(category_state, "criteria", "valid")
    assert domain == "example.com"

    category_state = {
        "example.com": {"criteria": "not-valid"},
        "example.org": {"criteria": "not-valid"},
    }
    domain = get_top_domain_by_category(category_state, "criteria", "valid")
    assert domain == "example.com"


def test_analyze_tls_protocol_support():
    """Test the analyze_tls_protocol_support function."""
    web_results = {
        "example.com": {
            "protocol_support": {
                "protocols": [
                    {"name": "TLSv1.0", "supported": False},
                    {"name": "TLSv1.1", "supported": False},
                    {"name": "TLSv1.2", "supported": True},
                    {"name": "TLSv1.3", "supported": True},
                ]
            }
        },
        "example.org": {
            "protocol_support": {
                "protocols": [
                    {"name": "TLSv1.0", "supported": True},
                    {"name": "TLSv1.1", "supported": True},
                    {"name": "TLSv1.2", "supported": True},
                    {"name": "TLSv1.3", "supported": False},
                ]
            }
        },
        "example.net": {},
    }

    protocol_stats = analyze_tls_protocol_support(web_results)

    assert protocol_stats["domain_count"] == 3
    assert protocol_stats["TLSv1.0"]["supported"] == 1
    assert protocol_stats["TLSv1.0"]["total"] == 2
    assert protocol_stats["TLSv1.1"]["supported"] == 1
    assert protocol_stats["TLSv1.1"]["total"] == 2
    assert protocol_stats["TLSv1.2"]["supported"] == 2
    assert protocol_stats["TLSv1.2"]["total"] == 2
    assert protocol_stats["TLSv1.3"]["supported"] == 1
    assert protocol_stats["TLSv1.3"]["total"] == 2


def test_get_domain_web_detail():
    """Test the get_domain_web_detail function."""
    domain = "example.com"
    state = {"rating": "excellent"}
    web_results = {
        "example.com": {
            "security_assessment": {
                "rating": "excellent",
                "issues": ["Issue1"],
                "critical_issues_count": 0,
                "major_issues_count": 0,
                "minor_issues_count": 1,
            },
            "certificate": {
                "is_valid": True,
                "days_until_expiry": 60,
                "key_info": {"secure": True, "length": 2048},
            },
            "protocol_support": {
                "has_secure_protocols": True,
                "has_insecure_protocols": False,
                "secure_protocols": ["TLSv1.2", "TLSv1.3"],
            },
            "ciphers": {
                "has_weak_ciphers": False,
                "has_strong_ciphers": True,
            },
            "hsts": {
                "enabled": True,
                "include_subdomains": True,
                "preload": True,
                "max_age": 31536000,
            },
            "security_headers": {
                "content_security_policy": True,
                "x_content_type_options": True,
                "x_frame_options": True,
                "referrer_policy": True,
            },
        }
    }

    detail = get_domain_web_detail(domain, state, web_results)

    assert detail["domain"] == "example.com"
    assert detail["score"] > 90
    assert detail["rating"] == "excellent"
    assert detail["tls_secure"] is True
    assert detail["cert_valid"] is True
    assert detail["uses_secure_protocols"] is True
    assert len(detail["issues"]) == 1
    assert len(detail["recommendations"]) == 0


def test_get_domain_web_detail_missing_domain():
    """Test get_domain_web_detail with a domain not in web_results."""
    domain = "missing.com"
    state = {"rating": "poor"}
    web_results = {}

    detail = get_domain_web_detail(domain, state, web_results)

    assert detail["domain"] == "missing.com"
    assert detail["score"] == 0
    assert detail["tls_secure"] is False
    assert detail["cert_valid"] is False
    assert detail["uses_secure_protocols"] is False


def test_extract_web_security_issues():
    """Test the extract_web_security_issues function."""
    web_results = {
        "example.com": {"security_assessment": {"issues": ["Issue1", "Issue2"]}},
        "example.org": {"security_assessment": {"issues": ["Issue3"]}},
        "example.net": {},
    }

    issues = extract_web_security_issues(web_results)

    assert "example.com" in issues
    assert "example.org" in issues
    assert "example.net" in issues
    assert len(issues["example.com"]) == 2
    assert len(issues["example.org"]) == 1
    assert len(issues["example.net"]) == 0


def test_analyze_dnssec_stats():
    """Test the analyze_dnssec_stats function."""
    dnssec_state = {
        "example.com": {"DNSSEC": True},
        "example.org": {"DNSSEC": True},
        "example.net": {"DNSSEC": False},
    }
    domain_count = 3

    stats = analyze_dnssec_stats(dnssec_state, domain_count)

    assert stats["compliant"] == 2
    assert stats["non_compliant"] == 1
    assert stats["partially_compliant"] == 0


def test_extract_dane_statuses():
    """Test the extract_dane_statuses function."""
    dane_state = {
        "example.com": {
            "Mail Server of Domain": "valid",
            "Nameserver of Domain": "valid",
            "Nameserver of Mail Server": "valid",
        },
        "example.org": {
            "Mail Server of Domain": "not-valid",
            "Nameserver of Domain": "valid",
        },
    }

    mx_statuses, ns_statuses, mail_ns_statuses = extract_dane_statuses(dane_state)

    assert mx_statuses == ["valid", "not-valid"]
    assert ns_statuses == ["valid", "valid"]
    assert mail_ns_statuses == ["valid", "not-found"]


def test_analyze_dane_stats():
    """Test the analyze_dane_stats function."""
    dane_state = {
        "example.com": {
            "Mail Server of Domain": "valid",
            "Nameserver of Domain": "valid",
            "Nameserver of Mail Server": "valid",
        },
        "example.org": {
            "Mail Server of Domain": "not-valid",
            "Nameserver of Domain": "valid",
            "Nameserver of Mail Server": "partially-valid",
        },
    }

    dane_stats, mx_stats, ns_stats, mail_ns_stats = analyze_dane_stats(dane_state)

    assert dane_stats["compliant"] == 1
    assert dane_stats["partially_compliant"] == 0
    assert dane_stats["non_compliant"] == 1

    assert mx_stats["valid"] == 1
    assert mx_stats["not_valid"] == 1

    assert ns_stats["valid"] == 2
    assert ns_stats["not_valid"] == 0

    assert mail_ns_stats["valid"] == 1
    assert mail_ns_stats["partially_valid"] == 1


def test_extract_email_statuses():
    """Test the extract_email_statuses function."""
    email_state = {
        "example.com": {"SPF": "valid", "DKIM": "valid", "DMARC": "valid"},
        "example.org": {
            "SPF": "valid",
            "DKIM": "not-valid",
            "DMARC": "partially-valid",
        },
    }

    spf_statuses, dkim_statuses, dmarc_statuses = extract_email_statuses(email_state)

    assert spf_statuses == ["valid", "valid"]
    assert dkim_statuses == ["valid", "not-valid"]
    assert dmarc_statuses == ["valid", "partially-valid"]


def test_analyze_email_stats():
    """Test the analyze_email_stats function."""
    email_state = {
        "example.com": {"SPF": "valid", "DKIM": "valid", "DMARC": "valid"},
        "example.org": {"SPF": "valid", "DKIM": "not-valid", "DMARC": "not-valid"},
        "example.net": {"SPF": "not-valid", "DKIM": "not-valid", "DMARC": "not-valid"},
    }

    email_stats, spf_stats, dkim_stats, dmarc_stats, fully_compliant = (
        analyze_email_stats(email_state)
    )

    assert email_stats["compliant"] == 1
    assert email_stats["partially_compliant"] == 1
    assert email_stats["non_compliant"] == 1
    assert email_stats["fully_compliant"] == 1

    assert spf_stats["valid"] == 2
    assert dkim_stats["valid"] == 1
    assert dmarc_stats["valid"] == 1

    assert fully_compliant == 1


def test_extract_rpki_statuses():
    """Test the extract_rpki_statuses function."""
    rpki_state = {
        "example.com": {
            "Mail Server of Domain": "valid",
            "Nameserver of Domain": "valid",
            "Nameserver of Mail Server": "valid",
        },
        "example.org": {
            "Mail Server of Domain": "not-valid",
            "Nameserver of Domain": "valid",
        },
    }

    mx_statuses, ns_statuses, mail_ns_statuses = extract_rpki_statuses(rpki_state)

    assert mx_statuses == ["valid", "not-valid"]
    assert ns_statuses == ["valid", "valid"]

    assert mail_ns_statuses == ["valid", "not-valid"]


def test_analyze_rpki_stats():
    """Test the analyze_rpki_stats function."""
    rpki_state = {
        "example.com": {
            "Mail Server of Domain": "valid",
            "Nameserver of Domain": "valid",
            "Nameserver of Mail Server": "valid",
        },
        "example.org": {
            "Mail Server of Domain": "partially-valid",
            "Nameserver of Domain": "valid",
            "Nameserver of Mail Server": "not-valid",
        },
        "example.net": {
            "Mail Server of Domain": "not-valid",
            "Nameserver of Domain": "not-valid",
            "Nameserver of Mail Server": "not-valid",
        },
    }

    rpki_stats, mx_stats, ns_stats, mail_ns_stats = analyze_rpki_stats(rpki_state)

    assert rpki_stats["compliant"] == 1
    assert rpki_stats["partially_compliant"] == 1
    assert rpki_stats["non_compliant"] == 1

    assert mx_stats["valid"] == 1
    assert mx_stats["partially_valid"] == 1
    assert mx_stats["not_valid"] == 1

    assert ns_stats["valid"] == 2
    assert ns_stats["not_valid"] == 1

    assert mail_ns_stats["valid"] == 1
    assert mail_ns_stats["not_valid"] == 2
