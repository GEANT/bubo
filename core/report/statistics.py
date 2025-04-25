# /core/report/statistics.py

from collections import Counter
from datetime import datetime
from typing import Any

from core.report.json_utils import json_dumps, convert_sets_to_lists
from core.logging.logger import setup_logger

logger = setup_logger(__name__)


def count_status(statuses: list[str], valid_values: list[str]) -> dict[str, int]:
    """
    Count occurrences of different statuses in a list.

    Args:
        statuses: List of status strings to analyze
        valid_values: List of values considered "valid"

    Returns:
        Dictionary with counts for valid, partially-valid, not-valid and not-found states
    """
    counter = Counter(statuses)
    result = {
        "valid": sum(counter[status] for status in valid_values if status in counter),
        "partially_valid": counter.get("partially-valid", 0),
        "not_valid": counter.get("not-valid", 0),
        "not_found": counter.get("not-found", 0)
        + counter.get("No TLSA records found", 0),
    }
    return result


def calculate_domain_score(
    domain: str,
    dnssec_state: dict,
    dane_state: dict,
    email_state: dict,
    rpki_state: dict,
    web_state: dict,
) -> float:
    """
    Calculate compliance score for a single domain across all security standards.

    Args:
        domain: Domain to calculate score for
        dnssec_state: DNSSEC validation results
        dane_state: DANE validation results
        email_state: Email security validation results
        rpki_state: RPKI validation results
        web_state: Web security validation results

    Returns:
        Compliance score as a percentage (0-100)
    """

    score = 0
    max_score = 0

    if dnssec_state[domain]["DNSSEC"]:
        score += 1
    max_score += 1

    if "Mail Server of Domain" in dane_state[domain]:
        status = dane_state[domain]["Mail Server of Domain"]
        if status == "valid":
            score += 1
        elif status == "partially-valid":
            score += 0.5
        max_score += 1

    email_components = ["SPF", "DKIM", "DMARC"]
    for component in email_components:
        if email_state[domain][component] == "valid":
            score += 1
        elif email_state[domain][component] == "partially-valid":
            score += 0.5
        max_score += 1

    rpki_components = ["Mail Server of Domain", "Nameserver of Domain"]
    if "Nameserver of Mail Server" in rpki_state[domain]:
        rpki_components.append("Nameserver of Mail Server")

    for component in rpki_components:
        if component in rpki_state[domain]:
            if rpki_state[domain][component] == "valid":
                score += 1
            elif rpki_state[domain][component] == "partially-valid":
                score += 0.5
            max_score += 1

    web_rating = web_state[domain]["rating"]
    if web_rating == "excellent":
        score += 1
    elif web_rating == "good":
        score += 0.75
    elif web_rating == "fair":
        score += 0.5
    max_score += 1

    return (score / max_score) * 100 if max_score > 0 else 0


def calculate_domain_scores(
    dnssec_state: dict,
    dane_state: dict,
    email_state: dict,
    rpki_state: dict,
    web_state: dict,
) -> list[tuple[str, float]]:
    """
    Calculate overall compliance score for each domain across all security standards.

    Args:
        dnssec_state: DNSSEC validation results by domain
        dane_state: DANE validation results by domain
        email_state: Email security validation results by domain
        rpki_state: RPKI validation results by domain
        web_state: Web security validation results by domain

    Returns:
        List of (domain, score) tuples sorted by score in descending order
    """
    domain_scores = {}

    for domain in dnssec_state:
        domain_scores[domain] = calculate_domain_score(
            domain, dnssec_state, dane_state, email_state, rpki_state, web_state
        )

    return sorted(domain_scores.items(), key=lambda x: x[1], reverse=True)


def count_valid_statuses(state_dict: dict, category: str = None) -> int:
    """
    Count valid statuses for a specific category or valid domains in general.

    Args:
        state_dict: Dictionary with validation states
        category: Optional specific category to count

    Returns:
        Count of valid statuses
    """
    valid_count = 0

    if category:
        for domain, state in state_dict.items():
            if state.get(category) == "valid":
                valid_count += 1
    else:
        for domain, state in state_dict.items():
            if all(value == "valid" for value in state.values()):
                valid_count += 1

    return valid_count


def get_common_web_issues(web_results: dict) -> list[tuple[str, int, list[str]]]:
    """
    Analyze and map common web security issues across domains.

    Args:
        web_results: Web security validation results

    Returns:
        List of (issue, count, affected_domains) tuples sorted by count
    """
    issue_to_domains = {}

    for domain, result in web_results.items():
        if (
            "security_assessment" in result
            and "issues" in result["security_assessment"]
        ):
            for issue in result["security_assessment"]["issues"]:
                if issue not in issue_to_domains:
                    issue_to_domains[issue] = []
                issue_to_domains[issue].append(domain)

    common_issues = [
        (issue, len(domains), sorted(domains))
        for issue, domains in issue_to_domains.items()
        if len(domains) >= 1
    ]

    return sorted(common_issues, key=lambda x: x[1], reverse=True)


def analyze_spf_policies(email_results: dict) -> dict[str, int]:
    """
    Count the different SPF policies across domains.

    Args:
        email_results: Email security validation results

    Returns:
        Dictionary with counts of different SPF policies
    """
    policy_counts = {"~all": 0, "-all": 0, "other": 0, "none": 0}

    for domain, result in email_results.items():
        if not result["spf"]["has_spf"]:
            policy_counts["none"] += 1
        elif result["spf"]["policy"] == "~all":
            policy_counts["~all"] += 1
        elif result["spf"]["policy"] == "-all":
            policy_counts["-all"] += 1
        else:
            policy_counts["other"] += 1

    return policy_counts


def analyze_dmarc_policies(email_results: dict) -> dict[str, int]:
    """
    Count the different DMARC policies across domains.

    Args:
        email_results: Email security validation results

    Returns:
        Dictionary with counts of different DMARC policies
    """
    policy_counts = {"reject": 0, "quarantine": 0, "none": 0, "no_record": 0}

    for domain, result in email_results.items():
        if not result["dmarc"]["record_exists"]:
            policy_counts["no_record"] += 1
        elif result["dmarc"]["policy"] == "reject":
            policy_counts["reject"] += 1
        elif result["dmarc"]["policy"] == "quarantine":
            policy_counts["quarantine"] += 1
        else:
            policy_counts["none"] += 1

    return policy_counts


def get_web_rating_counts(web_state: dict) -> dict[str, int]:
    """
    Count web security ratings across domains.

    Args:
        web_state: Web security validation results

    Returns:
        Dictionary with counts of different ratings
    """
    rating_counts = {"excellent": 0, "good": 0, "fair": 0, "poor": 0}

    for domain, state in web_state.items():
        rating = state["rating"]
        if rating in rating_counts:
            rating_counts[rating] += 1

    return rating_counts


def get_top_email_domain(email_state: dict) -> tuple[str, float]:
    """
    Find the domain with the best email security implementation.

    Args:
        email_state: Email security validation results

    Returns:
        tuple of (domain, score percentage)
    """
    scores = {}
    for domain, state in email_state.items():
        score = 0
        if state["SPF"] == "valid":
            score += 1
        if state["DKIM"] == "valid":
            score += 1
        if state["DMARC"] == "valid":
            score += 1
        scores[domain] = (score / 3) * 100

    top_domain = max(scores.items(), key=lambda x: x[1])
    return top_domain


def get_top_domain_by_category(
    category_state: dict, criteria_key: str, valid_value: Any
) -> str:
    """
    Find the domain with the best score in a specific category.

    Args:
        category_state: Validation results for a category
        criteria_key: Key to check for validity
        valid_value: Value considered valid

    Returns:
        Domain name with valid criteria
    """
    for domain, state in category_state.items():
        if state.get(criteria_key) == valid_value:
            return domain
    return list(category_state.keys())[0]


def analyze_tls_protocol_support(web_results: dict) -> dict[str, dict[str, int]]:
    """
    Analyze TLS protocol support across domains.

    Args:
        web_results: Web security validation results with detailed protocol info

    Returns:
        Dictionary with protocol statistics including supported counts and totals
    """
    protocol_stats = {
        "TLSv1.0": {"supported": 0, "total": 0},
        "TLSv1.1": {"supported": 0, "total": 0},
        "TLSv1.2": {"supported": 0, "total": 0},
        "TLSv1.3": {"supported": 0, "total": 0},
    }

    domain_count = 0

    for domain, result in web_results.items():
        domain_count += 1
        if "protocol_support" in result and "protocols" in result["protocol_support"]:
            for protocol in result["protocol_support"]["protocols"]:
                protocol_name = protocol.get("name")
                if protocol_name in protocol_stats:
                    protocol_stats[protocol_name]["total"] += 1
                    if protocol.get("supported", False):
                        protocol_stats[protocol_name]["supported"] += 1

    protocol_stats["domain_count"] = domain_count

    return protocol_stats


def get_domain_web_detail(domain: str, state: dict, web_results: dict) -> dict:
    """
    Get detailed web security information for a single domain.

    Args:
        domain: Domain name to analyze
        state: Web security state for the domain
        web_results: Detailed web security results

    Returns:
        Dictionary with domain security details
    """

    issues = []
    if domain in web_results and "security_assessment" in web_results[domain]:
        if "issues" in web_results[domain]["security_assessment"]:
            issues = web_results[domain]["security_assessment"]["issues"]

    tls_secure = 30 if state.get("tls_secure", False) else 0
    cert_valid = 20 if state.get("cert_valid", False) else 0
    secure_protocols = 20 if state.get("uses_secure_protocols", False) else 0

    rating = state["rating"]
    rating_score = {"excellent": 30, "good": 20, "fair": 10, "poor": 0}.get(rating, 0)

    total_score = tls_secure + cert_valid + secure_protocols + rating_score

    return {
        "domain": domain,
        "score": total_score,
        "issues": issues,
        "tls_secure": state.get("tls_secure", False),
        "cert_valid": state.get("cert_valid", False),
        "uses_secure_protocols": state.get("uses_secure_protocols", False),
    }


def get_web_rating_distribution_details(
    web_state: dict, web_results: dict
) -> dict[str, list[dict]]:
    """
    Group domains by web security rating and include their issues.

    Args:
        web_state: Web security validation state results
        web_results: Web security validation detailed results

    Returns:
        Dictionary with rating categories as keys and lists of domain details
    """
    rating_details = {"excellent": [], "good": [], "fair": [], "poor": []}

    for domain, state in web_state.items():
        rating = state["rating"]

        domain_detail = get_domain_web_detail(domain, state, web_results)

        if rating in rating_details:
            rating_details[rating].append(domain_detail)

    for rating in rating_details:
        rating_details[rating] = sorted(
            rating_details[rating], key=lambda x: x["score"], reverse=True
        )

    return rating_details


def analyze_dnssec_stats(dnssec_state: dict, domain_count: int) -> dict[str, int]:
    """
    Analyze DNSSEC compliance across domains.

    Args:
        dnssec_state: DNSSEC validation state by domain
        domain_count: Total number of domains

    Returns:
        Dictionary with DNSSEC compliance statistics
    """
    dnssec_compliant = sum(
        1 for domain, state in dnssec_state.items() if state["DNSSEC"]
    )

    return {
        "compliant": dnssec_compliant,
        "non_compliant": domain_count - dnssec_compliant,
        "partially_compliant": 0,
    }


def extract_dane_statuses(dane_state: dict) -> tuple[list[str], list[str], list[str]]:
    """
    Extract DANE status lists for different server types.

    Args:
        dane_state: DANE validation state by domain

    Returns:
        tuple of (MX statuses, NS statuses, Mail server NS statuses)
    """
    dane_mx_statuses = [
        state.get("Mail Server of Domain", "not-found") for state in dane_state.values()
    ]
    dane_ns_statuses = [
        state.get("Nameserver of Domain", "not-found") for state in dane_state.values()
    ]
    dane_mailserver_ns_statuses = [
        state.get("Nameserver of Mail Server", "not-found")
        for state in dane_state.values()
    ]

    return dane_mx_statuses, dane_ns_statuses, dane_mailserver_ns_statuses


def analyze_dane_stats(
    dane_state: dict,
) -> tuple[dict[str, int], dict[str, int], dict[str, int], dict[str, int]]:
    """
    Analyze DANE compliance across domains.

    Args:
        dane_state: DANE validation state by domain

    Returns:
        tuple of (overall stats, MX stats, NS stats, Mail server NS stats)
    """

    dane_mx_statuses, dane_ns_statuses, dane_mailserver_ns_statuses = (
        extract_dane_statuses(dane_state)
    )

    dane_mx_stats = count_status(dane_mx_statuses, ["valid"])
    dane_ns_stats = count_status(dane_ns_statuses, ["valid"])
    dane_mailserver_ns_stats = count_status(dane_mailserver_ns_statuses, ["valid"])

    dane_stats = {
        "compliant": dane_mx_stats["valid"],
        "partially_compliant": dane_mx_stats["partially_valid"],
        "non_compliant": dane_mx_stats["not_valid"],
    }

    return dane_stats, dane_mx_stats, dane_ns_stats, dane_mailserver_ns_stats


def extract_email_statuses(email_state: dict) -> tuple[list[str], list[str], list[str]]:
    """
    Extract Email security status lists for different standards.

    Args:
        email_state: Email security validation state by domain

    Returns:
        tuple of (SPF statuses, DKIM statuses, DMARC statuses)
    """
    email_spf_statuses = [state["SPF"] for state in email_state.values()]
    email_dkim_statuses = [state["DKIM"] for state in email_state.values()]
    email_dmarc_statuses = [state["DMARC"] for state in email_state.values()]

    return email_spf_statuses, email_dkim_statuses, email_dmarc_statuses


def count_email_fully_compliant(email_state: dict) -> int:
    """
    Count domains with all three email security standards implemented correctly.

    Args:
        email_state: Email security validation state by domain

    Returns:
        Count of fully compliant domains
    """
    return sum(
        1
        for domain, state in email_state.items()
        if (
            state["SPF"] == "valid"
            and state["DKIM"] == "valid"
            and state["DMARC"] == "valid"
        )
    )


def analyze_email_stats(
    email_state: dict,
) -> tuple[dict[str, int], dict[str, int], dict[str, int], dict[str, int], int]:
    """
    Analyze email security compliance across domains.

    Args:
        email_state: Email security validation state by domain

    Returns:
        tuple of (overall stats, SPF stats, DKIM stats, DMARC stats, fully compliant count)
    """

    email_spf_statuses, email_dkim_statuses, email_dmarc_statuses = (
        extract_email_statuses(email_state)
    )

    email_spf_stats = count_status(email_spf_statuses, ["valid"])
    email_dkim_stats = count_status(email_dkim_statuses, ["valid"])
    email_dmarc_stats = count_status(email_dmarc_statuses, ["valid"])

    email_fully_compliant = count_email_fully_compliant(email_state)

    email_stats = {
        "compliant": count_valid_statuses(email_state),
        "partially_compliant": sum(
            1
            for domain, state in email_state.items()
            if any(value == "valid" for value in state.values())
            and not all(value == "valid" for value in state.values())
        ),
        "non_compliant": sum(
            1
            for domain, state in email_state.items()
            if all(value != "valid" for value in state.values())
        ),
        "fully_compliant": email_fully_compliant,
    }

    return (
        email_stats,
        email_spf_stats,
        email_dkim_stats,
        email_dmarc_stats,
        email_fully_compliant,
    )


def extract_rpki_statuses(rpki_state: dict) -> tuple[list[str], list[str], list[str]]:
    """
    Extract RPKI status lists for different server types.

    Args:
        rpki_state: RPKI validation state by domain

    Returns:
        tuple of (MX statuses, NS statuses, Mail server NS statuses)
    """
    rpki_mx_statuses = [
        state.get("Mail Server of Domain", "not-valid") for state in rpki_state.values()
    ]
    rpki_ns_statuses = [
        state.get("Nameserver of Domain", "not-valid") for state in rpki_state.values()
    ]
    rpki_mailserver_ns_statuses = [
        state.get("Nameserver of Mail Server", "not-valid")
        if "Nameserver of Mail Server" in state
        else "not-valid"
        for state in rpki_state.values()
    ]

    return rpki_mx_statuses, rpki_ns_statuses, rpki_mailserver_ns_statuses


def analyze_rpki_stats(
    rpki_state: dict,
) -> tuple[dict[str, int], dict[str, int], dict[str, int], dict[str, int]]:
    """
    Analyze RPKI compliance across domains.

    Args:
        rpki_state: RPKI validation state by domain

    Returns:
        tuple of (overall stats, MX stats, NS stats, Mail server NS stats)
    """

    rpki_mx_statuses, rpki_ns_statuses, rpki_mailserver_ns_statuses = (
        extract_rpki_statuses(rpki_state)
    )

    rpki_mx_stats = count_status(rpki_mx_statuses, ["valid"])
    rpki_ns_stats = count_status(rpki_ns_statuses, ["valid"])
    rpki_mailserver_ns_stats = count_status(rpki_mailserver_ns_statuses, ["valid"])

    rpki_stats = {
        "compliant": count_valid_statuses(rpki_state),
        "partially_compliant": sum(
            1
            for domain, state in rpki_state.items()
            if any(value == "partially-valid" for value in state.values())
            or (
                any(value == "valid" for value in state.values())
                and not all(value == "valid" for value in state.values())
            )
        ),
        "non_compliant": sum(
            1
            for domain, state in rpki_state.items()
            if all(
                value != "valid" and value != "partially-valid"
                for value in state.values()
            )
        ),
    }

    return rpki_stats, rpki_mx_stats, rpki_ns_stats, rpki_mailserver_ns_stats


def analyze_web_security_stats(web_state: dict) -> dict[str, int]:
    """
    Analyze web security compliance based on ratings.

    Args:
        web_state: Web security validation state by domain

    Returns:
        Dictionary with web security compliance statistics
    """
    web_compliant = 0
    web_partially_compliant = 0
    web_non_compliant = 0

    for domain, state in web_state.items():
        rating = state["rating"]
        if rating in ["excellent", "good"]:
            web_compliant += 1
        elif rating == "fair":
            web_partially_compliant += 1
        else:
            web_non_compliant += 1

    return {
        "compliant": web_compliant,
        "partially_compliant": web_partially_compliant,
        "non_compliant": web_non_compliant,
    }


def find_top_domains(
    domain_scores: list[tuple[str, float]],
    domain_metadata: dict,
    dnssec_state: dict,
    email_state: dict,
    web_state: dict,
) -> tuple[str, float, str, tuple[str, float], str]:
    """
    Find domains with the best scores in different categories.

    Args:
        domain_scores: List of (domain, score) tuples
        domain_metadata: Domain metadata
        dnssec_state: DNSSEC validation state by domain
        email_state: Email security validation state by domain
        web_state: Web security validation state by domain

    Returns:
        tuple of (top domain, top domain score, top DNSSEC domain,
                 top email domain with score, top web domain)
    """

    if domain_scores:
        top_domain_score = domain_scores[0][1]
        top_domains = [
            domain for domain, score in domain_scores if score == top_domain_score
        ]

        if len(top_domains) == 1:
            top_domain = top_domains[0]
        else:
            top_domain = ", ".join(top_domains)
    else:
        top_domain = next(iter(domain_metadata))
        top_domain_score = 0

    top_dnssec_domain = get_top_domain_by_category(dnssec_state, "DNSSEC", True)

    top_email_domain, top_email_score = get_top_email_domain(email_state)

    top_web_domain = None
    for domain, state in web_state.items():
        if state["rating"] == "excellent":
            top_web_domain = domain
            break

    if not top_web_domain:
        for domain, state in web_state.items():
            if state["rating"] == "good":
                top_web_domain = domain
                break

    if not top_web_domain:
        top_web_domain = next(iter(web_state))

    return (
        top_domain,
        top_domain_score,
        top_dnssec_domain,
        (top_email_domain, top_email_score),
        top_web_domain,
    )


def extract_server_states(
    dane_state: dict, rpki_state: dict
) -> tuple[dict[str, str], dict[str, str]]:
    """
    Extract specific state information for mail servers.

    Args:
        dane_state: DANE validation state by domain
        rpki_state: RPKI validation state by domain

    Returns:
        tuple of (DANE mail server state, RPKI mail server state)
    """
    dane_mail_server_state = {
        domain: state.get("Mail Server of Domain", "not-found")
        for domain, state in dane_state.items()
    }

    rpki_mail_server_state = {
        domain: state.get("Mail Server of Domain", "not-valid")
        for domain, state in rpki_state.items()
    }

    return dane_mail_server_state, rpki_mail_server_state


def prepare_statistics_context(results: dict) -> dict:
    """
    Analyze validation results and prepare context for statistics template.

    Args:
        results: Validation results from all security checks

    Returns:
        Template context dictionary with statistical analysis
    """
    domain_metadata = results["domain_metadata"]
    domain_count = len(domain_metadata)

    dnssec_state = results["validations"]["DNSSEC"]["state"]
    dane_state = results["validations"]["DANE"]["state"]
    email_state = results["validations"]["EMAIL_SECURITY"]["state"]
    rpki_state = results["validations"]["RPKI"]["state"]
    web_state = results["validations"]["WEB_SECURITY"]["state"]

    dnssec_results = results["validations"]["DNSSEC"]["results"]
    dane_results = results["validations"]["DANE"]["results"]
    email_results = results["validations"]["EMAIL_SECURITY"]["results"]
    rpki_results = results["validations"]["RPKI"]["results"]
    web_results = results["validations"]["WEB_SECURITY"]["results"]

    dnssec_stats = analyze_dnssec_stats(dnssec_state, domain_count)

    dane_stats, dane_mx_stats, dane_ns_stats, dane_mailserver_ns_stats = (
        analyze_dane_stats(dane_state)
    )

    (
        email_stats,
        email_spf_stats,
        email_dkim_stats,
        email_dmarc_stats,
        email_fully_compliant,
    ) = analyze_email_stats(email_state)

    rpki_stats, rpki_mx_stats, rpki_ns_stats, rpki_mailserver_ns_stats = (
        analyze_rpki_stats(rpki_state)
    )

    web_stats = analyze_web_security_stats(web_state)
    web_rating_details = get_web_rating_distribution_details(web_state, web_results)

    tls_protocol_stats = analyze_tls_protocol_support(web_results)

    domain_scores = calculate_domain_scores(
        dnssec_state, dane_state, email_state, rpki_state, web_state
    )

    (
        top_domain,
        top_domain_score,
        top_dnssec_domain,
        (top_email_domain, top_email_score),
        top_web_domain,
    ) = find_top_domains(
        domain_scores, domain_metadata, dnssec_state, email_state, web_state
    )

    spf_policy_counts = analyze_spf_policies(email_results)

    dmarc_policy_counts = analyze_dmarc_policies(email_results)

    common_issues = get_common_web_issues(web_results)

    web_rating_counts = get_web_rating_counts(web_state)

    dane_mail_server_state, rpki_mail_server_state = extract_server_states(
        dane_state, rpki_state
    )

    return {
        "domain_metadata": domain_metadata,
        "domain_count": domain_count,
        "dnssec_state": dnssec_state,
        "dane_state": dane_state,
        "email_state": email_state,
        "rpki_state": rpki_state,
        "web_state": web_state,
        "dnssec_results": dnssec_results,
        "dane_results": dane_results,
        "email_results": email_results,
        "rpki_results": rpki_results,
        "web_results": web_results,
        "dnssec_stats": dnssec_stats,
        "dane_stats": dane_stats,
        "dane_mx_stats": dane_mx_stats,
        "dane_ns_stats": dane_ns_stats,
        "dane_mailserver_ns_stats": dane_mailserver_ns_stats,
        "email_stats": email_stats,
        "email_spf_stats": email_spf_stats,
        "email_dkim_stats": email_dkim_stats,
        "email_dmarc_stats": email_dmarc_stats,
        "rpki_stats": rpki_stats,
        "rpki_mx_stats": rpki_mx_stats,
        "rpki_ns_stats": rpki_ns_stats,
        "rpki_mailserver_ns_stats": rpki_mailserver_ns_stats,
        "web_stats": web_stats,
        "domain_scores": domain_scores,
        "top_domain": top_domain,
        "top_domain_score": top_domain_score,
        "top_dnssec_domain": top_dnssec_domain,
        "top_email_domain": top_email_domain,
        "top_email_score": top_email_score,
        "top_web_domain": top_web_domain,
        "spf_policy_counts": spf_policy_counts,
        "dmarc_policy_counts": dmarc_policy_counts,
        "common_issues": common_issues,
        "web_rating_counts": web_rating_counts,
        "web_rating_details": web_rating_details,
        "tls_protocol_stats": tls_protocol_stats,
        "dane_mail_server_state": dane_mail_server_state,
        "rpki_mail_server_state": rpki_mail_server_state,
        "year": datetime.now().year,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


async def generate_statistics_report(
    results: dict,
    stats_final_html_path: str,
    stats_html_path: str,
    stats_json_path: str,
    stats_final_json_path: str,
    env: Any,
) -> str:
    """
    Generate statistics report HTML using the template.

    Args:
        results: Validation results from all security checks
        stats_final_html_path: Path to the final HTML report
        stats_html_path: Path to the HTML report
        stats_json_path: Path to the JSON data
        stats_final_json_path: Path to the final JSON data
        env: Jinja2 environment with access to templates

    Returns:
        Rendered HTML content for statistics page
    """
    context = {}
    context["stats_json"] = convert_sets_to_lists(prepare_statistics_context(results))

    template = env.get_template("statistics.html")
    rendered_html = template.render(stats_json=context["stats_json"])

    context_json = json_dumps(context["stats_json"], indent=2, sort_keys=True)

    try:
        for file_path in [stats_json_path, stats_final_json_path]:
            with open(file_path, "w") as f:
                f.write(context_json)

        for file_path in [stats_html_path, stats_final_html_path]:
            with open(file_path, "w") as f:
                f.write(rendered_html)
        logger.info(f"Statistics report generated: {stats_html_path}")
    except Exception as e:
        logger.error(f"Error writing statistics report: {e}")

    return rendered_html
