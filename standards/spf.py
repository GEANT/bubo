import asyncio

from core.dns.resolver import dns_manager
from core.logging.logger import setup_logger

logger = setup_logger(__name__)

MAX_DNS_LOOKUPS = 10  # Maximum allowed DNS lookups for SPF


async def get_spf_record(domain: str) -> str | None:
    try:
        answers = await dns_manager.resolve(domain, "TXT")
        for record in answers:
            try:
                decoded_strings = []
                for string in record.strings:
                    if isinstance(string, bytes):
                        decoded_strings.append(string.decode("utf-8"))
                    else:
                        decoded_strings.append(string)

                txt = "".join(decoded_strings)

                if txt.startswith("v=spf1 ") or txt == "v=spf1":
                    return txt
            except (UnicodeDecodeError, AttributeError):
                continue

        # If no SPF record found in TXT, try the deprecated SPF type
        # (this is for backward compatibility, though rarely used now)
        try:
            answers = await dns_manager.resolve(domain, "SPF")
            for record in answers:
                try:
                    decoded_strings = []
                    for string in record.strings:
                        if isinstance(string, bytes):
                            decoded_strings.append(string.decode("utf-8"))
                        else:
                            decoded_strings.append(string)

                    txt = "".join(decoded_strings)

                    if txt.startswith("v=spf1 ") or txt == "v=spf1":
                        return txt
                except (UnicodeDecodeError, AttributeError):
                    logger.error(f"Error decoding SPF record for {domain}")
                    continue

        except Exception as e:
            logger.debug(f"Error fetching SPF record for {domain}: {str(e)}")
            return None

        return None
    except asyncio.TimeoutError:
        logger.error(f"Timeout when fetching SPF record for {domain}")
        return None
    except Exception as e:
        logger.error(f"Error when fetching SPF record for {domain}: {e}")
        return None


async def parse_spf_record(record: str, domain: str) -> dict:
    if not record:
        return {"valid": False, "error": "No SPF record found"}

    if not record.startswith("v=spf1"):
        return {"valid": False, "error": "Invalid SPF record format"}

    components = record.split(" ")

    policy = "?all"  # Default is neutral (?all)
    redirect = None

    # Process all components to find mechanisms and modifiers
    includes = []
    a_records = []
    mx_records = []
    ptr_records = []
    exists = []

    for comp in components[1:]:  # Skip v=spf1
        if not comp:  # Skip empty components
            continue

        if comp in ["+all", "-all", "~all", "?all"]:
            policy = comp
        elif comp == "all":
            policy = "+all"

        elif comp.startswith("redirect="):
            redirect = comp[9:]

        elif comp.startswith("include:"):
            includes.append(comp[8:])

        elif comp.startswith("a:"):
            a_records.append(comp[2:])
        elif comp == "a":
            a_records.append(domain)

        elif comp.startswith("mx:"):
            mx_records.append(comp[3:])
        elif comp == "mx":
            mx_records.append(domain)

        elif comp.startswith("ptr:"):
            ptr_records.append(comp[4:])
        elif comp == "ptr":
            ptr_records.append(domain)

        elif comp.startswith("exists:"):
            exists.append(comp[7:])

    return {
        "valid": True,
        "policy": policy,
        "redirect": redirect,
        "includes": includes,
        "a_records": a_records,
        "mx_records": mx_records,
        "ptr_records": ptr_records,
        "exists": exists,
        "record": record,
    }


async def count_dns_lookups(
    spf_info: dict,
    domain: str,
    visited: set[str] | None = None,
    lookup_count: int = 0,
) -> tuple[int, str, dict | None]:
    if visited is None:
        visited = set()

    if not spf_info.get("valid", False):
        return lookup_count, spf_info.get("policy", "?"), None

    lookup_count += len(spf_info["includes"])
    lookup_count += len(spf_info["a_records"])
    lookup_count += len(spf_info["mx_records"])
    lookup_count += len(spf_info["ptr_records"])
    lookup_count += len(spf_info["exists"])

    if lookup_count > MAX_DNS_LOOKUPS:
        return lookup_count, spf_info["policy"], None

    # Follow includes if they don't contain macros
    for include_domain in spf_info["includes"]:
        if "%" in include_domain:  # Contains macros, skip
            continue

        if include_domain in visited:  # Prevent loops
            continue

        visited.add(include_domain)
        include_record = await get_spf_record(include_domain)
        if include_record:
            include_info = await parse_spf_record(include_record, include_domain)
            lookup_count, _, _ = await count_dns_lookups(
                include_info, include_domain, visited, lookup_count
            )

            if lookup_count > MAX_DNS_LOOKUPS:
                break

    # Follow redirect if it exists and doesn't contain macros
    policy = spf_info["policy"]
    redirect_info = None
    if (
        spf_info["redirect"]
        and "%" not in spf_info["redirect"]
        and lookup_count <= MAX_DNS_LOOKUPS
    ):
        redirect_domain = spf_info["redirect"]

        if redirect_domain not in visited:  # Prevent loops
            visited.add(redirect_domain)
            redirect_record = await get_spf_record(redirect_domain)
            if redirect_record:
                redirect_info = await parse_spf_record(redirect_record, redirect_domain)
                lookup_count, policy, _ = await count_dns_lookups(
                    redirect_info, redirect_domain, visited, lookup_count
                )

    return lookup_count, policy, redirect_info


def check_policy_strictness(policy: str) -> bool:
    return policy in ["~all", "-all"]


async def check_spf(domain: str) -> dict:
    spf_record = await get_spf_record(domain)

    if not spf_record:
        return {
            "domain": domain,
            "has_spf": False,
            "valid": False,
            "error": "No SPF record found",
        }

    spf_info = await parse_spf_record(spf_record, domain)

    if not spf_info["valid"]:
        return {
            "domain": domain,
            "has_spf": True,
            "valid": False,
            "error": spf_info["error"],
            "record": spf_record,
        }

    lookup_count, policy, redirect_info = await count_dns_lookups(spf_info, domain)

    if policy == "?all" and not spf_info["redirect"]:
        policy_explanation = "SPF record contains non-restrictive '?all' mechanism which makes your policy not effective enough. Try to use '~all' (soft fail) or '-all' (hard fail) instead."
    elif policy in ["~all", "-all"]:
        policy_explanation = f"Policy '{policy}' is sufficiently strict."
    else:
        policy_explanation = f"Policy '{policy}' is not sufficiently strict."

    is_strict = check_policy_strictness(policy)
    is_valid = spf_info["valid"] and lookup_count <= MAX_DNS_LOOKUPS and is_strict

    result = {
        "domain": domain,
        "has_spf": True,
        "valid": is_valid,
        "record": spf_record,
        "policy": policy,
        "policy_explanation": policy_explanation,
        "policy_sufficiently_strict": is_strict,
        "dns_lookups": lookup_count,
        "exceeds_lookup_limit": lookup_count > MAX_DNS_LOOKUPS,
    }

    # Add redirect information if present
    if spf_info["redirect"] and redirect_info:
        result["redirect_domain"] = spf_info["redirect"]
        result["redirect_info"] = redirect_info

    if not is_valid:
        if not is_strict:
            result["error"] = (
                f"Policy '{policy}' is not sufficiently strict, use '~all' or '-all'."
            )
        elif lookup_count > MAX_DNS_LOOKUPS:
            result["error"] = (
                f"SPF record exceeds maximum DNS lookups ({lookup_count} > {MAX_DNS_LOOKUPS})"
            )

    return result


async def check_domains(domains: list[str]) -> dict:
    results = {}
    for domain in domains:
        try:
            result = await check_spf(domain)
            results[domain] = result
        except Exception as e:
            print(f"Error checking SPF for {domain}: {e}")
            results[domain] = {
                "domain": domain,
                "has_spf": False,
                "valid": False,
                "error": f"Error: {str(e)}",
            }

    return results
