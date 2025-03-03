import asyncio
import dns.asyncresolver
import dns.exception
from logging import getLogger
from typing import Dict, List, Tuple, Optional
import re
from core.utils import dns_manager


logger = getLogger(__name__)

# Common DKIM selector patterns
COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "dkim", "mail"]


async def get_txt_records(domain: str, record_type: str = None) -> List[str]:
    """
    Fetch TXT records for a given domain.
    """
    try:
        answers = await dns_manager.resolve(domain, "TXT")
        return [record.strings[0].decode("utf-8") for record in answers]
    except dns.resolver.NXDOMAIN:
        if record_type:
            logger.debug(f"No {record_type} record found for {domain} (NXDOMAIN)")
        return []
    except dns.resolver.NoAnswer:
        if record_type:
            logger.debug(f"No {record_type} record found for {domain} (NoAnswer)")
        return []
    except Exception as e:
        if record_type:
            logger.debug(f"Error fetching {record_type} records for {domain}: {str(e)}")
        return []


async def check_spf(domain: str) -> Dict:
    """Check SPF record for a domain."""
    results = {
        "record_exists": False,
        "valid": False,
        "record": None,
        "policy": None,
        "includes": [],
        "error": None,
    }

    try:
        txt_records = await get_txt_records(domain, "spf")
        spf_records = [r for r in txt_records if r.startswith("v=spf1")]

        if not spf_records:
            results["error"] = "No SPF record found"
            return results

        if len(spf_records) > 1:
            results["error"] = "Multiple SPF records found"
            results["record_exists"] = True
            results["valid"] = False
            return results

        spf_record = spf_records[0]
        results["record_exists"] = True
        results["record"] = spf_record

        # Extract policy
        if " -all" in spf_record:
            results["policy"] = "hard fail"
        elif " ~all" in spf_record:
            results["policy"] = "soft fail"
        elif " ?all" in spf_record:
            results["policy"] = "neutral"
        elif " +all" in spf_record:
            results["policy"] = "pass"
        else:
            results["policy"] = "none"

        # Extract includes
        includes = re.findall(r"include:(\S+)", spf_record)
        results["includes"] = includes

        results["valid"] = True

    except Exception as e:
        results["error"] = str(e)
        logger.error(f"Error checking SPF for {domain}: {str(e)}")

    return results


async def check_dkim_selector(domain: str, selector: str) -> Optional[Dict]:
    """Check a specific DKIM selector."""
    dkim_domain = f"{selector}._domainkey.{domain}"
    txt_records = await get_txt_records(dkim_domain, "dkim")

    for record in txt_records:
        if "v=DKIM1" in record:
            return {"record": record, "valid": True, "selector": selector}
    return None


async def check_dkim(domain: str) -> Dict:
    """Check DKIM records for a domain."""
    results = {"selectors_found": [], "records": {}, "valid": False, "error": None}

    try:
        # Check all selectors concurrently
        tasks = [
            check_dkim_selector(domain, selector) for selector in COMMON_DKIM_SELECTORS
        ]
        selector_results = await asyncio.gather(*tasks)

        # Process results
        valid_records = [r for r in selector_results if r is not None]

        if valid_records:
            results["selectors_found"] = [r["selector"] for r in valid_records]
            results["records"] = {
                r["selector"]: {"record": r["record"], "valid": r["valid"]}
                for r in valid_records
            }
            results["valid"] = True
        else:
            results["error"] = "No DKIM records found with common selectors"

    except Exception as e:
        results["error"] = str(e)
        logger.error(f"Error checking DKIM for {domain}: {str(e)}")

    return results


async def check_dmarc(domain: str) -> Dict:
    """
    Check DMARC record for a domain.
    Validates record syntax and ensures strict policy to prevent domain abuse.
    """
    results = {
        "record_exists": False,
        "valid": False,
        "record": None,
        "policy": None,
        "sub_policy": None,
        "percentage": None,
        "error": None,
        "warnings": [],
    }

    try:
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = await get_txt_records(dmarc_domain, "dmarc")

        dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

        if not dmarc_records:
            results["error"] = "No DMARC record found"
            return results

        if len(dmarc_records) > 1:
            results["error"] = "Multiple DMARC records found"
            results["record_exists"] = True
            results["valid"] = False
            return results

        dmarc_record = dmarc_records[0]
        results["record_exists"] = True
        results["record"] = dmarc_record

        # Basic syntax check
        if not re.match(r"^v=DMARC1;(\s*[a-zA-Z]+=[^;\s]+[;\s]*)*$", dmarc_record):
            results["error"] = "Invalid DMARC syntax"
            return results

        # Extract policy
        policy_match = re.search(r"p=(\w+)", dmarc_record)
        if not policy_match:
            results["error"] = "Missing required policy (p) tag"
            return results

        policy = policy_match.group(1).lower()
        results["policy"] = policy

        # Validate policy strictness
        if policy == "none":
            results["error"] = "Policy 'none' is insufficient to prevent domain abuse"
            results["valid"] = False
            return results
        elif policy not in ["quarantine", "reject"]:
            results["error"] = f"Invalid policy value: {policy}"
            results["valid"] = False
            return results

        # Extract subdomain policy
        sub_policy_match = re.search(r"sp=(\w+)", dmarc_record)
        if sub_policy_match:
            sub_policy = sub_policy_match.group(1).lower()
            results["sub_policy"] = sub_policy
            # Check if subdomain policy is also strict enough
            if sub_policy == "none":
                results["warnings"].append(
                    "Subdomain policy 'none' may allow domain abuse via subdomains"
                )
        else:
            results["sub_policy"] = results["policy"]  # Inherits from main policy

        # Extract and validate percentage
        pct_match = re.search(r"pct=(\d+)", dmarc_record)
        if pct_match:
            pct = int(pct_match.group(1))
            if not (0 <= pct <= 100):
                results["error"] = f"Invalid percentage value: {pct}"
                results["valid"] = False
                return results
            results["percentage"] = pct
            if pct < 100:
                results["warnings"].append(
                    f"Partial DMARC enforcement ({pct}%) may reduce effectiveness"
                )
        else:
            results["percentage"] = 100  # Default value

        # Set final validity based on all checks passing
        results["valid"] = (
            results["record_exists"]
            and results["policy"] in ["quarantine", "reject"]
            and not results["error"]
        )

    except Exception as e:
        results["error"] = str(e)
        logger.error(f"Error checking DMARC for {domain}: {str(e)}")

    return results


async def run(domain: str) -> Tuple[Dict, Dict]:
    """Main function to run email security checks."""
    results = {}
    state = {}

    logger.info(f"Running email security checks for {domain}")

    try:
        # Create tasks for all checks concurrently
        spf_task = asyncio.create_task(check_spf(domain))
        dkim_task = asyncio.create_task(check_dkim(domain))
        dmarc_task = asyncio.create_task(check_dmarc(domain))

        # Execute all tasks concurrently
        spf_results, dkim_results, dmarc_results = await asyncio.gather(
            spf_task, dkim_task, dmarc_task
        )

        results[domain] = {
            "spf": spf_results,
            "dkim": dkim_results,
            "dmarc": dmarc_results,
        }

        # Determine overall state
        state[domain] = {
            "SPF": "valid" if spf_results["valid"] else "not-valid",
            "DKIM": "valid" if dkim_results["valid"] else "not-valid",
            "DMARC": "valid" if dmarc_results["valid"] else "not-valid",
        }

    except Exception as e:
        logger.error(f"Error running email security checks for {domain}: {str(e)}")

    return results, state
