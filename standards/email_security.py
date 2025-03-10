import asyncio
import dns.asyncresolver
import dns.exception
from logging import getLogger
from typing import Dict, List, Tuple, Optional
import re
from core.utils import dns_manager
from core.custom_logger.logger import setup_logger
from standards.spf import check_spf


setup_logger()
logger = getLogger(__name__)
COMMON_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "dkim",
    "mail",
    "s1",
    "s2",
    "google",
    "k1",
    "k2",
    "m1",
    "m2",
    "mail",
    "email",
    "dkim",
    "smtp",
    "domainkey",
]


async def get_txt_records(domain: str, record_type: str = None) -> List[str]:
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


async def check_dkim_selector(domain: str, selector: str) -> Optional[Dict]:
    dkim_domain = f"{selector}._domainkey.{domain}"
    txt_records = await get_txt_records(dkim_domain, "dkim")

    for record in txt_records:
        if "v=DKIM1" in record:
            return {"record": record, "valid": True, "selector": selector}
    return None


async def check_dkim(domain: str) -> Dict:
    results = {"selectors_found": [], "records": {}, "valid": False, "error": None}

    try:
        tasks = [
            check_dkim_selector(domain, selector) for selector in COMMON_DKIM_SELECTORS
        ]
        selector_results = await asyncio.gather(*tasks)
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
        dmarc_records = []

        try:
            answers = await dns_manager.resolve(dmarc_domain, "TXT")
            for record in answers:
                try:
                    decoded_strings = []
                    for string in record.strings:
                        if isinstance(string, bytes):
                            decoded_strings.append(string.decode("utf-8"))
                        else:
                            decoded_strings.append(string)

                    txt = "".join(decoded_strings)
                    if txt.startswith("v=DMARC1"):
                        dmarc_records.append(txt)
                except (UnicodeDecodeError, AttributeError):
                    logger.error(f"Error decoding DMARC record for {dmarc_domain}")
                    continue
        except dns.resolver.NXDOMAIN:
            logger.debug(f"No DMARC record found for {dmarc_domain} (NXDOMAIN)")
        except dns.resolver.NoAnswer:
            logger.debug(f"No DMARC record found for {dmarc_domain} (NoAnswer)")
        except asyncio.TimeoutError:
            logger.error(f"Timeout when fetching DMARC record for {dmarc_domain}")
            results["error"] = f"DNS lookup timeout for {dmarc_domain}"
            return results
        except Exception as e:
            logger.debug(f"Error fetching DMARC records for {dmarc_domain}: {str(e)}")
            results["error"] = f"Error fetching DMARC records: {str(e)}"
            return results

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
            results["error"] = (
                "Policy 'none' is insufficient to prevent domain abuse. It should be 'reject' or 'quarantine' to be effective and strict."
            )
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
    results = {}
    state = {}

    logger.info(f"Running email security checks for {domain}")

    try:
        spf_task = asyncio.create_task(check_spf(domain))
        dkim_task = asyncio.create_task(check_dkim(domain))
        dmarc_task = asyncio.create_task(check_dmarc(domain))

        spf_results, dkim_results, dmarc_results = await asyncio.gather(
            spf_task, dkim_task, dmarc_task
        )

        results[domain] = {
            "spf": spf_results,
            "dkim": dkim_results,
            "dmarc": dmarc_results,
        }

        state[domain] = {
            "SPF": "valid" if spf_results["valid"] else "not-valid",
            "DKIM": "valid" if dkim_results["valid"] else "not-valid",
            "DMARC": "valid" if dmarc_results["valid"] else "not-valid",
        }

    except Exception as e:
        logger.error(f"Error running email security checks for {domain}: {str(e)}")

    return results, state
