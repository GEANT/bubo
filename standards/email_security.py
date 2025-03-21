import asyncio
import dns.asyncresolver
import dns.exception
from logging import getLogger
from typing import Dict, List, Tuple, Optional
import re
import base64
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
    """
    Fetch TXT records for a domain and properly reassemble multi-part records.
    Returns:
        List of complete TXT records as strings
    """
    try:
        answers = await dns_manager.resolve(domain, "TXT")

        complete_records = []
        for record in answers:
            segments = []
            for segment in record.strings:
                if isinstance(segment, bytes):
                    segments.append(segment.decode("utf-8"))
                else:
                    segments.append(segment)

            complete_record = "".join(segments)
            complete_records.append(complete_record)

        return complete_records
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


def extract_dkim_key_info(dkim_record: str) -> Dict:
    """
    Extract key information from a DKIM record and evaluate its strength based on best practices.

    Args:
        dkim_record: The DKIM TXT record

    Returns:
        Dictionary with key type, length, and strength assessment
    """
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    key_info = {
        "key_type": None,
        "key_length": None,
        "strength": None,
        "strength_description": None,
        "error": None,
    }

    try:
        k_match = re.search(r"k=([a-zA-Z0-9-]+)", dkim_record)
        key_type = k_match.group(1).lower() if k_match else "rsa"
        key_info["key_type"] = key_type

        p_match = re.search(r"p=([a-zA-Z0-9/+=]+)", dkim_record)
        if not p_match or p_match.group(1) == "":
            key_info["error"] = "No public key found in DKIM record"
            return key_info

        public_key_b64 = p_match.group(1)

        if key_type == "rsa":
            try:
                key_bytes = base64.b64decode(public_key_b64)
                public_key = load_der_public_key(key_bytes)
                key_length = public_key.key_size
                key_info["key_length"] = key_length

                if key_length <= 512:
                    key_info["strength"] = "vulnerable"
                    key_info["strength_description"] = (
                        "RSA-512 is highly vulnerable. Can be cracked for less than $8 in the cloud."
                    )
                elif key_length <= 1024:
                    key_info["strength"] = "acceptable"
                    key_info["strength_description"] = (
                        f"RSA-{key_length} is considered acceptable by modern standards. But it is recommended to use RSA-2048."
                    )
                elif key_length == 2048:
                    key_info["strength"] = "strong"
                    key_info["strength_description"] = (
                        "RSA-2048 is the current recommended standard for DKIM keys."
                    )
                else:
                    key_info["strength"] = "future-proof"
                    key_info["strength_description"] = (
                        f"RSA-{key_length} exceeds current recommendations and provides future-proofing."
                    )

            except Exception as e:
                # If cryptography library fails, try manual ASN.1 parsing as fallback
                try:
                    key_bytes = base64.b64decode(public_key_b64)
                    modulus_size_bytes = len(key_bytes) - 20
                    key_length = modulus_size_bytes * 8
                    key_info["key_length"] = key_length
                    key_info["strength"] = "unknown"
                    key_info["strength_description"] = (
                        f"RSA key length estimation: {key_length} bits (approximate)"
                    )
                except Exception:
                    key_info["error"] = f"Failed to parse RSA key: {str(e)}"

        elif key_type == "ed25519":
            key_info["key_type"] = "Ed25519"
            key_info["key_length"] = 256  # Ed25519 is always 256 bits
            key_info["strength"] = "future-proof"
            key_info["strength_description"] = (
                "Ed25519 (256-bit) offers strong security with better performance than RSA."
            )
        else:
            key_info["error"] = f"Unsupported key type: {key_type}"

    except Exception as e:
        key_info["error"] = f"Error extracting key info: {str(e)}"

    return key_info


async def check_dkim_selector(domain: str, selector: str) -> Optional[Dict]:
    dkim_domain = f"{selector}._domainkey.{domain}"
    txt_records = await get_txt_records(dkim_domain, "dkim")

    for record in txt_records:
        if "v=DKIM1" in record:
            key_info = extract_dkim_key_info(record)
            return {
                "record": record,
                "valid": True,
                "selector": selector,
                "key_info": key_info,
            }
    return None


async def check_dkim(domain: str) -> Dict:
    results = {
        "selectors_found": [],
        "records": {},
        "valid": False,
        "key_info": {},
        "overall_key_strength": None,
        "error": None,
    }

    try:
        tasks = [
            check_dkim_selector(domain, selector) for selector in COMMON_DKIM_SELECTORS
        ]
        selector_results = await asyncio.gather(*tasks)
        valid_records = [r for r in selector_results if r is not None]

        if valid_records:
            results["selectors_found"] = [r["selector"] for r in valid_records]
            results["records"] = {
                r["selector"]: {
                    "record": r["record"],
                    "valid": r["valid"],
                    "key_info": r["key_info"],
                }
                for r in valid_records
            }

            for r in valid_records:
                if "key_info" in r and r["key_info"]:
                    selector = r["selector"]
                    results["key_info"][selector] = r["key_info"]

            strength_levels = {
                "vulnerable": 0,
                "acceptable": 1,
                "strong": 2,
                "future-proof": 3,
            }

            min_strength = "strong"
            min_strength_level = 3

            for selector, info in results["key_info"].items():
                if "strength" in info and info["strength"]:
                    current_level = strength_levels.get(info["strength"], 3)
                    if current_level < min_strength_level:
                        min_strength_level = current_level
                        min_strength = info["strength"]

            results["overall_key_strength"] = min_strength
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
        "rua": None,
        "ruf": None,
        "error": None,
        "warnings": [],
    }

    try:
        dmarc_domain = f"_dmarc.{domain}"

        txt_records = await get_txt_records(dmarc_domain, "dmarc")

        dmarc_records = [
            record for record in txt_records if record.startswith("v=DMARC1")
        ]

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

        if not re.match(r"^v=DMARC1;(\s*[a-zA-Z]+=[^;\s]+[;\s]*)*$", dmarc_record):
            results["error"] = "Invalid DMARC syntax"
            return results

        policy_match = re.search(r"p=(\w+)", dmarc_record)
        if not policy_match:
            results["error"] = "Missing required policy (p) tag"
            return results

        policy = policy_match.group(1).lower()
        results["policy"] = policy

        rua_match = re.search(r"rua=([^;\s]+)", dmarc_record)
        if rua_match:
            results["rua"] = rua_match.group(1)

        ruf_match = re.search(r"ruf=([^;\s]+)", dmarc_record)
        if ruf_match:
            results["ruf"] = ruf_match.group(1)

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

        sub_policy_match = re.search(r"sp=(\w+)", dmarc_record)
        if sub_policy_match:
            sub_policy = sub_policy_match.group(1).lower()
            results["sub_policy"] = sub_policy
            if sub_policy == "none":
                results["warnings"].append(
                    "Subdomain policy 'none' may allow domain abuse via subdomains"
                )
        else:
            results["sub_policy"] = results["policy"]

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
            results["percentage"] = 100

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

        dkim_key_status = "not-valid"
        if dkim_results["valid"]:
            strength = dkim_results.get("overall_key_strength")
            if strength == "vulnerable":
                dkim_key_status = "critically-weak-key"
            elif strength in ["acceptable", "strong", "future-proof"]:
                dkim_key_status = "valid"

        state[domain] = {
            "SPF": "valid" if spf_results["valid"] else "not-valid",
            "DKIM": dkim_key_status,
            "DMARC": "valid" if dmarc_results["valid"] else "not-valid",
        }

    except Exception as e:
        logger.error(f"Error running email security checks for {domain}: {str(e)}")

    return results, state
