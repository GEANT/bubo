# standards/rpki.py

import argparse
import asyncio

import aiohttp

from core.logging.logger import setup_logger
from core.dns.records import process_domain, resolve_ips, translate_server_type
from core.network.ip_tools import get_asn_and_prefix

logger = setup_logger(__name__)


async def validate_rpki(asn, prefix):
    """
    Validate RPKI status for the ASN and prefix using the RPKI validation API.

    :param asn: The ASN number.
    :param prefix: The IP prefix in CIDR notation.
    :return: Validation result as a dictionary.
    """
    try:
        url = f"http://localhost:8323/api/v1/validity/{asn}/{prefix}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                response.raise_for_status()
                return await response.json()
    except aiohttp.ClientError as e:
        logger.error(f"Validating RPKI for ASN {asn} and Prefix {prefix} failed: {e}")
        return None


async def process_server(server, domain, results, stype):
    """
    Process a server (e.g., nameserver or mail server) to validate RPKI for its associated IPs.
    """
    # logger.info(f"Processing {stype}: {server}")
    ipv4, ipv6 = await resolve_ips(server)

    # Initialize server entry with "No IPv4 addresses found" by default
    if domain not in results:
        results[domain] = {}
    if stype not in results[domain]:
        results[domain][stype] = {}

    # If no IPv4 addresses found, set descriptive message
    if not ipv4:
        results[domain][stype][server] = {
            "ipv6": ipv6 if ipv6 else ["No IPv6"],
            "message": "No IPv4 addresses found",
        }
        return

    server_results = {"ipv6": ipv6 if ipv6 else ["No IPv6"], "prefix": {}}

    for ip in ipv4:
        asn, prefix = await get_asn_and_prefix(ip)
        if not asn or not prefix:
            logger.warning(f"Unable to retrieve ASN and Prefix for IP {ip}.")
            continue

        else:
            validation_result = await validate_rpki(asn, prefix)
            if not validation_result:
                logger.debug(
                    f"Unable to validate RPKI for IP {ip}, ASN {asn}, and Prefix {prefix}."
                )
                continue

            rpki_state = validation_result["validated_route"]["validity"][
                "state"
            ].capitalize()

            # Add or update the prefix entry
            if prefix not in server_results["prefix"]:
                server_results["prefix"][prefix] = {
                    "rpki_state": rpki_state,
                    "ipv4": [ip],
                    "asn": asn,
                }
            else:
                if ip not in server_results["prefix"][prefix]["ipv4"]:
                    server_results["prefix"][prefix]["ipv4"].append(ip)

            logger.debug(
                f"RPKI Validation Result for {server} (ASN: {asn}, Prefix: {prefix}): {rpki_state}"
            )

    # Only add server results if we found any prefix information
    if server_results["prefix"]:
        results[domain][stype][server] = server_results
    else:
        results[domain][stype][server] = {
            "ipv6": ipv6 if ipv6 else ["No IPv6"],
            "message": "No valid RPKI information found",
        }


async def type_validity(domain_results):
    """
    Return valid if all records in each type have rpki_state as valid.
    Enhanced to handle missing or invalid data better.
    """
    rpki_state = {}

    for domain, types in domain_results.items():
        domain_state = {}

        for type_, servers in types.items():
            # If no servers found
            if not servers:
                domain_state[await translate_server_type(type_)] = None
                continue

            # Check if any server has valid RPKI records
            has_valid_records = False
            all_valid = True
            has_servers = False

            for server_data in servers.values():
                # Check if server has prefix data
                if "prefix" in server_data:
                    has_servers = True
                    prefix_states = [
                        prefix_data["rpki_state"].lower() == "valid"
                        for prefix_data in server_data["prefix"].values()
                    ]

                    if prefix_states:  # If any prefix states exist
                        if any(prefix_states):
                            has_valid_records = True
                        if not all(prefix_states):
                            all_valid = False

            # Determine final state
            if not has_servers:
                state = None
            elif not has_valid_records:
                state = "not-valid"
            elif all_valid:
                state = "valid"
            else:
                state = "partially-valid"

            domain_state[await translate_server_type(type_)] = state

        rpki_state[domain] = domain_state

    return rpki_state


async def rpki_process_domain(domain):
    """
    Process a single domain to validate RPKI for its nameservers and mailservers.
    """
    results = {}
    domain_nameservers, domain_mailservers, mail_nameservers = await process_domain(
        domain
    )

    if domain_nameservers:
        nameserver_tasks = [
            process_server(nameserver, domain, results, "domain_ns")
            for nameserver in domain_nameservers
        ]
    else:
        nameserver_tasks = []

    if domain_mailservers:
        mailservers_tasks = [
            process_server(mailserver, domain, results, "domain_mx")
            for mailserver in domain_mailservers
        ]
    else:
        mailservers_tasks = []

    if mail_nameservers:
        mail_nameservers_tasks = [
            process_server(nameserver, domain, results, "mailserver_ns")
            for sublist in mail_nameservers
            for nameserver in sublist
        ]
    else:
        mail_nameservers_tasks = []

    tasks = [*nameserver_tasks, *mailservers_tasks, *mail_nameservers_tasks]
    await asyncio.gather(*tasks)

    if results:
        return results
    else:
        logger.debug(f"No results found for domain {domain}.")
        return {}


async def process_single_mode(domain):
    result = await rpki_process_domain(domain)
    if result:
        logger.debug(f"Found results for {domain}")
        rpki_state = await type_validity(result)
        return result, rpki_state
    else:
        logger.debug(f"No RPKI results found for {domain}.")
        return {}, {}


# ----------------------------------------------------------------
async def process_batch_mode(domains):
    """
    Process a batch of domains from a .txt or .csv file.
    """
    batch_results = {}
    tasks = [rpki_process_domain(domain) for domain in domains]
    domain_results_list = await asyncio.gather(*tasks)

    for domain_results in domain_results_list:
        if isinstance(domain_results, dict):  # Filter successful results
            batch_results.update(domain_results)
        elif isinstance(domain_results, Exception):
            logger.error(f"Error in processing: {domain_results}")

    if batch_results:
        rpki_state = await type_validity(batch_results)
        return batch_results, rpki_state

    else:
        logger.info("No results to generate the rpki report.")
        return {}, {}


async def run(domain, check_mode, domain_ns=None, domain_mx=None, mail_ns=None):
    """
    Run RPKI validation with pre-processed server information.
    """
    results = {domain: {}}  # Initialize with just the domain

    logger.info(f"Processing RPKI for domain: {domain}")
    # Process domain nameservers
    if domain_ns:
        nameserver_tasks = [
            process_server(nameserver, domain, results, "domain_ns")
            for nameserver in domain_ns
        ]
        await asyncio.gather(*nameserver_tasks)
        # Only keep domain_ns if it has data
        if not results[domain].get("domain_ns"):
            del results[domain]["domain_ns"]

    # Process mail servers
    if domain_mx:
        mailservers_tasks = [
            process_server(mailserver, domain, results, "domain_mx")
            for mailserver in domain_mx
        ]
        await asyncio.gather(*mailservers_tasks)
        # Only keep domain_mx if it has data
        if not results[domain].get("domain_mx"):
            del results[domain]["domain_mx"]

    # Process mail nameservers
    if mail_ns:
        mail_nameservers_tasks = [
            process_server(nameserver, domain, results, "mailserver_ns")
            for sublist in mail_ns
            for nameserver in sublist
        ]
        await asyncio.gather(*mail_nameservers_tasks)
        # Only keep mailserver_ns if it has data
        if not results[domain].get("mailserver_ns"):
            del results[domain]["mailserver_ns"]

    rpki_state = await type_validity(results)

    # If no results were found for the domain, return empty dicts
    if not results[domain]:
        return {}, {}

    return results, rpki_state


async def main():
    parser = argparse.ArgumentParser(description="Check/Validate RPKI for domains.")
    parser.add_argument("--single", type=str, help="Single domain name to check.")
    parser.add_argument(
        "--batch", type=str, help="Path to a file (txt/csv) containing domains."
    )
    args = parser.parse_args()

    if args.single:
        await process_single_mode(args.single)

    elif args.batch:
        await process_batch_mode(args.batch)
    else:
        logger.error(
            "Invalid input. Please provide [--single DOMAIN_NAME ] or [--batch FILE_PATH]"
        )


if __name__ == "__main__":
    asyncio.run(main())
