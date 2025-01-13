# standards/dane.py

import asyncio
import os
from logging import getLogger
from typing import List, Dict, Tuple

import aiofiles
import dns.asyncresolver
from dns.exception import DNSException

from core.custom_logger.logger import setup_logger

setup_logger()
logger = getLogger(__name__)


async def check_tlsa_record(domain: str, port: int) -> List[str]:
    """
    Check for TLSA records with specified port.
    
    Args:
        domain: Domain to check
        port: Port number (25 for SMTP, 443 for HTTPS)
    Returns:
        List of TLSA records
    """
    try:
        tlsa_query = f"_{port}._tcp.{domain}"
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 10  # Set timeout for DNS queries
        resolver.lifetime = 10  # Set maximum time for resolution

        answers = await resolver.resolve(tlsa_query, "TLSA")
        logger.info(f"TLSA records found for {domain} on port {port}")
        return [answer.to_text() for answer in answers]
    except DNSException as e:
        logger.info(f"No TLSA records found for {domain} on port {port}: {e}")
        return []
    except Exception as e:
        logger.error(f"Error checking TLSA records for {domain} on port {port}: {e}")
        return []


async def validate_tlsa_hash(domain: str, port: int, tlsa_record: str, server: str) -> bool:
    """
    Validate TLSA hash using OpenSSL.
    """
    try:
        command = [
            "openssl", "s_client",
            "-starttls", "smtp" if port == 25 else "notls",
            "-connect", f"{server}:{port}",
            "-dane_tlsa_domain", server.rstrip('.'),
            "-dane_tlsa_rrdata", tlsa_record
        ]
        retries = 0
        while retries <= 3:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(input=b''), timeout=20)
                output = stdout.decode()

                # Save output
                base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
                output_dir = os.path.join(base_dir, "results", domain)
                os.makedirs(output_dir, exist_ok=True)

                async with aiofiles.open(f"{output_dir}/dane_output_{server}_{port}.txt", "w") as f:
                    await f.write(f"Command: {' '.join(command)}\nOutput:\n{output}")

                return "Verification: OK" in output

            except asyncio.TimeoutError:
                logger.error(f"Timeout validating TLSA for {server}:{port}. Retrying in 6 seconds...")
                if proc:
                    proc.kill()
                await asyncio.sleep(6)
                retries += 1

        return False

    except Exception as e:
        logger.error(f"Error validating TLSA for {server}:{port}: {e}")
        return False


async def process_servers(domain: str, servers: List[str], port: int, server_type: str) -> Dict:
    """
    Process a list of servers for TLSA records and validation.
    Returns results for all servers, including those without TLSA records.
    """
    results = {}

    if not servers:
        return results

    for server in servers:
        server = server.rstrip('.')
        tlsa_records = await check_tlsa_record(server, port)

        if tlsa_records:
            validation_tasks = [validate_tlsa_hash(domain, port, record, server)
                                for record in tlsa_records]
            validation_results = await asyncio.gather(*validation_tasks)

            results[server] = {
                "tlsa_records": [
                    {"record": record, "valid": valid}
                    for record, valid in zip(tlsa_records, validation_results)
                ],
                "validation": any(validation_results)
            }
        else:
            # Include servers without TLSA records
            results[server] = {
                "tlsa_records": [],
                "validation": False
            }

    return results


def get_state_value(results):
    """
    Determine state value based on TLSA validation results.

    Args:
        results: Dictionary containing TLSA validation results for servers
    Returns:
        str: State value indicating TLSA status
    """
    if not results:  # If results is empty (no servers or empty dict)
        return "No TLSA records found"
    # Check if any server has valid TLSA records
    return "valid" if any(srv["validation"] for srv in results.values()) else "not-valid"


async def run(domain: str, check_mode: str, domain_ns: List[str], domain_mx: List[str], mail_ns: List[str]) -> Tuple[
    Dict, Dict]:
    try:
        results = {domain: {}}

        # Process different server types concurrently
        ns_task = process_servers(domain, domain_ns, 443, "domain_ns")
        mx_task = process_servers(domain, domain_mx, 25, "domain_mx")
        mail_ns_task = process_servers(domain, [ns for sublist in mail_ns for ns in sublist] if mail_ns else [], 443,
                                       "mailserver_ns")

        ns_results, mx_results, mail_ns_results = await asyncio.gather(ns_task, mx_task, mail_ns_task)

        # Always include all server types in results
        results[domain]["domain_ns"] = ns_results
        results[domain]["domain_mx"] = mx_results
        results[domain]["mailserver_ns"] = mail_ns_results

        # Set state based on validation results with more detailed status
        state = {domain: {
            "Mail Server of Domain": get_state_value(mx_results),
            "Nameserver of Domain": get_state_value(ns_results),
            "Nameserver of Mail Server": get_state_value(mail_ns_results)
        }}

        return results, state

    except Exception as e:
        logger.error(f"Error in DANE validation for {domain}: {e}")
        return {domain: {
            "domain_ns": {},
            "domain_mx": {},
            "mailserver_ns": {}
        }}, {domain: {
            "Mail Server of Domain": "not-valid",
            "Nameserver of Domain": "not-valid",
            "Nameserver of Mail Server": "not-valid"
        }}
