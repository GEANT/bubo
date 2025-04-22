# standards/dane.py

import asyncio
import dns.asyncresolver
from random import random

from core.logging.logger import setup_logger
from core.dns.resolver import dns_manager


logger = setup_logger(__name__)


async def check_tlsa_record(domain: str, port: int) -> list[str]:
    """
    Check for TLSA records with a specified port.

    Args:
        domain: Domain to check
        port: Port number (25 for SMTP, 443 for HTTPS)
    Returns:
        List of TLSA records
    """
    try:
        tlsa_query = f"_{port}._tcp.{domain}"

        answers = await dns_manager.resolve(tlsa_query, "TLSA")
        logger.debug(f"TLSA records found for {domain} on port {port}")
        return [answer.to_text() for answer in answers]
    except dns.exception.DNSException as e:
        logger.debug(f"No TLSA records found for {domain} on port {port}: {e}")
        return []
    except Exception as e:
        logger.error(f"Error checking TLSA records for {domain} on port {port}: {e}")
        return []


async def validate_tlsa_hash(
    domain: str, port: int, tlsa_record: str, server: str
) -> bool:
    """
    Validate TLSA hash using OpenSSL.
    """
    try:
        command = [
            "openssl",
            "s_client",
            "-starttls",
            "smtp" if port == 25 else "notls",
            "-connect",
            f"{server}:{port}",
            "-dane_tlsa_domain",
            server.rstrip("."),
            "-dane_tlsa_rrdata",
            tlsa_record,
        ]
        retries = 0
        while retries <= 1:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=b""), timeout=20
                )
                output = stdout.decode()

                return "Verification: OK" in output

            except asyncio.TimeoutError:
                logger.warning(
                    f"Timeout validating TLSA for {server}:{port}. Retrying in 6 seconds..."
                )
                if proc:
                    proc.kill()
                await asyncio.sleep(1 + 7 * random())
                retries += 1

        return False

    except Exception as e:
        logger.error(f"Error validating TLSA for {server}:{port}: {e}")
        return False


async def process_servers(
    domain: str, servers: list[str], port: int, server_type: str
) -> dict:
    """
    Process a list of servers for TLSA records and validation.
    Returns results for all servers, including those without TLSA records.
    """
    results = {}

    if not servers:
        return results

    for server in servers:
        server = server.rstrip(".")
        tlsa_records = await check_tlsa_record(server, port)

        if tlsa_records:
            validation_tasks = [
                validate_tlsa_hash(domain, port, record, server)
                for record in tlsa_records
            ]
            validation_results = await asyncio.gather(*validation_tasks)

            results[server] = {
                "tlsa_records": [
                    {"record": record, "valid": valid}
                    for record, valid in zip(tlsa_records, validation_results)
                ],
                "validation": any(validation_results),
            }
        else:
            # Include servers without TLSA records
            results[server] = {"tlsa_records": [], "validation": False}

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
    return (
        "valid" if any(srv["validation"] for srv in results.values()) else "not-valid"
    )


async def run(
    domain: str,
    check_mode: str,
    domain_ns: list[str],
    domain_mx: list[str],
    mail_ns: list[str],
) -> tuple[dict, dict]:
    logger.info(f"Processing DANE for domain: {domain}")

    try:
        results = {domain: {}}
        state = {domain: {}}

        tasks = {}

        if domain_ns:
            tasks["domain_ns"] = process_servers(domain, domain_ns, 443, "domain_ns")

        if domain_mx:
            tasks["domain_mx"] = process_servers(domain, domain_mx, 25, "domain_mx")

        mail_servers = [ns for sublist in mail_ns for ns in sublist] if mail_ns else []
        if mail_servers:
            tasks["mailserver_ns"] = process_servers(
                domain, mail_servers, 443, "mailserver_ns"
            )

        task_results = {}
        for task_name, task in tasks.items():
            task_results[task_name] = await task

        for server_type, result in task_results.items():
            if result:
                results[domain][server_type] = result
                state_label = {
                    "domain_ns": "Nameserver of Domain",
                    "domain_mx": "Mail Server of Domain",
                    "mailserver_ns": "Nameserver of Mail Server",
                }.get(server_type)

                if state_label:
                    state[domain][state_label] = get_state_value(result)

        return results, state

    except Exception as e:
        logger.error(f"Error in DANE validation for {domain}: {e}")
        error_state = {domain: {}}
        for server_type in results.get(domain, {}):
            if server_type == "domain_ns":
                error_state[domain]["Nameserver of Domain"] = "not-valid"
            elif server_type == "domain_mx":
                error_state[domain]["Mail Server of Domain"] = "not-valid"
            elif server_type == "mailserver_ns":
                error_state[domain]["Nameserver of Mail Server"] = "not-valid"

        return results, error_state
