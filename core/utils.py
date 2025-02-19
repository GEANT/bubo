# core/utils.py

import asyncio
import ipaddress
import re
from csv import DictReader
from logging import getLogger

import dns
import dns.asyncresolver
from ipwhois import IPWhois

from core.custom_logger.logger import setup_logger

setup_logger()
logger = getLogger(__name__)


def is_valid_ip(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


async def resolve_nameservers(domain):
    # First check if the domain is actually an IP address
    if is_valid_ip(domain):
        try:
            asn, prefix = await get_asn_and_prefix(domain)
            if asn and prefix:
                return [domain]  # Return IP as a nameserver
            return []
        except Exception as e:
            logger.error(f"Error processing IP address {domain}: {e}")
            return []

    # If not an IP, proceed with normal NS resolution
    retries = 0
    while retries < 3:
        try:
            resolver = dns.asyncresolver.Resolver()
            ns_records = await resolver.resolve(domain, "NS")
            return [str(record).strip(".") for record in ns_records]
        except dns.resolver.NoNameservers:
            logger.warning(f"No nameservers found for domain {domain}.")
            return []
        except dns.resolver.NXDOMAIN:
            logger.warning(f"[NS] Domain {domain} does not exist.")
            return []
        except dns.resolver.NoAnswer:
            logger.warning(f"No NS records for domain {domain}.")
            return []
        except Exception as e:
            logger.warning(
                f"Error resolving nameservers: {e}. Retrying in 5 seconds..."
            )
            await asyncio.sleep(5)
            retries += 1
    return []


async def resolve_ips(nameserver):
    """
    Resolve IP addresses for a nameserver.
    If the nameserver is already an IP, return it directly.
    """
    # If the nameserver is already an IP address
    if is_valid_ip(nameserver):
        return [nameserver], ["No IPv6"]

    retries = 0
    while retries <= 3:
        try:
            resolver = dns.asyncresolver.Resolver()
            ipv4 = [str(record) for record in await resolver.resolve(nameserver, "A")]
            break
        except dns.resolver.NoAnswer:
            ipv4 = []
            break
        except Exception as e:
            logger.error(
                f"Error resolving IPv4 for {nameserver}: {e}. Retrying in 5 seconds..."
            )
            await asyncio.sleep(5)
            ipv4 = []
            retries += 1

    retries = 0
    while retries <= 3:
        try:
            ipv6 = [
                str(record) for record in await resolver.resolve(nameserver, "AAAA")
            ]
            break
        except dns.resolver.NoAnswer:
            ipv6 = ["No IPv6"]
            break
        except Exception as e:
            logger.error(
                f"Error resolving IPv6 for {nameserver}: {e}. Retrying in 5 seconds..."
            )
            ipv6 = ["No IPv6"]
            await asyncio.sleep(5)
            retries += 1

    return ipv4, ipv6


async def get_asn_and_prefix(ip):
    """
    Retrieve the ASN and prefix for a given IP using the ipwhois library.

    :param ip: The IPv4 address to query.
    :return: A tuple (ASN, prefix) or (None, None) if not found.
    """
    retries = 0
    while retries <= 3:
        try:
            obj = IPWhois(ip)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, obj.lookup_rdap)
            asn = result.get("asn").split(" ")[0]
            prefix = result.get("asn_cidr")
            return asn, prefix
        except Exception as e:
            logger.error(f"Error retrieving ASN and prefix for IP {ip}: {e}")
            logger.info(f"Retrying to get ASN for {ip}...")
            await asyncio.sleep(2)
            retries += 1
    return None, None


async def get_mx_records(domain):
    """Retrieve MX records for the given domain."""
    retries = 0
    while retries < 3:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            return sorted(r.exchange.to_text() for r in answers)
        except dns.resolver.NoAnswer:
            logger.info(f"No MX records found for domain {domain}.")
            return None

        # Handle the DNS query name does not exist
        except dns.resolver.NXDOMAIN:
            logger.warning(f"[MX] Domain {domain} does not exist.")
            return None

        # Handle lifetime expired
        except dns.resolver.Timeout:
            logger.error(
                f"DNS query lifetime exceeded for {domain}. Retrying in 5 seconds..."
            )
            await asyncio.sleep(5)
            retries += 1

        except Exception as e:
            logger.error(f"Error retrieving MX records for {domain}: {e}")
            await asyncio.sleep(5)
            retries += 1

    return None


async def validate_hostname(hostname):
    if not hostname or len(hostname) > 255:
        return False

    if hostname[-1] == ".":
        hostname = hostname[:-1]

    pattern = r"^(?!-)[A-Za-z0-9\u4e00-\u9fa5-]+(?<!-)(?:\.(?!-)[A-Za-z0-9\u4e00-\u9fa5-]+(?<!-))*\.(?!-)[A-Za-z\u4e00-\u9fa5]{2,}(?<!-)$"
    return bool(
        re.match(pattern, hostname)
        and all(len(part) <= 63 for part in hostname.split("."))
    )


async def translate_server_type(server_type):
    if server_type == "domain_ns":
        return "Nameserver of Domain"
    elif server_type == "domain_mx":
        return "Mail Server of Domain"
    elif server_type == "mailserver_ns":
        return "Nameserver of Mail Server"
    else:
        return "Unknown Server Type"


async def process_file(file_path, sort_by="Country"):
    domains = []

    try:
        if file_path.endswith(".txt"):
            with open(file_path, "r") as file:
                domains = [
                    {"Domain": line.strip(), "Country": "", "Institution": ""}
                    for line in file
                    if line.strip()
                ]
        elif file_path.endswith(".csv"):
            with open(file_path, "r") as file:
                reader = DictReader(file)
                if "Domain" not in reader.fieldnames:
                    logger.warning("CSV file must contain a 'Domain' column.")
                    return []

                for row in reader:
                    if row["Domain"]:  # Only process rows with non-empty Domain
                        domain_info = {
                            "Domain": row["Domain"],
                            "Country": row.get(
                                "Country", ""
                            ),  # Use get() with default empty string
                            "Institution": row.get("Institution", ""),
                        }
                        domains.append(domain_info)

                logger.info(f"Found {len(domains)} domains in the CSV file")

        else:
            raise Exception(
                "Invalid file format. Only .txt and .csv files are supported."
            )

        # Sort the domains list if it's not empty and sort_by field exists
        if domains and sort_by:
            # Sort with None/empty values at the end
            domains.sort(key=lambda x: (x[sort_by] == "", x[sort_by]))
            logger.info(f"Sorted domains by {sort_by}")

    except Exception as e:
        raise Exception(f"Error processing file: {e}")

    return domains


async def process_domain(domain):
    """
    Process a single domain to validate RPKI for its nameservers and mailservers.
    """
    domain = domain.split("@")[1] if "@" in domain else domain
    domain_validated = await validate_hostname(domain) or is_valid_ip(domain)

    if domain_validated:
        try:
            domain_nameservers = await resolve_nameservers(domain)
        except Exception as e:
            logger.error(f"Error processing nameservers for {domain}: {e}")
            domain_nameservers = None

        try:
            domain_mailservers = await get_mx_records(domain)
            if domain_mailservers:
                domain_mailservers = [ms.rstrip(".") for ms in domain_mailservers]
        except Exception as e:
            logger.error(f"Error processing mailservers for {domain}: {e}")
            domain_mailservers = None

        mail_nameservers = []
        try:
            if domain_mailservers:
                for mailserver in domain_mailservers:
                    # Check if mailserver is an IP address
                    if is_valid_ip(mailserver):
                        mail_nameservers.append([mailserver])
                    else:
                        # Get the parent domain of the mailserver
                        mail_domain = ".".join(mailserver.split(".")[1:])
                        ns_list = await resolve_nameservers(mail_domain)
                        mail_nameservers.append(ns_list if ns_list else [])

                # If all lists in mail_nameservers are empty, set it to None
                if all(not ns for ns in mail_nameservers):
                    mail_nameservers = None
            else:
                mail_nameservers = None

        except Exception as e:
            logger.error(f"Error processing mail nameservers for {domain}: {e}")
            mail_nameservers = None

        return domain_nameservers, domain_mailservers, mail_nameservers
    else:
        logger.warning(f"Domain {domain} is not valid. Skipping.")
        return None, None, None
