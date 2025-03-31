# core/utils.py

import asyncio
import html
import ipaddress
import re
from csv import DictReader
from logging import getLogger
import os
import dns
import dns.asyncresolver
from ipwhois import IPWhois
from random import random

from core.custom_logger.logger import setup_logger
from core.cache_manager import IPWhoisCache
from datetime import timedelta


setup_logger()
logger = getLogger(__name__)
_ipwhois_cache = None


class DNSResolverManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DNSResolverManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 8
        self.resolver.lifetime = 10
        self.resolver.nameservers = [
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
        ]

        self.semaphore = asyncio.Semaphore(20)

    async def resolve(self, domain, record_type, retries=3):
        backoff_factor = 1.5
        current_retry = 0

        while current_retry <= retries:
            try:
                async with self.semaphore:
                    return await self.resolver.resolve(domain, record_type)
            except dns.resolver.NoNameservers:
                # Don't retry on these specific errors
                raise
            except dns.resolver.NXDOMAIN:
                raise
            except dns.resolver.NoAnswer:
                raise
            except Exception as e:
                if current_retry >= retries:
                    raise

                wait_time = (backoff_factor**current_retry) * (1 + random())
                logger.warning(
                    f"DNS resolution error ({domain}, {record_type}): {e}. "
                    f"Retry {current_retry + 1}/{retries} in {wait_time:.2f} seconds..."
                )
                await asyncio.sleep(wait_time)
                current_retry += 1

        raise Exception(f"Failed to resolve {domain} after {retries} retries")

    async def resolve_dnssec(self, domain, record_type, raise_on_no_answer=False):
        """
        Specialized method for DNSSEC-enabled DNS resolution.
        """
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
        resolver.timeout = 5
        resolver.lifetime = 10
        resolver.use_edns(0, dns.flags.DO, 4096)

        backoff_factor = 1.5
        retries = 3
        current_retry = 0

        while current_retry <= retries:
            try:
                async with self.semaphore:
                    return await resolver.resolve(
                        domain, record_type, raise_on_no_answer=raise_on_no_answer
                    )
            except dns.resolver.NoNameservers:
                raise
            except dns.resolver.NXDOMAIN:
                raise
            except dns.resolver.NoAnswer:
                if raise_on_no_answer:
                    raise
                return None
            except Exception as e:
                if current_retry >= retries:
                    raise

                wait_time = (backoff_factor**current_retry) * (1 + random())
                logger.warning(
                    f"DNSSEC resolution error ({domain}, {record_type}): {e}. "
                    f"Retry {current_retry + 1}/{retries} in {wait_time:.2f} seconds..."
                )
                await asyncio.sleep(wait_time)
                current_retry += 1

        raise Exception(
            f"Failed to resolve DNSSEC for {domain} after {retries} retries"
        )


dns_manager = DNSResolverManager()


def is_valid_ip(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


async def resolve_nameservers(domain, ignore_cache=False):
    if is_valid_ip(domain):
        try:
            asn, prefix = await get_asn_and_prefix(domain, ignore_cache=ignore_cache)
            if asn and prefix:
                return [domain]
            return []
        except Exception as e:
            logger.error(f"Error processing IP address {domain}: {e}")
            return []

    try:
        ns_records = await dns_manager.resolve(domain, "NS")
        return [str(record).strip(".") for record in ns_records]
    except dns.resolver.NoNameservers:
        logger.warning(f"No nameservers found for domain {domain}.")
        return []
    except dns.resolver.NXDOMAIN:
        logger.warning(f"[NS] Domain {domain} does not exist.")
        return []
    except dns.resolver.NoAnswer:
        logger.info(f"No NS records for domain {domain}.")
        return []
    except Exception as e:
        logger.error(f"Failed to resolve nameservers for {domain} after retries: {e}")
        return []


async def resolve_ips(nameserver):
    """
    Resolve IP addresses for a nameserver.
    If the nameserver is already an IP, return it directly.
    """
    if is_valid_ip(nameserver):
        return [nameserver], ["No IPv6"]

    ipv4 = []
    ipv6 = ["No IPv6"]

    try:
        ipv4 = [str(record) for record in await dns_manager.resolve(nameserver, "A")]
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        logger.error(f"Error resolving IPv4 for {nameserver}: {e}")

    try:
        ipv6 = [str(record) for record in await dns_manager.resolve(nameserver, "AAAA")]
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        logger.error(f"Error resolving IPv6 for {nameserver}: {e}")

    return ipv4, ipv6


async def get_asn_and_prefix(ip, ignore_cache=False):
    """
    Retrieve the ASN and prefix for a given IP using the ipwhois library or cache.
    """
    global _ipwhois_cache

    if _ipwhois_cache is None:
        cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cache")
        _ipwhois_cache = IPWhoisCache(cache_dir, timedelta(days=30))

    cached_result = _ipwhois_cache.get_result(ip, ignore_cache)
    if cached_result:
        return cached_result

    # If not in cache or cache ignored, perform lookup
    logger.debug(f"Getting ASN and prefix for IP {ip}...")
    retries = 0
    while retries <= 3:
        try:
            obj = IPWhois(ip)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, obj.lookup_rdap)
            asn = result.get("asn").split(" ")[0]
            prefix = result.get("asn_cidr")

            _ipwhois_cache.save_result(ip, asn, prefix)

            return asn, prefix
        except Exception as e:
            logger.error(f"Error retrieving ASN and prefix for IP {ip}: {e}")
            logger.info(f"Retrying to get ASN for {ip}...")
            await asyncio.sleep(4 + 7 * random())
            retries += 1
    return None, None


async def get_mx_records(domain):
    """Retrieve MX records for the given domain."""
    try:
        answers = await dns_manager.resolve(domain, "MX")
        return sorted(r.exchange.to_text() for r in answers)
    except dns.resolver.NoAnswer:
        logger.info(f"No MX records found for domain {domain}.")
        return None
    except dns.resolver.NXDOMAIN:
        logger.warning(f"[MX] Domain {domain} does not exist.")
        return None
    except dns.resolver.Timeout:
        logger.error(f"DNS query lifetime exceeded for {domain}.")
        return None
    except Exception as e:
        logger.error(f"Error retrieving MX records for {domain}: {e}")
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

    # Path validation (added)
    file_path = os.path.abspath(os.path.normpath(file_path))
    if not os.path.isfile(file_path):
        raise Exception(f"File does not exist: {file_path}")

    try:
        if file_path.endswith(".txt"):
            with open(file_path, "r", encoding="utf-8") as file:  # Specify encoding
                for line in file:
                    line = line.strip()
                    if line:
                        # Validate domain before adding (added)
                        if await validate_hostname(line) or is_valid_ip(line):
                            domains.append(
                                {"Domain": line, "Country": "", "Institution": ""}
                            )
                        else:
                            logger.warning(f"Skipping invalid domain: {line}")

        elif file_path.endswith(".csv"):
            with open(file_path, "r", encoding="utf-8") as file:  # Specify encoding
                reader = DictReader(file)
                try:
                    if "Domain" not in reader.fieldnames:
                        raise Exception("CSV file must contain a 'Domain' column.")

                    for row in reader:
                        if row.get("Domain"):
                            domain = row["Domain"].strip()
                            # Validate domain (added)
                            if await validate_hostname(domain) or is_valid_ip(domain):
                                # Sanitize country and institution (added)
                                country = sanitize_text_field(
                                    row.get("Country", ""), max_length=100
                                )
                                institution = sanitize_text_field(
                                    row.get("Institution", ""), max_length=200
                                )

                                domain_info = {
                                    "Domain": domain,
                                    "Country": country,
                                    "Institution": institution,
                                }
                                domains.append(domain_info)
                            else:
                                logger.warning(f"Skipping invalid domain: {domain}")
                except Exception as e:
                    raise Exception(f"Error processing CSV file: {e}")

                logger.info(f"Found {len(domains)} valid domains in the CSV file")
        else:
            raise Exception(
                "Invalid file format. Only .txt and .csv files are supported."
            )

    except Exception as e:
        raise Exception(f"Error processing file: {e}")

    # Limit number of domains to prevent resource exhaustion (added)
    MAX_DOMAINS = 75
    if len(domains) > MAX_DOMAINS:
        logger.warning(
            f"Too many domains in file (limit: {MAX_DOMAINS}). Processing only the first {MAX_DOMAINS}."
        )
        domains = domains[:MAX_DOMAINS]

    try:
        if domains and sort_by:
            domains.sort(key=lambda x: (x[sort_by] == "", x[sort_by]))
            logger.debug(f"Sorted domains by {sort_by}")
    except KeyError:
        logger.warning(f"Column {sort_by} not found in the file. Skipping sorting.")

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
                    if is_valid_ip(mailserver):
                        mail_nameservers.append([mailserver])
                    else:
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


def sanitize_domain(domain):
    domain = domain.strip().strip("'\"")
    if not re.match(r"^[a-zA-Z0-9.\-_]+$", domain):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain


def sanitize_file_path(file_path):
    abs_path = os.path.abspath(os.path.normpath(file_path))
    if not os.path.isfile(abs_path):
        raise ValueError(f"File does not exist: {file_path}")
    if not (abs_path.endswith(".txt") or abs_path.endswith(".csv")):
        raise ValueError("Only .txt and .csv files are supported")
    return abs_path


def sanitize_text_field(text, max_length=100):
    """Sanitize text fields to prevent XSS and injection attacks."""
    if text is None:
        return ""
    text = text.strip()
    if len(text) > max_length:
        text = text[:max_length]
    # Convert HTML entities to prevent XSS
    text = html.escape(text)
    return text
