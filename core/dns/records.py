# core/dns/records.py


import dns.resolver

from core.logging.logger import setup_logger
from core.dns.resolver import dns_manager
from core.network.ip_tools import is_valid_ip, get_asn_and_prefix

logger = setup_logger(__name__)


async def resolve_nameservers(domain: str, ignore_cache: bool = False) -> list[str]:
    """
    Resolve nameservers for a domain or IP address.
    If a subdomain doesn't have its own NS records, it will recursively
    check parent domains until NS records are found.

    Args:
        domain: Domain name or IP address
        ignore_cache: Whether to ignore cached results for IP lookups

    Returns:
        List of nameserver strings or empty list if none found
    """
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
        # If no NS records exist for this domain and it's a subdomain,
        # try to get NS records from the parent domain
        domain_parts = domain.split(".")
        if len(domain_parts) > 2:
            parent_domain = ".".join(domain_parts[1:])
            logger.debug(
                f"No NS records for subdomain {domain}. Trying parent domain {parent_domain}."
            )
            return await resolve_nameservers(parent_domain, ignore_cache)
        else:
            logger.info(f"No NS records for domain {domain} and it's not a subdomain.")
            return []
    except Exception as e:
        logger.error(f"Failed to resolve nameservers for {domain} after retries: {e}")
        return []


async def resolve_ips(nameserver: str) -> tuple[list[str], list[str]]:
    """
    Resolve IPv4 and IPv6 addresses for a nameserver.
    If the nameserver is already an IP, return it directly.

    Args:
        nameserver: Nameserver hostname or IP address

    Returns:
        Tuple of (IPv4 addresses list, IPv6 addresses list)
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


async def get_mx_records(domain: str) -> list[str] | None:
    """
    Retrieve MX records for the given domain.

    Args:
        domain: Domain name to query MX records for

    Returns:
        Sorted list of mail servers or None if none found/error
    """
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


async def translate_server_type(server_type: str) -> str:
    """
    Translate server type codes to human-readable descriptions.

    Args:
        server_type: Server type code

    Returns:
        Human-readable server type description
    """
    translations = {
        "domain_ns": "Nameserver of Domain",
        "domain_mx": "Mail Server of Domain",
        "mailserver_ns": "Nameserver of Mail Server",
    }
    return translations.get(server_type, "Unknown Server Type")


async def process_domain(
    domain: str,
) -> tuple[list[str] | None, list[str] | None, list[list[str]] | None]:
    """
    Process a single domain to get its nameservers and mailservers.

    Args:
        domain: Domain name to process

    Returns:
        Tuple of (domain nameservers, domain mailservers, mail nameservers)
    """
    from core.validators.sanitizer import validate_hostname

    domain = domain.split("@")[1] if "@" in domain else domain
    domain_validated = await validate_hostname(domain) or is_valid_ip(domain)

    if not domain_validated:
        logger.warning(f"Domain {domain} is not valid. Skipping.")
        return None, None, None

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
