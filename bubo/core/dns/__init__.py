from core.dns.records import (
    get_mx_records,
    process_domain,
    resolve_ips,
    resolve_nameservers,
    translate_server_type,
)
from core.dns.resolver import DNSResolverManager, dns_manager

__all__ = [
    "dns_manager",
    "DNSResolverManager",
    "resolve_nameservers",
    "resolve_ips",
    "get_mx_records",
    "translate_server_type",
    "process_domain",
]
