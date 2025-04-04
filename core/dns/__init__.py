from core.dns.resolver import dns_manager, DNSResolverManager
from core.dns.records import (
    resolve_nameservers,
    resolve_ips,
    get_mx_records,
    translate_server_type,
    process_domain,
)

__all__ = [
    "dns_manager",
    "DNSResolverManager",
    "resolve_nameservers",
    "resolve_ips",
    "get_mx_records",
    "translate_server_type",
    "process_domain",
]
