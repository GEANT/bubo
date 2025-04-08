import asyncio
from typing import Optional, Tuple, Dict, Any
from core.web.headers import check_security_headers
from core.tls.models import TLSCheckConfig
from core.web.models import HSTSInfo, SecurityHeadersInfo
from core.web.hsts import check_hsts


async def run_http_security_checks(
    domain: str, port: int, config: TLSCheckConfig
) -> Tuple[Optional[HSTSInfo], Optional[SecurityHeadersInfo]]:
    """Run HSTS and security headers checks if configured."""
    http_tasks = []

    if config.check_hsts:
        http_tasks.append(
            asyncio.create_task(check_hsts(domain, port, config.timeout_connect))
        )
    else:
        http_tasks.append(None)

    if config.check_security_headers:
        http_tasks.append(
            asyncio.create_task(
                check_security_headers(domain, port, config.timeout_connect)
            )
        )
    else:
        http_tasks.append(None)

    hsts_info = await http_tasks[0] if http_tasks[0] else None
    headers_info = await http_tasks[1] if http_tasks[1] else None

    return hsts_info, headers_info


def build_http_security_dicts(
    hsts_info: Optional[HSTSInfo], headers_info: Optional[SecurityHeadersInfo]
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Build dictionaries for HSTS and security headers information."""
    hsts_dict = None
    if hsts_info:
        hsts_dict = {
            "enabled": hsts_info.enabled,
            "max_age": hsts_info.max_age,
            "include_subdomains": hsts_info.include_subdomains,
            "preload": hsts_info.preload,
            "header_value": hsts_info.header_value,
        }

    headers_dict = None
    if headers_info:
        headers_dict = {
            "x_content_type_options": headers_info.content_type_options,
            "x_frame_options": headers_info.frame_options,
            "content_security_policy": headers_info.content_security_policy,
            "referrer_policy": headers_info.referrer_policy,
        }

    return hsts_dict, headers_dict
