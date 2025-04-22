import asyncio
from typing import Any
from core.web.headers import check_security_headers
from core.tls.models import TLSCheckConfig
from core.web.models import HSTSInfo, SecurityHeadersInfo
from core.web.hsts import check_hsts
from core.web.http_client import fetch_headers


async def run_http_security_checks(
    domain: str, port: int, config: TLSCheckConfig
) -> tuple[HSTSInfo | None, SecurityHeadersInfo | None]:
    """Run HSTS and security headers checks with a single HTTP request"""
    hsts_info = None
    headers_info = None

    if config.check_hsts or config.check_security_headers:
        response_headers = await fetch_headers(domain, port, config.timeout_connect)

        if response_headers:
            tasks = []

            if config.check_hsts:
                tasks.append(
                    asyncio.create_task(
                        check_hsts(
                            domain, port, config.timeout_connect, response_headers
                        )
                    )
                )

            if config.check_security_headers:
                tasks.append(
                    asyncio.create_task(
                        check_security_headers(
                            domain, port, config.timeout_connect, response_headers
                        )
                    )
                )

            results = await asyncio.gather(*tasks)

            result_index = 0
            if config.check_hsts:
                hsts_info = results[result_index]
                result_index += 1

            if config.check_security_headers:
                headers_info = results[result_index]

    return hsts_info, headers_info


def build_http_security_dicts(
    hsts_info: HSTSInfo | None, headers_info: SecurityHeadersInfo | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
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
