import asyncio
from dataclasses import dataclass
from typing import Any

import aiohttp

from bubo.core.dns.records import resolve_ips, translate_server_type
from bubo.core.logging.logger import setup_logger
from bubo.core.network.ip_tools import get_asn_and_prefix

logger = setup_logger(__name__)


@dataclass
class ValidatorState:
    """State management for RPKI validator"""

    is_down: bool = False
    timeout_count: int = 0
    timeout_threshold: int = 3

    def reset_timeouts(self) -> None:
        """Reset timeout counter"""
        self.timeout_count = 0

    def increment_timeout(self) -> None:
        """Increment timeout counter and check if threshold exceeded"""
        self.timeout_count += 1
        if self.timeout_count >= self.timeout_threshold:
            self.is_down = True

    def mark_down(self) -> None:
        """Mark validator as down"""
        self.is_down = True


class RPKIValidator:
    """RPKI validation service with encapsulated state"""

    def __init__(self, routinator_url: str, timeout_threshold: int = 3):
        self.routinator_url = routinator_url
        self.state = ValidatorState(timeout_threshold=timeout_threshold)

    async def validate_rpki(self, asn: str, prefix: str) -> dict[str, Any] | None:
        """
        Validate RPKI status for the ASN and prefix using Routinator API.
        Returns None if the validator is down or validation fails.
        """
        if self.state.is_down:
            return None

        try:
            url = f"{self.routinator_url}/api/v1/validity/{asn}/{prefix}"
            async with (
                aiohttp.ClientSession() as session,
                session.get(url, timeout=10) as response,
            ):
                response.raise_for_status()
                self.state.reset_timeouts()
                return await response.json()

        except aiohttp.ClientConnectorError as e:
            if not self.state.is_down:
                logger.error(f"RPKI validator is unavailable: {e}")
                self.state.mark_down()
            return None
        except aiohttp.ClientResponseError as e:
            logger.error(
                f"RPKI validator service unavailable: {e.message}. Marking as down."
            )
            self.state.mark_down()
            return None
        except aiohttp.ClientError as e:
            logger.error(f"ClientError caught: {type(e).__name__}")
            return None
        except asyncio.TimeoutError:
            if not self.state.is_down:
                self.state.increment_timeout()
                logger.error(
                    f"RPKI validation request timed out. Timeout count: "
                    f"{self.state.timeout_count}/{self.state.timeout_threshold}"
                )

                if self.state.is_down:
                    logger.error(
                        f"RPKI validator marked as down due to "
                        f"{self.state.timeout_count} consecutive timeouts"
                    )
            return None

    async def process_server(
        self, server: str, domain: str, results: dict[str, Any], stype: str
    ) -> None:
        """Process a server to validate RPKI for its associated IPs."""
        ipv4, ipv6 = await resolve_ips(server)

        if domain not in results:
            results[domain] = {}
        if stype not in results[domain]:
            results[domain][stype] = {}

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

            validation_result = await self.validate_rpki(asn, prefix)
            if not validation_result:
                logger.debug(
                    f"Unable to validate RPKI for IP {ip}, ASN {asn}, and Prefix {prefix}."
                )
                continue

            rpki_state = validation_result["validated_route"]["validity"][
                "state"
            ].capitalize()

            if prefix not in server_results["prefix"]:
                server_results["prefix"][prefix] = {
                    "rpki_state": rpki_state,
                    "ipv4": [ip],
                    "asn": asn,
                }
            elif ip not in server_results["prefix"][prefix]["ipv4"]:
                server_results["prefix"][prefix]["ipv4"].append(ip)

            logger.debug(
                f"RPKI Validation Result for {server} (ASN: {asn}, Prefix: {prefix}): {rpki_state}"
            )

        if server_results["prefix"]:
            results[domain][stype][server] = server_results
        else:
            results[domain][stype][server] = {
                "ipv6": ipv6 if ipv6 else ["No IPv6"],
                "message": "No valid RPKI information found",
            }

    async def run_validation(
        self, domain: str, domain_ns: list, domain_mx: list, mail_ns: list
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run RPKI validation with pre-processed server information."""
        if self.state.is_down:
            logger.debug(f"Skipping RPKI validation for {domain} - validator is down")
            return {}, {
                domain: {
                    "rpki_state": "unknown",
                    "message": "RPKI validator unavailable",
                }
            }

        results = {domain: {}}
        logger.info(f"Processing RPKI for domain: {domain}")

        tasks = []

        if domain_ns:
            tasks.extend(
                [
                    self.process_server(ns, domain, results, "domain_ns")
                    for ns in domain_ns
                ]
            )

        if domain_mx:
            tasks.extend(
                [
                    self.process_server(mx, domain, results, "domain_mx")
                    for mx in domain_mx
                ]
            )

        if mail_ns:
            tasks.extend(
                [
                    self.process_server(ns, domain, results, "mailserver_ns")
                    for sublist in mail_ns
                    for ns in sublist
                ]
            )

        await asyncio.gather(*tasks)

        if self.state.is_down or not results[domain]:
            return {}, {
                domain: {
                    "rpki_state": "unknown",
                    "message": "RPKI validator unavailable",
                }
            }

        rpki_state = await type_validity(results)
        return results, rpki_state


async def type_validity(domain_results):
    """Return valid if all records in each type have rpki_state as valid."""
    rpki_state = {}

    for domain, types in domain_results.items():
        domain_state = {}

        for type_, servers in types.items():
            if not servers:
                domain_state[await translate_server_type(type_)] = None
                continue

            has_valid_records = False
            all_valid = True
            has_servers = False

            for server_data in servers.values():
                if "prefix" in server_data:
                    has_servers = True
                    prefix_states = [
                        prefix_data["rpki_state"].lower() == "valid"
                        for prefix_data in server_data["prefix"].values()
                    ]

                    if prefix_states:
                        if any(prefix_states):
                            has_valid_records = True
                        if not all(prefix_states):
                            all_valid = False

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


# Module-level validator instances cache to maintain shared state per URL
_validator_instances: dict[str, RPKIValidator] = {}


def _get_validator_instance(routinator_url: str) -> RPKIValidator:
    """Get or create a validator instance for the given URL to maintain shared state"""
    if routinator_url not in _validator_instances:
        _validator_instances[routinator_url] = RPKIValidator(routinator_url)
    return _validator_instances[routinator_url]


async def run(domain, domain_ns, domain_mx, mail_ns, routinator_url):
    """
    Main entry point called by main.py.
    Uses cached validator instance to maintain shared state across concurrent calls.
    """
    validator = _get_validator_instance(routinator_url)
    return await validator.run_validation(domain, domain_ns, domain_mx, mail_ns)
