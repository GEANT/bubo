# core/dns/resolver.py

import asyncio
from random import random
from typing import Optional, Any

import dns
import dns.asyncresolver

from core.logging.logger import setup_logger

logger = setup_logger(__name__)


class DNSResolverManager:
    """
    Singleton class to manage DNS resolution operations with built-in
    rate limiting and retry logic.
    """

    _instance = None

    def __new__(cls) -> "DNSResolverManager":
        if cls._instance is None:
            cls._instance = super(DNSResolverManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        """Initialize DNS resolver settings and connection limits"""
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 8
        self.resolver.lifetime = 10
        self.resolver.nameservers = [
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
        ]

        # Rate limiting semaphore to prevent overwhelming DNS servers
        self.semaphore = asyncio.Semaphore(20)

    async def resolve(self, domain: str, record_type: str, retries: int = 3) -> Any:
        """
        Resolve DNS records with retry logic and exponential backoff.

        Args:
            domain: Domain name to resolve
            record_type: DNS record type (e.g., 'A', 'MX', 'NS')
            retries: Number of retries on failure

        Returns:
            DNS resolver answer containing requested records

        Raises:
            Various dns.resolver exceptions based on the query outcome
        """
        backoff_factor = 1.5
        current_retry = 0

        while current_retry <= retries:
            try:
                async with self.semaphore:
                    return await self.resolver.resolve(domain, record_type)
            except (
                dns.resolver.NoNameservers,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
            ):
                # Don't retry on these specific errors
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

    async def resolve_dnssec(
        self, domain: str, record_type: str, raise_on_no_answer: bool = False
    ) -> Optional[Any]:
        """
        Specialized method for DNSSEC-enabled DNS resolution.

        Args:
            domain: Domain name to resolve
            record_type: DNS record type
            raise_on_no_answer: Whether to raise exception on no answer

        Returns:
            DNS resolver answer or None if no answer and not raising
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
