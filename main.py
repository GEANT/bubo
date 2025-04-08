import argparse
import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from core.cache_manager.cache_manager import DomainResultsCache
from core.logging.logger import setup_logger
from core.report.generator import generate_html_report
from core.dns.records import process_domain
from core.io.file_processor import process_file, sanitize_file_path
from core.validators.sanitizer import sanitize_domain
from standards import rpki, dane, dnssec, email_security, web
import traceback


logger = setup_logger("domain_validator")


class DomainValidator:
    """
    Handles domain validation operations including RPKI, DANE, DNSSEC, and email security checks.
    """

    VALIDATION_TYPES = {
        "RPKI": rpki.run,
        "DANE": dane.run,
        "DNSSEC": dnssec.run,
        "EMAIL_SECURITY": email_security.run,
        "WEB_SECURITY": web.run,
    }

    def __init__(
        self, cache_dir: str, cache_duration: timedelta, max_concurrent: int = 64
    ):
        self.cache = DomainResultsCache(
            cache_dir=cache_dir, cache_duration=cache_duration
        )
        self.domain_semaphore = asyncio.Semaphore(max_concurrent)

    def create_validation_tasks(
        self,
        domain: str,
        mode: str,
        domain_ns: List[str],
        domain_mx: List[str],
        mail_ns: List[str],
    ) -> Dict[str, asyncio.Task]:
        """
        Creates async tasks for each validation type (RPKI, DANE, DNSSEC, EMAIL_SECURITY).
        Returns a dictionary of validation tasks.
        """
        effective_mail_ns = (
            None if not mail_ns or all(not ns for ns in mail_ns) else mail_ns
        )

        return {
            v_type: asyncio.create_task(
                v_func(domain, mode, domain_ns, domain_mx, effective_mail_ns or [])
                if v_type in ("RPKI", "DANE")
                else v_func(domain)
            )
            for v_type, v_func in self.VALIDATION_TYPES.items()
        }

    async def process_single_domain(
        self, domain_info: Dict[str, str]
    ) -> Optional[Dict[str, Any]]:
        """
        Processes a single domain by running all validations and returning combined results.
        Returns None if domain processing fails.
        """
        domain = domain_info["Domain"]

        async with self.domain_semaphore:  # Limit concurrent domain processing
            domain_ns, domain_mx, mail_ns = await process_domain(domain)

            if not (domain_ns and domain_mx):
                logger.warning(f"No nameservers found for domain: {domain}")
                return None

            try:
                validation_tasks = self.create_validation_tasks(
                    domain, "single", domain_ns, domain_mx, mail_ns
                )

                task_keys = list(validation_tasks.keys())
                task_values = list(validation_tasks.values())
                task_results = await asyncio.gather(*task_values)

                validation_results = dict(zip(task_keys, task_results))

                return {
                    "domain": domain,
                    "country": domain_info.get("Country", ""),
                    "institution": domain_info.get("Institution", ""),
                    **validation_results,
                }
            except Exception as e:
                logger.error(f"Error processing domain {domain}: {str(e)}")
                return None

    def initialize_results_structure(self) -> Dict[str, Any]:
        """
        Creates the initial structure for storing validation results.
        """
        return {
            "validations": {
                v_type: {"results": {}, "state": {}} for v_type in self.VALIDATION_TYPES
            },
            "domain_metadata": {},
        }

    async def process_cached_domain(
        self, domain: str, all_results: Dict[str, Any], cached_results: Dict[str, Any]
    ) -> None:
        """
        Processes and merges cached domain results into the overall results structure.
        """
        all_results["domain_metadata"].update(cached_results["domain_metadata"])
        for v_type in self.VALIDATION_TYPES:
            v_type_result = cached_results["validations"][v_type]["results"]
            v_type_state = cached_results["validations"][v_type]["state"]

            all_results["validations"][v_type]["results"].update(
                v_type_result if v_type_result else {}
            )
            all_results["validations"][v_type]["state"].update(v_type_state)

    async def process_domain(
        self, domains: List[Dict[str, str]], ignore_cache: bool = False
    ) -> Dict[str, Any]:
        """
        Processes a single domain or multiple domains in batch, handling both cached and uncached domains.
        Returns combined results of standards checks.
        """
        all_results = self.initialize_results_structure()
        cached_domains = []
        tasks = []

        for domain_info in domains:
            domain = domain_info["Domain"]
            cached_results = self.cache.get_results(domain, ignore_cache=ignore_cache)

            if cached_results:
                cached_domains.append((domain, cached_results))
            else:
                tasks.append(self.process_single_domain(domain_info))

        if cached_domains:
            await asyncio.gather(
                *[
                    self.process_cached_domain(domain, all_results, cached_results)
                    for domain, cached_results in cached_domains
                ]
            )

        if tasks:
            results = await asyncio.gather(*tasks)
            await self.merge_batch_results(results, all_results)

        return all_results

    async def merge_batch_results(
        self, results: List[Dict[str, Any]], all_results: Dict[str, Any]
    ) -> None:
        """
        Merges batch processing results into the overall results structure and updates cache_manager.
        """
        for result in results:
            if result:
                domain = result["domain"]
                all_results["domain_metadata"][domain] = {
                    "country": result["country"],
                    "institution": result["institution"],
                }

                for v_type in self.VALIDATION_TYPES:
                    results_data, state_data = result[v_type]
                    all_results["validations"][v_type]["results"].update(results_data)
                    all_results["validations"][v_type]["state"].update(state_data)

                # Cache individual domain results
                domain_results = self.extract_domain_results(domain, all_results)
                self.cache.save_results(domain, domain_results)

    def extract_domain_results(
        self, domain: str, all_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extracts results for a specific domain from the combined results.
        """
        return {
            "validations": {
                v_type: {
                    "results": {
                        k: v
                        for k, v in all_results["validations"][v_type][
                            "results"
                        ].items()
                        if domain in k
                    },
                    "state": {
                        k: v
                        for k, v in all_results["validations"][v_type]["state"].items()
                        if domain in k
                    },
                }
                for v_type in self.VALIDATION_TYPES
            },
            "domain_metadata": {domain: all_results["domain_metadata"][domain]},
        }


@dataclass
class CLIOptions:
    single: Optional[str] = None
    batch: Optional[str] = None
    max_concurrent: int = 48
    ignore_cache: bool = False


class CLIHandler:
    """Handles CLI argument parsing and validation with improved security"""

    @staticmethod
    def parse_args() -> CLIOptions:
        parser = argparse.ArgumentParser(
            description="Domain Validation Tool",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )

        input_group = parser.add_mutually_exclusive_group(required=True)
        input_group.add_argument("--single", help="Single domain to validate")
        input_group.add_argument("--batch", help="Path to file containing domains")

        parser.add_argument(
            "--max-concurrent",
            type=int,
            default=48,
            help="Maximum concurrent validations",
        )

        parser.add_argument(
            "--ignore-cache", action="store_true", help="Force fresh validation"
        )

        args = parser.parse_args()

        if args.single:
            args.single = sanitize_domain(args.single)
        if args.batch:
            args.batch = sanitize_file_path(args.batch)

        if args.max_concurrent < 1 or args.max_concurrent > 100:
            args.max_concurrent = 48

        return CLIOptions(**vars(args))


async def main():
    """
    Main entry point for the domain validation tool.
    Handles command line arguments and initiates domain processing.
    """
    cli_options = CLIHandler.parse_args()

    cache_dir = os.path.join(os.path.dirname(__file__), "cache")
    validator = DomainValidator(
        cache_dir,
        cache_duration=timedelta(days=1),
        max_concurrent=cli_options.max_concurrent,
    )

    check_mode = "single" if cli_options.single else "batch"
    domains = (
        cli_options.single
        if cli_options.single
        else await process_file(cli_options.batch)
    )

    if not domains:
        logger.error("No domains to process")
        return

    try:
        results = await validator.process_domain(
            [{"Domain": domains, "Country": "", "Institution": ""}]
            if isinstance(domains, str)
            else domains,
            ignore_cache=cli_options.ignore_cache,
        )

        output_file = (
            f"standards_{check_mode}"
            f"{'_' + domains if isinstance(domains, str) else '_' + domains['Domain'] if check_mode == 'single' else ''}"
            f"_report_{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}.html"
        )

        await generate_html_report(results, output_file)

    except Exception as e:
        logger.error(f"Error processing domains: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")


if __name__ == "__main__":
    asyncio.run(main())
