import asyncio
import os
import traceback
from datetime import datetime, timedelta
from typing import Any, ClassVar

from dotenv import load_dotenv

from bubo.core.cache_manager.cache_manager import DomainResultsCache
from bubo.core.cli.handler import CLIHandler
from bubo.core.dns.records import process_domain
from bubo.core.io.file_processor import process_file
from bubo.core.logging.logger import setup_logger
from bubo.core.report.generator import generate_html_report
from bubo.core.tls import cipher_utils
from bubo.standards import dane, dnssec, email_security, rpki, web

logger = setup_logger("domain_validator")


class DomainValidator:
    """
    Handles domain validation operations including RPKI, DANE, DNSSEC, and email security checks.
    """

    VALIDATION_TYPES: ClassVar[dict] = {
        "RPKI": rpki.run,
        "DANE": dane.run,
        "DNSSEC": dnssec.run,
        "EMAIL_SECURITY": email_security.run,
        "WEB_SECURITY": web.run,
    }

    def __init__(
        self,
        cache_dir: str,
        cache_duration: timedelta,
        max_concurrent: int = 64,
        routinator_url: str = "http://localhost:8323",
    ):
        self.cache = DomainResultsCache(
            cache_dir=cache_dir, cache_duration=cache_duration
        )
        self.domain_semaphore = asyncio.Semaphore(max_concurrent)
        self.routinator_url = routinator_url

    def create_validation_tasks(
        self,
        domain: str,
        mode: str,
        domain_ns: list[str],
        domain_mx: list[str],
        mail_ns: list[str] | list[list[str]],
    ) -> dict[str, asyncio.Task]:
        """
        Creates async tasks for each validation type (RPKI, DANE, DNSSEC, EMAIL_SECURITY).
        Returns a dictionary of validation tasks.
        """
        effective_mail_ns = (
            None if not mail_ns or all(not ns for ns in mail_ns) else mail_ns
        )

        tasks = {}
        for v_type, v_func in self.VALIDATION_TYPES.items():
            if v_type == "RPKI":
                tasks[v_type] = asyncio.create_task(
                    v_func(
                        domain,
                        domain_ns,
                        domain_mx,
                        effective_mail_ns or [],
                        routinator_url=self.routinator_url,
                    )
                )
            elif v_type == "DANE":
                tasks[v_type] = asyncio.create_task(
                    v_func(domain, mode, domain_ns, domain_mx, mail_ns or [])
                )

            else:
                tasks[v_type] = asyncio.create_task(v_func(domain))

        return tasks

    async def process_single_domain(
        self, domain_info: dict[str, str]
    ) -> dict[str, Any] | None:
        """
        Processes a single domain by running all validations and returning combined results.
        Returns None if domain processing fails.
        """
        domain = domain_info["Domain"]

        async with self.domain_semaphore:
            domain_ns, domain_mx, mail_ns = await process_domain(domain)

            if not (domain_ns and domain_mx):
                logger.warning(
                    f"Both or one of the domain nameservers and mailservers are empty for {domain}. Skipping."
                )
                return None

            try:
                validation_tasks = self.create_validation_tasks(
                    domain, "single", domain_ns, domain_mx, mail_ns
                )

                task_keys = list(validation_tasks.keys())
                task_values = list(validation_tasks.values())
                task_results = await asyncio.gather(*task_values)

                validation_results = dict(zip(task_keys, task_results, strict=False))

                return {
                    "domain": domain,
                    "country": domain_info.get("Country", ""),
                    "institution": domain_info.get("Institution", ""),
                    **validation_results,
                }
            except Exception as e:
                logger.error(f"Error processing domain {domain}: {e}")
                return None

    def initialize_results_structure(self) -> dict[str, Any]:
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
        self, domain: str, all_results: dict[str, Any], cached_results: dict[str, Any]
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
        self, domains: list[dict[str, str]], ignore_cache: bool = False
    ) -> dict[str, Any]:
        """
        Processes a single domain or multiple domains in batch, handling both cached and uncached domains.
        Returns combined results of standards checks.
        """
        all_results = self.initialize_results_structure()
        cached_domains = []
        tasks = []

        successful_domains = False

        for domain_info in domains:
            domain = domain_info["Domain"]
            cached_results = self.cache.get_results(domain, ignore_cache=ignore_cache)

            if cached_results:
                cached_domains.append((domain, cached_results))
                successful_domains = True
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
            valid_results = [r for r in results if r]

            if valid_results:
                successful_domains = True
                await self.merge_batch_results(valid_results, all_results)

        return {**all_results, "success": successful_domains}

    async def merge_batch_results(
        self, results: list[dict[str, Any]], all_results: dict[str, Any]
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
        self, domain: str, all_results: dict[str, Any]
    ) -> dict[str, Any]:
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


async def start():
    """
    Main entry point for the domain validation tool.
    Handles command line arguments and initiates domain processing.
    """
    load_dotenv()
    await cipher_utils.initialize()

    cli_options = CLIHandler.parse_args()

    cache_dir = os.path.join(os.path.dirname(__file__), "cache")
    validator = DomainValidator(
        cache_dir,
        cache_duration=timedelta(days=1),
        max_concurrent=cli_options.max_concurrent,
        routinator_url=cli_options.routinator_url,
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

        if not results.get("success", False):
            logger.warning("No domains were successfully processed")
            return

        output_file = (
            f"standards_{check_mode}"
            f"{'_' + domains if isinstance(domains, str) else '_' + domains['Domain'] if check_mode == 'single' else ''}"
            f"_report_{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}.html"
        )

        await generate_html_report(
            results, output_file, output_dir=cli_options.output_dir
        )

    except Exception as e:
        logger.error(f"Error processing domains: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")


def main():
    try:
        asyncio.run(start())
    except KeyboardInterrupt:
        logger.info("Process interrupted by user.")
    except Exception as e:
        logger.error(f"Error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")


if __name__ == "__main__":
    main()
