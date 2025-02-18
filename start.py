# start.py

import argparse
import asyncio
import os
from datetime import datetime
from datetime import timedelta
from logging import getLogger

from core.cache_manager import DomainResultsCache
from core.custom_logger.logger import setup_logger
from core.generate_report import generate_html_report
from core.utils import process_domain, process_file
from standards import rpki, dane, dnssec

setup_logger()
logger = getLogger(__name__)


async def process_single_domain(domain_info):
    """Process a single domain and return its RPKI, DANE, and DNSSEC results."""
    domain = domain_info['Domain']
    domain_ns, domain_mx, mail_ns = await process_domain(domain)
    if not domain_ns:  # Only check domain nameservers/mailservers are required
        return None

    effective_mail_ns = None if not mail_ns or all(not ns for ns in mail_ns) else mail_ns

    rpki_task = asyncio.create_task(rpki.run(domain, "single", domain_ns, domain_mx, effective_mail_ns or []))
    dane_task = asyncio.create_task(dane.run(domain, "single", domain_ns, domain_mx, effective_mail_ns or []))
    dnssec_task = asyncio.create_task(dnssec.run(domain))

    try:
        rpki_results = await rpki_task
        dane_results = await dane_task
        dnssec_results = await dnssec_task

        return {
            "domain": domain,
            "country": domain_info['Country'],
            "institution": domain_info['Institution'],
            "RPKI": rpki_results,
            "DANE": dane_results,
            "DNSSEC": dnssec_results
        }
    except Exception as e:
        logger.error(f"Error processing domain {domain}: {str(e)}")
        return None


async def start(domains, check_mode, ignore_cache=False):
    all_results = {
        "validations": {
            "RPKI": {
                "results": {},
                "state": {}
            },
            "DANE": {
                "results": {},
                "state": {}
            },
            "DNSSEC": {
                "results": {},
                "state": {}
            }
        },
        "domain_metadata": {}
    }

    if check_mode == "single":
        domain_info = domains if isinstance(domains, dict) else {'Domain': domains, 'Country': '', 'Institution': ''}
        domain = domain_info['Domain']

        # Check cache first unless ignore_cache is True
        cached_results = cache.get_results(domain, ignore_cache=ignore_cache)
        if cached_results:
            # logger.info(f"Using cached results for domain: {domain}")
            output_file = f"standards_single_{domain}_cached_report_{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}.html"
            await generate_html_report(cached_results, output_file)
            return

        logger.info(f"Processing domain: {domain}")
        result = await process_single_domain(domain_info)
        if result:
            rpki_results, rpki_state = result["RPKI"]
            dane_results, dane_state = result["DANE"]
            dnssec_results, dnssec_state = result["DNSSEC"]

            all_results["domain_metadata"][result["domain"]] = {
                "country": result["country"],
                "institution": result["institution"]
            }

            all_results["validations"]["RPKI"]["results"].update(rpki_results)
            all_results["validations"]["RPKI"]["state"].update(rpki_state)
            all_results["validations"]["DANE"]["results"].update(dane_results)
            all_results["validations"]["DANE"]["state"].update(dane_state)
            all_results["validations"]["DNSSEC"]["results"].update(dnssec_results)
            all_results["validations"]["DNSSEC"]["state"].update(dnssec_state)

            cache.save_results(domain, all_results)

    else:
        # Handle batch mode
        processed_domains = set()
        tasks = []

        for domain_info in domains:
            domain = domain_info['Domain']
            cached_results = cache.get_results(domain, ignore_cache=ignore_cache)

            if cached_results:
                # logger.info(f"Using cached results for domain: {domain}")
                # Merge cached results into all_results
                all_results["domain_metadata"].update(cached_results["domain_metadata"])
                for validation_type in all_results["validations"]:
                    all_results["validations"][validation_type]["results"].update(
                        cached_results["validations"][validation_type]["results"]
                    )
                    all_results["validations"][validation_type]["state"].update(
                        cached_results["validations"][validation_type]["state"]
                    )
                processed_domains.add(domain)
            else:
                logger.info(f"Queueing domain for processing: {domain}")
                tasks.append(process_single_domain(domain_info))


        await asyncio.sleep(2)
        # Process domains that weren't in cache
        if tasks:
            logger.info(f"Processing {len(tasks)} uncached domains")
            results = await asyncio.gather(*tasks)

            for result in results:
                if result:
                    domain = result["domain"]
                    rpki_results, rpki_state = result["RPKI"]
                    dane_results, dane_state = result["DANE"]
                    dnssec_results, dnssec_state = result["DNSSEC"]

                    all_results["domain_metadata"][domain] = {
                        "country": result["country"],
                        "institution": result["institution"]
                    }

                    all_results["validations"]["RPKI"]["results"].update(rpki_results)
                    all_results["validations"]["RPKI"]["state"].update(rpki_state)
                    all_results["validations"]["DANE"]["results"].update(dane_results)
                    all_results["validations"]["DANE"]["state"].update(dane_state)
                    all_results["validations"]["DNSSEC"]["results"].update(dnssec_results)
                    all_results["validations"]["DNSSEC"]["state"].update(dnssec_state)

                    # Create individual domain results for caching
                    domain_results = {
                        "validations": {
                            vtype: {
                                "results": {k: v for k, v in all_results["validations"][vtype]["results"].items()
                                            if domain in k},
                                "state": {k: v for k, v in all_results["validations"][vtype]["state"].items()
                                          if domain in k}
                            }
                            for vtype in ["RPKI", "DANE", "DNSSEC"]
                        },
                        "domain_metadata": {
                            domain: all_results["domain_metadata"][domain]
                        }
                    }
                    cache.save_results(domain, domain_results)

    output_file = f"standards_{check_mode + f'_{domains if isinstance(domains, str) else domains["Domain"]}' if check_mode == 'single' else check_mode}_report_{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}.html"
    await generate_html_report(all_results, output_file)


async def main():
    parser = argparse.ArgumentParser(description="Check/Validate RPKI, DANE and DNSSEC for domains.")
    parser.add_argument('--single', type=str, help="Single domain name to check.")
    parser.add_argument('--batch', type=str, help="Path to a file (txt/csv) containing domains.")
    parser.add_argument('--max-concurrent', type=int, default=10,
                        help="Maximum number of concurrent domain checks (default: 10)")
    parser.add_argument('--ignore-cache', action='store_true',
                        help="Force refresh of results ignoring cache")
    args = parser.parse_args()

    cache_dir = os.path.join(os.path.dirname(__file__), "cache")
    global cache
    cache = DomainResultsCache(
        cache_dir=cache_dir,
        cache_duration=timedelta(days=1)
    )

    check_mode = "single" if args.single else "batch"
    if not args.single and not args.batch:
        logger.error("Invalid input. Please provide [--single DOMAIN.tld] or --batch [file_path.txt].")
        return

    domain = args.single if args.single else await process_file(args.batch)
    if domain:
        await start(domain, check_mode, ignore_cache=args.ignore_cache)


if __name__ == "__main__":
    asyncio.run(main())
