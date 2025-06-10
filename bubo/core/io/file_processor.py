# core/io/file_processor.py

import os
from csv import DictReader

from bubo.core.logging.logger import setup_logger
from bubo.core.network.ip_tools import is_valid_ip
from bubo.core.validators.sanitizer import sanitize_text_field, validate_hostname

logger = setup_logger(__name__)


async def process_file(
    file_path: str, sort_by: str | None = "Country"
) -> list[dict[str, str]]:
    """
    Process a text or CSV file containing domains.

    Args:
        file_path: Path to the file to process
        sort_by: Column to sort by (for CSV files)

    Returns:
        List of domain dictionaries with metadata

    Raises:
        Exception: If file processing fails
    """
    domains = []

    file_path = os.path.abspath(os.path.normpath(file_path))
    if not os.path.isfile(file_path):
        raise Exception(f"File does not exist: {file_path}")

    try:
        if file_path.endswith(".txt"):
            with open(file_path, encoding="utf-8") as file:
                for line in file:
                    stripped_line = line.strip()
                    if stripped_line:
                        if await validate_hostname(stripped_line) or is_valid_ip(
                            stripped_line
                        ):
                            domains.append(
                                {
                                    "Domain": stripped_line,
                                    "Country": "",
                                    "Institution": "",
                                }
                            )
                        else:
                            logger.warning(f"Skipping invalid domain: {stripped_line}")

        elif file_path.endswith(".csv"):
            with open(file_path, encoding="utf-8") as file:
                reader = DictReader(file)
                try:
                    if "Domain" not in reader.fieldnames:
                        raise Exception("CSV file must contain a 'Domain' column.")

                    for row in reader:
                        if row.get("Domain"):
                            domain = row["Domain"].strip()

                            if await validate_hostname(domain) or is_valid_ip(domain):
                                country = sanitize_text_field(
                                    row.get("Country", ""), max_length=100
                                )
                                institution = sanitize_text_field(
                                    row.get("Institution", ""), max_length=200
                                )

                                domain_info = {
                                    "Domain": domain,
                                    "Country": country,
                                    "Institution": institution,
                                }
                                domains.append(domain_info)
                            else:
                                logger.warning(f"Skipping invalid domain: {domain}")
                except Exception as e:
                    raise Exception(f"Error processing CSV file: {e}") from e

                logger.info(f"Found {len(domains)} valid domains in the CSV file")
        else:
            raise Exception(
                "Invalid file format. Only .txt and .csv files are supported."
            )

    except Exception as e:
        raise Exception(f"Error processing file: {e}") from e

    # Limit number of domains to prevent resource exhaustion
    max_domains = 75
    if len(domains) > max_domains:
        logger.warning(
            f"Too many domains in file (limit: {max_domains}). Processing only the first {max_domains}."
        )
        domains = domains[:max_domains]

    try:
        if domains and sort_by:
            domains.sort(key=lambda x: (x[sort_by] == "", x[sort_by]))
            logger.debug(f"Sorted domains by {sort_by}")
    except KeyError:
        logger.warning(f"Column {sort_by} not found in the file. Skipping sorting.")

    return domains


def sanitize_file_path(file_path: str) -> str:
    """
    Sanitize and validate a file path.

    Args:
        file_path: File path to sanitize

    Returns:
        Sanitized absolute file path

    Raises:
        ValueError: If file doesn't exist or has invalid extension
    """
    abs_path = os.path.abspath(os.path.normpath(file_path))
    if not os.path.isfile(abs_path):
        raise ValueError(f"File does not exist: {file_path}")
    if not abs_path.endswith((".txt", ".csv")):
        raise ValueError("Only .txt and .csv files are supported")
    return abs_path
