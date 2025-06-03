# core/io/file_processor.py

import os
from csv import DictReader

from core.logging.logger import setup_logger
from core.network.ip_tools import is_valid_ip
from core.validators.sanitizer import sanitize_text_field, validate_hostname

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
                    line = line.strip()
                    if line:
                        if await validate_hostname(line) or is_valid_ip(line):
                            domains.append(
                                {"Domain": line, "Country": "", "Institution": ""}
                            )
                        else:
                            logger.warning(f"Skipping invalid domain: {line}")

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
    MAX_DOMAINS = 75
    if len(domains) > MAX_DOMAINS:
        logger.warning(
            f"Too many domains in file (limit: {MAX_DOMAINS}). Processing only the first {MAX_DOMAINS}."
        )
        domains = domains[:MAX_DOMAINS]

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
    if not (abs_path.endswith(".txt") or abs_path.endswith(".csv")):
        raise ValueError("Only .txt and .csv files are supported")
    return abs_path
