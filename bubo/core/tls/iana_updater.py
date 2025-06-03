"""
IANA TLS parameters update utility.

This module checks for updates to the IANA TLS parameters and downloads the latest CSV.
Updates are cached and only checked once per month to reduce network overhead.
"""

import json
import os
import re
from datetime import datetime, timedelta

import aiohttp

from core.logging.logger import setup_logger

logger = setup_logger(__name__)

DEFAULT_CACHE_DURATION_DAYS = 30
CSV_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
IANA_TLS_PARAMETERS_URL = (
    "https://www.iana.org/assignments/tls-parameters/tls-parameters.txt"
)


async def get_iana_last_updated_date() -> datetime | None:
    """
    Get the last updated date from the IANA TLS parameters text page.

    Returns:
        datetime: The last updated date or None if unable to fetch
    """
    url = IANA_TLS_PARAMETERS_URL
    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(url, timeout=10) as response,
        ):
            if response.status != 200:
                logger.error(f"Failed to fetch IANA parameters: HTTP {response.status}")
                return None

            content = await response.text()

            match = re.search(r"Last Updated\s+(\d{4}-\d{2}-\d{2})", content)
            if match:
                date_text = match.group(1)
                return datetime.strptime(date_text, "%Y-%m-%d")
            else:
                logger.error("Could not find Last Updated date in IANA parameters")
                return None
    except Exception as e:
        logger.error(f"Error fetching IANA last updated date: {e}")
        return None


def get_cached_info(cache_file: str) -> tuple[datetime | None, datetime | None]:
    """
    Get the cached IANA last updated date and last checked date.

    Args:
        cache_file: Path to the cache file

    Returns:
        Tuple containing:
            - Last IANA updated date or None if not available
            - Last checked date or None if not available
    """
    try:
        if os.path.exists(cache_file):
            with open(cache_file) as f:
                data = json.load(f)

                iana_date = data.get("iana_updated")
                checked_date = data.get("last_checked")

                if iana_date:
                    iana_datetime = datetime.strptime(iana_date, "%Y-%m-%d")
                else:
                    iana_datetime = None

                if checked_date:
                    checked_datetime = datetime.strptime(checked_date, "%Y-%m-%d")
                else:
                    checked_datetime = None

                return iana_datetime, checked_datetime
    except Exception as e:
        logger.error(f"Error reading cache file: {e}")

    return None, None


def update_cache_info(
    cache_file: str,
    iana_date: datetime | None = None,
    checked_date: datetime | None = None,
) -> None:
    """
    Update the cached IANA information.

    Args:
        cache_file: Path to the cache file
        iana_date: IANA last updated date
        checked_date: Current check date
    """
    try:
        data: dict[str, str] = {}

        if os.path.exists(cache_file):
            try:
                with open(cache_file) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        if iana_date:
            data["iana_updated"] = iana_date.strftime("%Y-%m-%d")

        if checked_date:
            data["last_checked"] = checked_date.strftime("%Y-%m-%d")

        directory = os.path.dirname(cache_file)
        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(cache_file, "w") as f:
            json.dump(data, f)

    except Exception as e:
        logger.error(f"Error updating cache file: {e}")


async def download_iana_csv(csv_url: str, save_path: str) -> bool:
    """
    Download the IANA TLS parameters CSV file using aiohttp.

    Args:
        csv_url: URL of the CSV file
        save_path: Path to save the CSV file

    Returns:
        bool: True if download successful, False otherwise
    """
    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(csv_url, timeout=10) as response,
        ):
            if response.status != 200:
                logger.error(f"Failed to download CSV: HTTP {response.status}")
                return False

            content = await response.read()

            directory = os.path.dirname(save_path)
            if not os.path.exists(directory):
                os.makedirs(directory)

            with open(save_path, "wb") as f:
                f.write(content)
            return True
    except Exception as e:
        logger.error(f"Error downloading IANA CSV: {e}")
        return False


async def check_and_update_iana_csv(
    csv_path: str, cache_duration_days: int = DEFAULT_CACHE_DURATION_DAYS
) -> bool:
    """
    Check if the IANA TLS parameters CSV file needs to be updated and download it if necessary.
    Only checks for updates once per month (or as specified by cache_duration_days) to reduce
    network overhead.

    Args:
        csv_path: Path to save the CSV file
        cache_duration_days: Number of days to cache the update check (default: 30)

    Returns:
        bool: True if the CSV is up to date or was updated successfully, False otherwise
    """
    cache_file = os.path.join(os.path.dirname(csv_path), "iana_cache.json")
    today = datetime.now()

    stored_iana_date, last_checked_date = get_cached_info(cache_file)

    if last_checked_date and (today - last_checked_date) < timedelta(
        days=cache_duration_days
    ):
        logger.debug(
            f"Using cached IANA information (last checked: {last_checked_date.strftime('%Y-%m-%d')})"
        )

        if stored_iana_date and os.path.exists(csv_path):
            return True

        if stored_iana_date:
            csv_url = CSV_URL
            return await download_iana_csv(csv_url, csv_path)

    logger.debug("Checking for IANA TLS parameters updates")
    web_date = await get_iana_last_updated_date()

    update_cache_info(cache_file, iana_date=web_date, checked_date=today)

    if web_date is None:
        return os.path.exists(csv_path)

    if (
        stored_iana_date is None
        or web_date > stored_iana_date
        or not os.path.exists(csv_path)
    ):
        csv_url = CSV_URL
        if await download_iana_csv(csv_url, csv_path):
            logger.info(
                f"Downloaded updated IANA CSV file (last updated: {web_date.strftime('%Y-%m-%d')})"
            )
            return True
        return False

    return True
