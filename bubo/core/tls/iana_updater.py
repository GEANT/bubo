"""
IANA TLS parameters update utility.

This module checks for updates to the IANA TLS parameters and downloads the latest CSV.
Updates are cached and only checked once per configured period to reduce network overhead.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import aiohttp

from bubo.core.logging.logger import setup_logger
from bubo.core.tls.cipher_utils import get_cache_directory

logger = setup_logger(__name__)

DEFAULT_CACHE_DURATION_DAYS = 30
CSV_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
IANA_TLS_PARAMETERS_URL = (
    "https://www.iana.org/assignments/tls-parameters/tls-parameters.txt"
)


@dataclass
class CacheInfo:
    """Container for cache information."""

    iana_updated: datetime | None = None
    last_checked: datetime | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        data = {}
        if self.iana_updated:
            data["iana_updated"] = self.iana_updated.strftime("%Y-%m-%d")
        if self.last_checked:
            data["last_checked"] = self.last_checked.strftime("%Y-%m-%d")
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "CacheInfo":
        """Create CacheInfo from dictionary."""
        iana_updated = None
        last_checked = None

        if "iana_updated" in data:
            iana_updated = datetime.strptime(data["iana_updated"], "%Y-%m-%d")
        if "last_checked" in data:
            last_checked = datetime.strptime(data["last_checked"], "%Y-%m-%d")

        return cls(iana_updated=iana_updated, last_checked=last_checked)


def get_cache_file_path() -> Path:
    """Get the path to the cache metadata file."""
    return get_cache_directory() / "iana_cache.json"


async def fetch_iana_last_updated_date() -> datetime | None:
    """
    Fetch the last updated date from the IANA TLS parameters text page.

    Returns:
        The last updated date or None if unable to fetch
    """
    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(IANA_TLS_PARAMETERS_URL, timeout=10) as response,
        ):
            if response.status != 200:
                logger.error(f"Failed to fetch IANA parameters: HTTP {response.status}")
                return None

            content = await response.text()

            match = re.search(r"Last Updated\s+(\d{4}-\d{2}-\d{2})", content)
            if match:
                date_text = match.group(1)
                return datetime.strptime(date_text, "%Y-%m-%d")

            logger.error("Could not find Last Updated date in IANA parameters page")
            return None

    except Exception as e:
        logger.error(f"Error fetching IANA last updated date: {e}")
        return None


def load_cache_info() -> CacheInfo:
    """
    Load cache information from disk.

    Returns:
        CacheInfo object with loaded data or empty if file doesn't exist
    """
    cache_file = get_cache_file_path()

    if not cache_file.exists():
        return CacheInfo()

    try:
        with open(cache_file) as f:
            data = json.load(f)
            return CacheInfo.from_dict(data)
    except Exception as e:
        logger.error(f"Error reading cache file: {e}")
        return CacheInfo()


def save_cache_info(cache_info: CacheInfo) -> None:
    """
    Save cache information to disk.

    Args:
        cache_info: CacheInfo object to save
    """
    cache_file = get_cache_file_path()

    try:
        with open(cache_file, "w") as f:
            json.dump(cache_info.to_dict(), f, indent=2)
    except Exception as e:
        logger.error(f"Error saving cache file: {e}")


async def download_iana_csv(save_path: Path) -> bool:
    """
    Download the IANA TLS parameters CSV file.

    Args:
        save_path: Path where to save the CSV file

    Returns:
        True if download successful, False otherwise
    """
    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(CSV_URL, timeout=30) as response,
        ):
            if response.status != 200:
                logger.error(f"Failed to download CSV: HTTP {response.status}")
                return False

            content = await response.read()

            temp_path = save_path.with_suffix(".tmp")
            temp_path.write_bytes(content)
            temp_path.replace(save_path)

            logger.info(f"Successfully downloaded IANA CSV to {save_path}")
            return True

    except Exception as e:
        logger.error(f"Error downloading IANA CSV: {e}")
        return False


def should_check_for_updates(cache_info: CacheInfo, cache_duration_days: int) -> bool:
    """
    Determine if we should check for updates based on cache info.

    Args:
        cache_info: Current cache information
        cache_duration_days: How many days to wait between checks

    Returns:
        True if we should check for updates, False otherwise
    """
    if not cache_info.last_checked:
        return True

    days_since_check = (datetime.now() - cache_info.last_checked).days
    return days_since_check >= cache_duration_days


def needs_csv_download(
    cache_info: CacheInfo, web_date: datetime | None, csv_path: Path
) -> bool:
    """
    Determine if we need to download the CSV file.

    Args:
        cache_info: Current cache information
        web_date: Last updated date from IANA website
        csv_path: Path to the CSV file

    Returns:
        True if download is needed, False otherwise
    """

    if not csv_path.exists():
        return True

    if web_date is None:
        return False

    if cache_info.iana_updated is None:
        return True

    return web_date > cache_info.iana_updated


async def check_and_update_iana_csv(
    csv_path: str, cache_duration_days: int = DEFAULT_CACHE_DURATION_DAYS
) -> bool:
    """
    Check if the IANA TLS parameters CSV file needs to be updated and download if necessary.

    This function implements a smart caching strategy:
    1. Only checks IANA website once per cache_duration_days period
    2. Downloads CSV only if it's newer than cached version or missing
    3. Tracks both last check date and IANA's last update date

    Args:
        csv_path: Path to save the CSV file (can be string or Path)
        cache_duration_days: Days between update checks (default: 30)

    Returns:
        True if the CSV is available and up to date, False if there were errors
    """
    csv_path = Path(csv_path)

    cache_info = load_cache_info()

    if not should_check_for_updates(cache_info, cache_duration_days):
        logger.debug(
            f"Using cached IANA data (last checked: "
            f"{cache_info.last_checked.strftime('%Y-%m-%d') if cache_info.last_checked else 'never'})"
        )

        return csv_path.exists()

    logger.info("Checking IANA website for TLS parameters updates")

    web_date = await fetch_iana_last_updated_date()

    cache_info.last_checked = datetime.now()

    if needs_csv_download(cache_info, web_date, csv_path):
        logger.info(
            f"Downloading updated IANA CSV "
            f"(web date: {web_date.strftime('%Y-%m-%d') if web_date else 'unknown'}, "
            f"cached date: {cache_info.iana_updated.strftime('%Y-%m-%d') if cache_info.iana_updated else 'never'})"
        )

        if await download_iana_csv(csv_path):
            if web_date:
                cache_info.iana_updated = web_date
            save_cache_info(cache_info)
            return True
        save_cache_info(cache_info)
        return csv_path.exists()

    logger.debug("IANA CSV is up to date, no download needed")

    save_cache_info(cache_info)
    return csv_path.exists()


async def get_iana_last_updated_date() -> datetime | None:
    """
    Get the last updated date from the IANA TLS parameters text page.

    This is a wrapper for backwards compatibility.
    """
    return await fetch_iana_last_updated_date()
