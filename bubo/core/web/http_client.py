# core/web/http_client.py

import asyncio

import aiohttp

from bubo.core.logging.logger import setup_logger
from bubo.core.web.headers import USER_AGENT

logger = setup_logger(__name__)


async def fetch_headers(domain: str, port: int, timeout: int) -> dict[str, str] | None:
    """Make a single HTTP request and return all response headers."""
    url = f"https://{domain}"
    if port != 443:
        url = f"https://{domain}:{port}"

    max_attempts = 3

    for attempt in range(max_attempts):
        try:
            headers = {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Connection": "keep-alive",
            }

            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                logger.debug(f"Sending GET request to {url}")
                async with session.get(
                    url, allow_redirects=True, headers=headers, ssl=False
                ) as response:
                    logger.debug(f"Response status: {response.status}")
                    logger.debug(f"Response headers: {response.headers}")

                    return {k.lower(): v for k, v in response.headers.items()}

        except aiohttp.ClientConnectorError as e:
            logger.error(f"Connection error fetching headers for {domain}:{port}: {e}")
        except aiohttp.ClientError as e:
            logger.error(f"Client error fetching headers for {domain}:{port}: {e}")
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching headers for {domain}:{port}")
        except Exception as e:
            logger.error(
                f"Unexpected error fetching headers for {domain}:{port}: {e}",
                exc_info=True,
            )

        if attempt < max_attempts - 1:
            sleep_duration = 2**attempt
            logger.debug(
                f"Retrying in {sleep_duration} seconds (attempt {attempt + 1}/{max_attempts})"
            )
            await asyncio.sleep(sleep_duration)

    return None
