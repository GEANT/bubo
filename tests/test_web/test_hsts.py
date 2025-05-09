import asyncio
import unittest
from unittest.mock import patch

from core.web.hsts import check_hsts


class TestHSTS(unittest.TestCase):
    """Tests for the check_hsts function."""

    def setUp(self):
        """Set up test environment."""
        self.domain = "example.com"
        self.port = 443
        self.timeout = 10

    @patch("core.web.hsts.logger")
    def test_complete_hsts_header(self, mock_logger):
        """Test when a complete HSTS header is present."""

        response_headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
        }

        result = asyncio.run(
            check_hsts(self.domain, self.port, self.timeout, response_headers)
        )

        self.assertTrue(result.enabled)
        self.assertEqual(result.max_age, 31536000)
        self.assertTrue(result.include_subdomains)
        self.assertTrue(result.preload)
        self.assertEqual(
            result.header_value, "max-age=31536000; includeSubDomains; preload"
        )

    @patch("core.web.hsts.logger")
    def test_partial_hsts_header_max_age_only(self, mock_logger):
        """Test when HSTS header only contains max-age directive."""

        response_headers = {"strict-transport-security": "max-age=15768000"}

        result = asyncio.run(
            check_hsts(self.domain, self.port, self.timeout, response_headers)
        )

        self.assertTrue(result.enabled)
        self.assertEqual(result.max_age, 15768000)
        self.assertFalse(result.include_subdomains)
        self.assertFalse(result.preload)
        self.assertEqual(result.header_value, "max-age=15768000")

    @patch("core.web.hsts.logger")
    def test_partial_hsts_header_with_subdomains(self, mock_logger):
        """Test when HSTS header contains max-age and includeSubDomains."""

        response_headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains"
        }

        result = asyncio.run(
            check_hsts(self.domain, self.port, self.timeout, response_headers)
        )

        self.assertTrue(result.enabled)
        self.assertEqual(result.max_age, 31536000)
        self.assertTrue(result.include_subdomains)
        self.assertFalse(result.preload)

    @patch("core.web.hsts.logger")
    def test_case_insensitivity(self, mock_logger):
        """Test that header parsing is case-insensitive."""

        response_headers = {
            "strict-transport-security": "Max-Age=31536000; IncludeSubDomains; Preload"
        }

        result = asyncio.run(
            check_hsts(self.domain, self.port, self.timeout, response_headers)
        )

        self.assertTrue(result.enabled)
        self.assertEqual(result.max_age, 31536000)
        self.assertTrue(result.include_subdomains)
        self.assertTrue(result.preload)

    @patch("core.web.hsts.logger")
    def test_no_hsts_header(self, mock_logger):
        """Test when HSTS header is not present in response headers."""

        response_headers = {"content-type": "text/html", "server": "nginx"}

        result = asyncio.run(
            check_hsts(self.domain, self.port, self.timeout, response_headers)
        )

        self.assertFalse(result.enabled)
        self.assertEqual(result.max_age, 0)
        self.assertFalse(result.include_subdomains)
        self.assertFalse(result.preload)
        self.assertIsNone(result.header_value)

    @patch("core.web.hsts.logger")
    def test_no_response_headers(self, mock_logger):
        """Test when response headers are None."""

        result = asyncio.run(check_hsts(self.domain, self.port, self.timeout, None))

        self.assertFalse(result.enabled)
        self.assertEqual(result.max_age, 0)
        self.assertFalse(result.include_subdomains)
        self.assertFalse(result.preload)
        self.assertIsNone(result.header_value)

        mock_logger.warning.assert_called_once()

    @patch("core.web.hsts.logger")
    def test_log_messages(self, mock_logger):
        """Test that appropriate log messages are generated."""

        response_headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
        }

        asyncio.run(check_hsts(self.domain, self.port, self.timeout, response_headers))

        self.assertTrue(mock_logger.debug.call_count >= 6)

        first_call_args = mock_logger.debug.call_args_list[0][0][0]
        self.assertIn(self.domain, first_call_args)
        self.assertIn(str(self.port), first_call_args)


if __name__ == "__main__":
    unittest.main()
