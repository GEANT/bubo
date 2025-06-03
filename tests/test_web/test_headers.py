import asyncio
import unittest
from unittest.mock import patch

from bubo.core.web.headers import check_security_headers


class TestSecurityHeaders(unittest.TestCase):
    """Tests for the check_security_headers function."""

    def setUp(self):
        """Set up test environment."""
        self.domain = "example.com"
        self.port = 443
        self.timeout = 10

    @patch("bubo.core.web.headers.logger")
    def test_all_security_headers_present(self, mock_logger):
        """Test when all security headers are present in the response."""

        response_headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "referrer-policy": "no-referrer",
        }

        result = asyncio.run(
            check_security_headers(
                self.domain, self.port, self.timeout, response_headers
            )
        )

        self.assertEqual(result.content_type_options, "nosniff")
        self.assertEqual(result.frame_options, "DENY")
        self.assertEqual(result.content_security_policy, "default-src 'self'")
        self.assertEqual(result.referrer_policy, "no-referrer")

    @patch("bubo.core.web.headers.logger")
    def test_some_security_headers_missing(self, mock_logger):
        """Test when some security headers are missing from the response."""

        response_headers = {
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        }

        result = asyncio.run(
            check_security_headers(
                self.domain, self.port, self.timeout, response_headers
            )
        )

        self.assertEqual(result.content_type_options, "nosniff")
        self.assertEqual(result.referrer_policy, "no-referrer")

        self.assertIsNone(result.frame_options)
        self.assertIsNone(result.content_security_policy)

    @patch("bubo.core.web.headers.logger")
    def test_empty_response_headers(self, mock_logger):
        """Test when response headers are empty."""

        response_headers = {}

        result = asyncio.run(
            check_security_headers(
                self.domain, self.port, self.timeout, response_headers
            )
        )

        self.assertIsNone(result.content_type_options)
        self.assertIsNone(result.frame_options)
        self.assertIsNone(result.content_security_policy)
        self.assertIsNone(result.referrer_policy)

    @patch("bubo.core.web.headers.logger")
    def test_no_response_headers(self, mock_logger):
        """Test when response headers are None."""

        result = asyncio.run(
            check_security_headers(self.domain, self.port, self.timeout, None)
        )

        self.assertIsNone(result.content_type_options)
        self.assertIsNone(result.frame_options)
        self.assertIsNone(result.content_security_policy)
        self.assertIsNone(result.referrer_policy)

        mock_logger.warning.assert_called_once()

    @patch("bubo.core.web.headers.logger")
    def test_log_messages(self, mock_logger):
        """Test that appropriate log messages are generated."""

        response_headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
        }

        asyncio.run(
            check_security_headers(
                self.domain, self.port, self.timeout, response_headers
            )
        )

        self.assertEqual(mock_logger.debug.call_count, 6)

        first_call_args = mock_logger.debug.call_args_list[0][0][0]
        self.assertIn(self.domain, first_call_args)
        self.assertIn(str(self.port), first_call_args)


if __name__ == "__main__":
    unittest.main()
