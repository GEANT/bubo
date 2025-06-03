import asyncio
import unittest
from unittest.mock import patch

from bubo.core.tls.models import TLSCheckConfig
from bubo.core.web.http_security import (
    build_http_security_dicts,
    run_http_security_checks,
)
from bubo.core.web.models import HSTSInfo, SecurityHeadersInfo


class TestHttpSecurity(unittest.TestCase):
    """Tests for HTTP security functionality."""

    def setUp(self):
        """Set up test environment."""
        self.domain = "example.com"
        self.port = 443
        self.config = TLSCheckConfig(
            timeout_connect=10, check_hsts=True, check_security_headers=True
        )

        self.sample_hsts_info = HSTSInfo(
            enabled=True,
            max_age=31536000,
            include_subdomains=True,
            preload=True,
            header_value="max-age=31536000; includeSubDomains; preload",
        )

        self.sample_headers_info = SecurityHeadersInfo(
            content_type_options="nosniff",
            frame_options="DENY",
            content_security_policy="default-src 'self'",
            referrer_policy="no-referrer",
        )

        self.sample_headers = {
            "content-type": "text/html",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "referrer-policy": "no-referrer",
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        }

    @patch("bubo.core.web.http_security.check_security_headers")
    @patch("bubo.core.web.http_security.check_hsts")
    @patch("bubo.core.web.http_security.fetch_headers")
    async def _test_run_http_security_checks_both_enabled(
        self, mock_fetch_headers, mock_check_hsts, mock_check_security_headers
    ):
        """Helper for testing when both HSTS and security headers checks are enabled."""

        mock_fetch_headers.return_value = self.sample_headers
        mock_check_hsts.return_value = self.sample_hsts_info
        mock_check_security_headers.return_value = self.sample_headers_info

        hsts_info, headers_info = await run_http_security_checks(
            self.domain, self.port, self.config
        )

        mock_fetch_headers.assert_called_once_with(
            self.domain, self.port, self.config.timeout_connect
        )

        mock_check_hsts.assert_called_once_with(
            self.domain, self.port, self.config.timeout_connect, self.sample_headers
        )

        mock_check_security_headers.assert_called_once_with(
            self.domain, self.port, self.config.timeout_connect, self.sample_headers
        )

        self.assertEqual(hsts_info, self.sample_hsts_info)
        self.assertEqual(headers_info, self.sample_headers_info)

    def test_run_http_security_checks_both_enabled(self):
        """Test running checks with both HSTS and security headers enabled."""
        asyncio.run(self._test_run_http_security_checks_both_enabled())

    @patch("bubo.core.web.http_security.check_security_headers")
    @patch("bubo.core.web.http_security.check_hsts")
    @patch("bubo.core.web.http_security.fetch_headers")
    async def _test_run_http_security_checks_hsts_only(
        self, mock_fetch_headers, mock_check_hsts, mock_check_security_headers
    ):
        """Helper for testing when only HSTS check is enabled."""

        mock_fetch_headers.return_value = self.sample_headers
        mock_check_hsts.return_value = self.sample_hsts_info

        config = TLSCheckConfig(
            timeout_connect=10, check_hsts=True, check_security_headers=False
        )

        hsts_info, headers_info = await run_http_security_checks(
            self.domain, self.port, config
        )

        mock_fetch_headers.assert_called_once()

        mock_check_hsts.assert_called_once()
        mock_check_security_headers.assert_not_called()

        self.assertEqual(hsts_info, self.sample_hsts_info)
        self.assertIsNone(headers_info)

    def test_run_http_security_checks_hsts_only(self):
        """Test running checks with only HSTS enabled."""
        asyncio.run(self._test_run_http_security_checks_hsts_only())

    @patch("bubo.core.web.http_security.check_security_headers")
    @patch("bubo.core.web.http_security.check_hsts")
    @patch("bubo.core.web.http_security.fetch_headers")
    async def _test_run_http_security_checks_security_headers_only(
        self, mock_fetch_headers, mock_check_hsts, mock_check_security_headers
    ):
        """Helper for testing when only security headers check is enabled."""

        mock_fetch_headers.return_value = self.sample_headers
        mock_check_security_headers.return_value = self.sample_headers_info

        config = TLSCheckConfig(
            timeout_connect=10, check_hsts=False, check_security_headers=True
        )

        hsts_info, headers_info = await run_http_security_checks(
            self.domain, self.port, config
        )

        mock_fetch_headers.assert_called_once()

        mock_check_hsts.assert_not_called()
        mock_check_security_headers.assert_called_once()

        self.assertIsNone(hsts_info)
        self.assertEqual(headers_info, self.sample_headers_info)

    def test_run_http_security_checks_security_headers_only(self):
        """Test running checks with only security headers enabled."""
        asyncio.run(self._test_run_http_security_checks_security_headers_only())

    @patch("bubo.core.web.http_security.fetch_headers")
    async def _test_run_http_security_checks_both_disabled(self, mock_fetch_headers):
        """Helper for testing when both checks are disabled."""

        config = TLSCheckConfig(
            timeout_connect=10, check_hsts=False, check_security_headers=False
        )

        hsts_info, headers_info = await run_http_security_checks(
            self.domain, self.port, config
        )

        mock_fetch_headers.assert_not_called()

        self.assertIsNone(hsts_info)
        self.assertIsNone(headers_info)

    def test_run_http_security_checks_both_disabled(self):
        """Test running checks with both checks disabled."""
        asyncio.run(self._test_run_http_security_checks_both_disabled())

    @patch("bubo.core.web.http_security.fetch_headers")
    async def _test_run_http_security_checks_fetch_headers_returns_none(
        self, mock_fetch_headers
    ):
        """Helper for testing when fetch_headers returns None."""

        mock_fetch_headers.return_value = None

        hsts_info, headers_info = await run_http_security_checks(
            self.domain, self.port, self.config
        )

        mock_fetch_headers.assert_called_once()

        self.assertIsNone(hsts_info)
        self.assertIsNone(headers_info)

    def test_run_http_security_checks_fetch_headers_returns_none(self):
        """Test when fetch_headers returns None."""
        asyncio.run(self._test_run_http_security_checks_fetch_headers_returns_none())

    def test_build_http_security_dicts_all_values(self):
        """Test building dictionaries with all values present."""
        hsts_dict, headers_dict = build_http_security_dicts(
            self.sample_hsts_info, self.sample_headers_info
        )

        expected_hsts_dict = {
            "enabled": True,
            "max_age": 31536000,
            "include_subdomains": True,
            "preload": True,
            "header_value": "max-age=31536000; includeSubDomains; preload",
        }
        self.assertEqual(hsts_dict, expected_hsts_dict)

        expected_headers_dict = {
            "x_content_type_options": "nosniff",
            "x_frame_options": "DENY",
            "content_security_policy": "default-src 'self'",
            "referrer_policy": "no-referrer",
        }
        self.assertEqual(headers_dict, expected_headers_dict)

    def test_build_http_security_dicts_none_values(self):
        """Test building dictionaries with None values."""
        hsts_dict, headers_dict = build_http_security_dicts(None, None)

        self.assertIsNone(hsts_dict)
        self.assertIsNone(headers_dict)

    def test_build_http_security_dicts_hsts_only(self):
        """Test building dictionaries with only HSTS info."""
        hsts_dict, headers_dict = build_http_security_dicts(self.sample_hsts_info, None)

        self.assertIsNotNone(hsts_dict)
        self.assertIsNone(headers_dict)

    def test_build_http_security_dicts_headers_only(self):
        """Test building dictionaries with only security headers info."""
        hsts_dict, headers_dict = build_http_security_dicts(
            None, self.sample_headers_info
        )

        self.assertIsNone(hsts_dict)
        self.assertIsNotNone(headers_dict)


if __name__ == "__main__":
    unittest.main()
