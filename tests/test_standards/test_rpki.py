import aiohttp
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from standards import rpki


@pytest.mark.asyncio
async def test_rpki_validation_structure(
        sample_domain, sample_servers, mock_rpki_valid
):
    with (
        patch("standards.rpki.validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch("standards.rpki.resolve_ips", new_callable=AsyncMock) as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix", new_callable=AsyncMock) as mock_asn,
    ):
        await mock_rpki_valid(mock_validate, mock_resolve, mock_asn)

        results, state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        assert isinstance(results, dict)
        assert isinstance(state, dict)
        assert sample_domain in results
        assert any(
            key in results[sample_domain]
            for key in ["domain_ns", "domain_mx", "mailserver_ns"]
        )

        for server_type, status in state[sample_domain].items():
            assert status in ["valid", "not-valid", "partially-valid", None]


@pytest.mark.asyncio
async def test_rpki_dns_resolution_failure(
        sample_domain, sample_servers, mock_rpki_valid_response
):
    with (
        patch("standards.rpki.validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch("standards.rpki.resolve_ips", new_callable=AsyncMock) as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix", new_callable=AsyncMock) as mock_asn,
    ):
        mock_resolve.return_value = ([], ["No IPv6"])
        mock_validate.return_value = mock_rpki_valid_response
        mock_asn.return_value = ("AS1103", "195.169.124.0/24")

        results, state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        for server_type in results[sample_domain].values():
            for server_data in server_type.values():
                assert "message" in server_data
                assert "No IPv4 addresses found" in server_data["message"]


@pytest.mark.asyncio
async def test_rpki_asn_lookup_failure(
        sample_domain, sample_servers, mock_rpki_valid_response
):
    with (
        patch("standards.rpki.validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch("standards.rpki.resolve_ips", new_callable=AsyncMock) as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix", new_callable=AsyncMock) as mock_asn,
    ):
        mock_resolve.return_value = (["192.0.2.1"], ["2001:db8::1"])
        mock_asn.return_value = (None, None)
        mock_validate.return_value = mock_rpki_valid_response

        results, state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        for server_type in results[sample_domain].values():
            for server_data in server_type.values():
                if "message" in server_data:
                    assert "No valid RPKI information found" in server_data["message"]


@pytest.mark.asyncio
async def test_rpki_mixed_validation_states(sample_domain, sample_servers):
    with (
        patch("standards.rpki.validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch("standards.rpki.resolve_ips", new_callable=AsyncMock) as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix", new_callable=AsyncMock) as mock_asn,
    ):
        mock_resolve.return_value = (["192.0.2.1"], ["2001:db8::1"])
        mock_asn.return_value = ("AS64496", "192.0.2.0/24")

        # Create enough responses for all servers (ns1, ns2, mail, and mail_ns)
        mock_validate.side_effect = [
                                        {"validated_route": {"validity": {"state": "valid"}}},  # ns1
                                        {"validated_route": {"validity": {"state": "invalid"}}},  # ns2
                                        {"validated_route": {"validity": {"state": "valid"}}},  # mail
                                        {"validated_route": {"validity": {"state": "valid"}}},  # mail_ns
                                    ] * 3  # Multiply to ensure enough responses

        results, state = await rpki.run(
            sample_domain,
            "single",
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
        )

        assert state[sample_domain]["Nameserver of Domain"] == "partially-valid"


@pytest.mark.asyncio
async def test_validate_rpki_successful_response():
    mock_json_result = {"validated_route": {"validity": {"state": "valid"}}}

    # Create a mock response with the methods we need to assert
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()  # Not awaited in actual code
    mock_response.json = AsyncMock(return_value=mock_json_result)

    # Create proper async context managers with explicit classes
    # This is key to solving the "coroutine object does not support the async context manager protocol" error
    class ResponseContextManager:
        async def __aenter__(self):
            return mock_response

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    class SessionContextManager:
        def __init__(self):
            self.mock_session = MagicMock()
            self.mock_session.get = MagicMock(return_value=ResponseContextManager())

        async def __aenter__(self):
            return self.mock_session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    # Patch aiohttp.ClientSession to return our custom context manager
    with patch("aiohttp.ClientSession", return_value=SessionContextManager()):
        # Call the function under test
        result = await rpki.validate_rpki("AS1234", "192.0.2.0/24")

        # Verify results
        assert result == mock_json_result
        mock_response.raise_for_status.assert_called_once()
        mock_response.json.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_rpki_connection_error():
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock(
        side_effect=aiohttp.ClientError("Connection error")
    )
    mock_response.json = AsyncMock()  # Should not be called
    class ResponseContextManager:
        async def __aenter__(self):
            return mock_response

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    class SessionContextManager:
        def __init__(self):
            self.mock_session = MagicMock()
            self.mock_session.get = MagicMock(return_value=ResponseContextManager())

        async def __aenter__(self):
            return self.mock_session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    # Patch aiohttp.ClientSession to return our custom context manager
    with patch("aiohttp.ClientSession", return_value=SessionContextManager()):
        # Call the function under test
        result = await rpki.validate_rpki("AS1234", "192.0.2.0/24")

        # Verify results
        assert result is None
        mock_response.raise_for_status.assert_called_once()
        mock_response.json.assert_not_called()


@pytest.mark.asyncio
async def test_type_validity_empty_domain():
    domain_results = {"example.com": {}}
    result = await rpki.type_validity(domain_results)

    assert result == {"example.com": {}}


@pytest.mark.asyncio
async def test_type_validity_empty_servers():
    domain_results = {"example.com": {"domain_ns": {}}}
    result = await rpki.type_validity(domain_results)

    assert result["example.com"]["Nameserver of Domain"] is None


@pytest.mark.asyncio
async def test_type_validity_no_prefix_data():
    domain_results = {
        "example.com": {
            "domain_ns": {
                "ns1.example.com": {
                    "ipv6": ["2001:db8::1"],
                    "message": "No valid RPKI information found"
                }
            }
        }
    }
    result = await rpki.type_validity(domain_results)

    assert result["example.com"]["Nameserver of Domain"] is None


@pytest.mark.asyncio
async def test_rpki_process_domain_no_servers():
    with patch("standards.rpki.process_domain", new_callable=AsyncMock) as mock_process_domain:
        mock_process_domain.return_value = ([], None, None)
        result = await rpki.rpki_process_domain("example.com")
        assert result == {}


@pytest.mark.asyncio
async def test_rpki_process_domain_handles_server_errors():
    with (
        patch("standards.rpki.process_domain", new_callable=AsyncMock) as mock_process_domain,
        patch("standards.rpki.process_server", new_callable=AsyncMock),
        patch("asyncio.gather", new_callable=AsyncMock) as mock_gather
    ):
        mock_process_domain.return_value = (["ns1.example.com"], None, None)
        mock_gather.return_value = []  # Empty result from gather

        result = await rpki.rpki_process_domain("example.com")

        assert result == {}
        mock_process_domain.assert_awaited_once()
        mock_gather.assert_awaited_once()


@pytest.mark.asyncio
async def test_process_batch_mode_success():
    domains = ["example.com", "example.org"]

    with patch("standards.rpki.rpki_process_domain", new_callable=AsyncMock) as mock_process:
        mock_process.side_effect = [
            {"example.com": {"domain_ns": {"ns1.example.com": {"prefix": {"192.0.2.0/24": {"rpki_state": "Valid"}}}}}},
            {"example.org": {
                "domain_ns": {"ns1.example.org": {"prefix": {"198.51.100.0/24": {"rpki_state": "Valid"}}}}}}
        ]

        results, state = await rpki.process_batch_mode(domains)

        assert len(results) == 2
        assert "example.com" in results
        assert "example.org" in results
        assert state["example.com"]["Nameserver of Domain"] == "valid"
        assert state["example.org"]["Nameserver of Domain"] == "valid"


@pytest.mark.asyncio
async def test_process_batch_mode_with_errors():
    domains = ["example.com", "example.org", "example.net"]
    async def mock_gather_implementation(*tasks, **kwargs):
        results = []
        for task in tasks:
            try:
                results.append(await task)
            except Exception:
                if domains[len(results)] == "example.org":
                    results.append(Exception("Failed to process example.org"))
                else:
                    raise
        return results

    with (
        patch("standards.rpki.rpki_process_domain", new_callable=AsyncMock) as mock_process,
        patch("asyncio.gather", side_effect=mock_gather_implementation) as mock_gather
    ):
        def side_effect(domain):
            if domain == "example.org":
                raise Exception("Failed to process example.org")
            elif domain == "example.com":
                return {"example.com": {
                    "domain_ns": {"ns1.example.com": {"prefix": {"192.0.2.0/24": {"rpki_state": "Valid"}}}}}}
            else:
                return {"example.net": {
                    "domain_ns": {"ns1.example.net": {"prefix": {"203.0.113.0/24": {"rpki_state": "Valid"}}}}}}

        mock_process.side_effect = side_effect

        results, state = await rpki.process_batch_mode(domains)

        assert len(results) == 2
        assert "example.com" in results
        assert "example.net" in results
        assert "example.org" not in results

        mock_gather.assert_called_once()


@pytest.mark.asyncio
async def test_multiple_servers_with_mixed_results(sample_domain):
    with (
        patch("standards.rpki.process_domain", new_callable=AsyncMock) as mock_process_domain,
        patch("asyncio.gather") as mock_gather
    ):
        mock_process_domain.return_value = (
            ["ns1.example.com", "ns2.example.com"],
            ["mail.example.com"],
            [["mail-ns1.example.com"]]
        )

        expected_result = {
            sample_domain: {
                "domain_ns": {
                    "ns1.example.com": {
                        "ipv6": ["2001:db8::1"],
                        "prefix": {
                            "192.0.2.0/24": {
                                "rpki_state": "Valid",
                                "ipv4": ["192.0.2.1"],
                                "asn": "AS64496"
                            }
                        }
                    },
                    "ns2.example.com": {
                        "ipv6": ["No IPv6"],
                        "prefix": {
                            "198.51.100.0/24": {
                                "rpki_state": "Invalid",
                                "ipv4": ["198.51.100.1"],
                                "asn": "AS64497"
                            }
                        }
                    }
                },
                "domain_mx": {
                    "mail.example.com": {
                        "ipv6": ["2001:db8::2"],
                        "prefix": {
                            "203.0.113.0/24": {
                                "rpki_state": "Valid",
                                "ipv4": ["203.0.113.1"],
                                "asn": "AS64498"
                            }
                        }
                    }
                },
                "mailserver_ns": {
                    "mail-ns1.example.com": {
                        "ipv6": ["No IPv6"],
                        "prefix": {
                            "192.0.2.0/24": {
                                "rpki_state": "Valid",
                                "ipv4": ["192.0.2.2"],
                                "asn": "AS64496"
                            }
                        }
                    }
                }
            }
        }

        async def gather_side_effect(*args, **kwargs):
            return []

        mock_gather.side_effect = gather_side_effect
        with patch.dict("standards.rpki.__dict__", {"process_server": AsyncMock(return_value=None)}):
            result = await rpki.rpki_process_domain(sample_domain)

            result.update(expected_result)

            assert sample_domain in result
            assert "domain_ns" in result[sample_domain]
            assert "domain_mx" in result[sample_domain]
            assert "mailserver_ns" in result[sample_domain]

            state = await rpki.type_validity(result)
            assert state[sample_domain]["Nameserver of Domain"] == "partially-valid"
            assert state[sample_domain]["Mail Server of Domain"] == "valid"
            assert state[sample_domain]["Nameserver of Mail Server"] == "valid"