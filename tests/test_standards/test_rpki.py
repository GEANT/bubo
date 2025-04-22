import aiohttp
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from standards import rpki
from standards.rpki import (
    process_server,
    type_validity,
    rpki_process_domain,
    process_single_mode,
    process_batch_mode,
    run,
)
import asyncio


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
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
            routinator_url="http://localhost:8323",
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
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
            routinator_url="http://localhost:8323",
        )

        for server_type in results[sample_domain].values():
            for server_data in server_type.values():
                assert "message" in server_data
                assert "No IPv4 addresses found" in server_data["message"]


@pytest.mark.asyncio
async def test_rpki_mixed_validation_states(sample_domain, sample_servers):
    with (
        patch("standards.rpki.validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch("standards.rpki.resolve_ips", new_callable=AsyncMock) as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix", new_callable=AsyncMock) as mock_asn,
    ):
        mock_resolve.return_value = (["192.0.2.1"], ["2001:db8::1"])
        mock_asn.return_value = ("AS64496", "192.0.2.0/24")

        mock_validate.side_effect = [
            {"validated_route": {"validity": {"state": "valid"}}},
            {"validated_route": {"validity": {"state": "invalid"}}},
            {"validated_route": {"validity": {"state": "valid"}}},
            {"validated_route": {"validity": {"state": "valid"}}},
        ] * 3

        results, state = await rpki.run(
            sample_domain,
            sample_servers["domain_ns"],
            sample_servers["domain_mx"],
            sample_servers["mail_ns"],
            routinator_url="http://localhost:8323",
        )

        assert state[sample_domain]["Nameserver of Domain"] == "partially-valid"


@pytest.mark.asyncio
async def test_validate_rpki_successful_response():
    mock_json_result = {"validated_route": {"validity": {"state": "valid"}}}

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = AsyncMock(return_value=mock_json_result)

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

    with patch("aiohttp.ClientSession", return_value=SessionContextManager()):
        result = await rpki.validate_rpki(
            "AS1234", "192.0.2.0/24", "http://localhost:8323"
        )

        assert result == mock_json_result
        mock_response.raise_for_status.assert_called_once()
        mock_response.json.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_rpki_connection_error():
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock(
        side_effect=aiohttp.ClientError("Connection error")
    )
    mock_response.json = AsyncMock()

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

    with patch("aiohttp.ClientSession", return_value=SessionContextManager()):
        result = await rpki.validate_rpki(
            "AS1234", "192.0.2.0/24", "http://localhost:8323"
        )

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
                    "message": "No valid RPKI information found",
                }
            }
        }
    }
    result = await rpki.type_validity(domain_results)

    assert result["example.com"]["Nameserver of Domain"] is None


@pytest.mark.asyncio
async def test_rpki_process_domain_no_servers():
    with (
        patch(
            "standards.rpki.process_domain", new_callable=AsyncMock
        ) as mock_process_domain,
        patch(
            "standards.rpki.process_server", new_callable=AsyncMock
        ) as mock_process_server,
    ):
        mock_process_domain.return_value = ([], None, None)
        mock_process_server.return_value = None

        result = await rpki.rpki_process_domain("example.com")
        assert result == {}


@pytest.mark.asyncio
async def test_process_batch_mode_success():
    domains = ["example.com", "example.org"]

    with patch(
        "standards.rpki.rpki_process_domain", new_callable=AsyncMock
    ) as mock_process:
        mock_process.side_effect = [
            {
                "example.com": {
                    "domain_ns": {
                        "ns1.example.com": {
                            "prefix": {"192.0.2.0/24": {"rpki_state": "Valid"}}
                        }
                    }
                }
            },
            {
                "example.org": {
                    "domain_ns": {
                        "ns1.example.org": {
                            "prefix": {"198.51.100.0/24": {"rpki_state": "Valid"}}
                        }
                    }
                }
            },
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
        patch(
            "standards.rpki.rpki_process_domain", new_callable=AsyncMock
        ) as mock_process,
        patch("asyncio.gather", side_effect=mock_gather_implementation) as mock_gather,
    ):

        def side_effect(domain):
            if domain == "example.org":
                raise Exception("Failed to process example.org")
            elif domain == "example.com":
                return {
                    "example.com": {
                        "domain_ns": {
                            "ns1.example.com": {
                                "prefix": {"192.0.2.0/24": {"rpki_state": "Valid"}}
                            }
                        }
                    }
                }
            else:
                return {
                    "example.net": {
                        "domain_ns": {
                            "ns1.example.net": {
                                "prefix": {"203.0.113.0/24": {"rpki_state": "Valid"}}
                            }
                        }
                    }
                }

        mock_process.side_effect = side_effect

        results, state = await rpki.process_batch_mode(domains)

        assert len(results) == 2
        assert "example.com" in results
        assert "example.net" in results
        assert "example.org" not in results

        mock_gather.assert_called_once()


@pytest.fixture
def event_loop():
    """Create and provide an event loop for async tests."""
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


@pytest.mark.asyncio
async def test_process_server_no_ipv4():
    """Test process_server when no IPv4 addresses are found."""
    with patch("standards.rpki.resolve_ips") as mock_resolve:
        mock_resolve.return_value = ([], ["2001:db8::1"])

        server = "test.example.com"
        domain = "example.com"
        results = {}
        stype = "domain_ns"
        routinator_url = "http://localhost:8323"

        await process_server(server, domain, results, stype, routinator_url)

        assert domain in results
        assert stype in results[domain]
        assert server in results[domain][stype]
        assert results[domain][stype][server]["message"] == "No IPv4 addresses found"
        assert results[domain][stype][server]["ipv6"] == ["2001:db8::1"]


@pytest.mark.asyncio
async def test_process_server_no_asn_prefix():
    """Test process_server when ASN and prefix retrieval fails."""
    with (
        patch("standards.rpki.resolve_ips") as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix") as mock_get_asn,
    ):
        mock_resolve.return_value = (["192.168.1.1"], [])
        mock_get_asn.return_value = (None, None)

        server = "test.example.com"
        domain = "example.com"
        results = {}
        stype = "domain_ns"
        routinator_url = "http://localhost:8323"

        await process_server(server, domain, results, stype, routinator_url)

        assert domain in results
        assert stype in results[domain]
        assert server in results[domain][stype]
        assert (
            results[domain][stype][server]["message"]
            == "No valid RPKI information found"
        )


@pytest.mark.asyncio
async def test_process_server_rpki_validation_failure():
    """Test process_server when RPKI validation fails."""
    with (
        patch("standards.rpki.resolve_ips") as mock_resolve,
        patch("standards.rpki.get_asn_and_prefix") as mock_get_asn,
        patch("standards.rpki.validate_rpki") as mock_validate,
    ):
        mock_resolve.return_value = (["192.168.1.1"], [])
        mock_get_asn.return_value = ("AS12345", "192.168.1.0/24")
        mock_validate.return_value = None

        server = "test.example.com"
        domain = "example.com"
        results = {}
        stype = "domain_ns"
        routinator_url = "http://localhost:8323"

        await process_server(server, domain, results, stype, routinator_url)

        assert domain in results
        assert stype in results[domain]
        assert server in results[domain][stype]
        assert (
            results[domain][stype][server]["message"]
            == "No valid RPKI information found"
        )


@pytest.mark.asyncio
async def test_type_validity_no_servers():
    """Test type_validity when no servers are found for a type."""
    with patch("standards.rpki.translate_server_type") as mock_translate:
        mock_translate.return_value = "Domain Nameservers"

        domain_results = {"example.com": {"domain_ns": {}}}

        result = await type_validity(domain_results)

        assert "example.com" in result
        assert "Domain Nameservers" in result["example.com"]
        assert result["example.com"]["Domain Nameservers"] is None


@pytest.mark.asyncio
async def test_rpki_process_domain_no_nameservers():
    """Test rpki_process_domain when no domain nameservers exist."""
    with (
        patch("standards.rpki.process_domain") as mock_process_domain,
        patch("standards.rpki.process_server") as mock_process_server,
    ):
        mock_process_domain.return_value = (
            [],
            ["mail.example.com"],
            [["ns1.mail.example.com"]],
        )

        async def side_effect(
            server, domain, results, stype, routinator_url="http://localhost:8323"
        ):
            if domain not in results:
                results[domain] = {}
            if stype not in results[domain]:
                results[domain][stype] = {}
            results[domain][stype][server] = {"test": "data"}

        mock_process_server.side_effect = side_effect

        result = await rpki_process_domain("example.com")

        assert "example.com" in result
        assert "domain_ns" not in result["example.com"]
        assert "domain_mx" in result["example.com"]
        assert "mailserver_ns" in result["example.com"]


@pytest.mark.asyncio
async def test_rpki_process_domain_no_mailservers():
    """Test rpki_process_domain when no mail servers exist."""
    with (
        patch("standards.rpki.process_domain") as mock_process_domain,
        patch("standards.rpki.process_server") as mock_process_server,
    ):
        mock_process_domain.return_value = (
            ["ns1.example.com"],
            [],
            [["ns1.mail.example.com"]],
        )

        async def side_effect(
            server, domain, results, stype, routinator_url="http://localhost:8323"
        ):
            if domain not in results:
                results[domain] = {}
            if stype not in results[domain]:
                results[domain][stype] = {}
            results[domain][stype][server] = {"test": "data"}

        mock_process_server.side_effect = side_effect

        result = await rpki_process_domain("example.com")

        assert "example.com" in result
        assert "domain_ns" in result["example.com"]
        assert "domain_mx" not in result["example.com"]
        assert "mailserver_ns" in result["example.com"]


@pytest.mark.asyncio
async def test_rpki_process_domain_no_mail_nameservers():
    """Test rpki_process_domain when no mail nameservers exist."""
    with (
        patch("standards.rpki.process_domain") as mock_process_domain,
        patch("standards.rpki.process_server") as mock_process_server,
    ):
        mock_process_domain.return_value = (
            ["ns1.example.com"],
            ["mail.example.com"],
            [],
        )

        async def side_effect(
            server, domain, results, stype, routinator_url="http://localhost:8323"
        ):
            if domain not in results:
                results[domain] = {}
            if stype not in results[domain]:
                results[domain][stype] = {}
            results[domain][stype][server] = {"test": "data"}

        mock_process_server.side_effect = side_effect

        result = await rpki_process_domain("example.com")

        assert "example.com" in result
        assert "domain_ns" in result["example.com"]
        assert "domain_mx" in result["example.com"]
        assert "mailserver_ns" not in result["example.com"]


@pytest.mark.asyncio
async def test_rpki_process_domain_no_results():
    """Test rpki_process_domain when no results are found."""
    with (
        patch("standards.rpki.process_domain") as mock_process_domain,
        patch("standards.rpki.process_server") as mock_process_server,
    ):
        mock_process_domain.return_value = (
            ["ns1.example.com"],
            ["mail.example.com"],
            [["ns1.mail.example.com"]],
        )

        mock_process_server.return_value = None

        result = await rpki_process_domain("example.com")

        assert result == {}


@pytest.mark.asyncio
async def test_process_single_mode_with_results():
    """Test process_single_mode when results are found."""
    with (
        patch("standards.rpki.rpki_process_domain") as mock_rpki,
        patch("standards.rpki.type_validity") as mock_validity,
    ):
        test_results = {"example.com": {"domain_ns": {"ns1.example.com": {}}}}
        test_state = {"example.com": {"Domain Nameservers": "valid"}}

        mock_rpki.return_value = test_results
        mock_validity.return_value = test_state

        results, state = await process_single_mode("example.com")

        assert results == test_results
        assert state == test_state
        mock_rpki.assert_called_once_with("example.com")
        mock_validity.assert_called_once_with(test_results)


@pytest.mark.asyncio
async def test_process_single_mode_no_results():
    """Test process_single_mode when no results are found."""
    with patch("standards.rpki.rpki_process_domain") as mock_rpki:
        mock_rpki.return_value = {}

        results, state = await process_single_mode("example.com")

        assert results == {}
        assert state == {}


@pytest.mark.asyncio
async def test_process_batch_mode_no_results():
    """Test process_batch_mode when no results are found."""
    with patch("standards.rpki.rpki_process_domain") as mock_rpki:
        mock_rpki.return_value = {}

        results, state = await process_batch_mode(["example.com"])

        assert results == {}
        assert state == {}


@pytest.mark.asyncio
async def test_run_no_domain_ns():
    """Test run when no domain nameservers are provided."""
    with (
        patch("standards.rpki.process_server") as mock_process_server,
        patch("standards.rpki.type_validity") as mock_validity,
    ):

        async def side_effect(server, domain, results, stype, routinator_url):
            if domain not in results:
                results[domain] = {}
            if stype not in results[domain]:
                results[domain][stype] = {}
            results[domain][stype][server] = {"test": "data"}

        mock_process_server.side_effect = side_effect
        mock_validity.return_value = {"example.com": {"Mail Servers": "valid"}}

        results, state = await run(
            "example.com",
            domain_ns=None,
            domain_mx=["mail.example.com"],
            mail_ns=[["ns1.mail.example.com"]],
            routinator_url="http://localhost:8323",
        )

        assert "example.com" in results
        assert "domain_ns" not in results["example.com"]
        assert "domain_mx" in results["example.com"]
        assert "mailserver_ns" in results["example.com"]


@pytest.mark.asyncio
async def test_run_no_domain_mx():
    """Test run when no mail servers are provided."""
    with (
        patch("standards.rpki.process_server") as mock_process_server,
        patch("standards.rpki.type_validity") as mock_validity,
    ):

        async def side_effect(server, domain, results, stype, routinator_url):
            if domain not in results:
                results[domain] = {}
            if stype not in results[domain]:
                results[domain][stype] = {}
            results[domain][stype][server] = {"test": "data"}

        mock_process_server.side_effect = side_effect
        mock_validity.return_value = {"example.com": {"Domain Nameservers": "valid"}}

        results, state = await run(
            "example.com",
            domain_ns=["ns1.example.com"],
            domain_mx=None,
            mail_ns=[["ns1.mail.example.com"]],
            routinator_url="http://localhost:8323",
        )

        assert "example.com" in results
        assert "domain_ns" in results["example.com"]
        assert "domain_mx" not in results["example.com"]
        assert "mailserver_ns" in results["example.com"]


@pytest.mark.asyncio
async def test_run_no_mail_ns():
    """Test run when no mail nameservers are provided."""
    with (
        patch("standards.rpki.process_server") as mock_process_server,
        patch("standards.rpki.type_validity") as mock_validity,
    ):

        async def side_effect(server, domain, results, stype, routinator_url):
            if domain not in results:
                results[domain] = {}
            if stype not in results[domain]:
                results[domain][stype] = {}
            results[domain][stype][server] = {"test": "data"}

        mock_process_server.side_effect = side_effect
        mock_validity.return_value = {"example.com": {"Domain Nameservers": "valid"}}

        results, state = await run(
            "example.com",
            domain_ns=["ns1.example.com"],
            domain_mx=["mail.example.com"],
            mail_ns=None,
            routinator_url="http://localhost:8323",
        )

        assert "example.com" in results
        assert "domain_ns" in results["example.com"]
        assert "domain_mx" in results["example.com"]
        assert "mailserver_ns" not in results["example.com"]
