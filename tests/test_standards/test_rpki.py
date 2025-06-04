import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bubo.standards import rpki
from bubo.standards.rpki import (
    RPKIValidator,
    ValidatorState,
    _get_validator_instance,
    run,
    type_validity,
)


@pytest.fixture
def mock_validator():
    """Create a mock validator instance for testing"""
    return RPKIValidator("http://localhost:8323")


@pytest.mark.asyncio
async def test_rpki_validation_structure(
        sample_domain, sample_servers, mock_rpki_valid
):
    with (
        patch.object(RPKIValidator, "validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch(
            "bubo.standards.rpki.resolve_ips", new_callable=AsyncMock
        ) as mock_resolve,
        patch(
            "bubo.standards.rpki.get_asn_and_prefix", new_callable=AsyncMock
        ) as mock_asn,
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

        for _server_type, status in state[sample_domain].items():
            assert status in ["valid", "not-valid", "partially-valid", None]


@pytest.mark.asyncio
async def test_rpki_dns_resolution_failure(
        sample_domain, sample_servers, mock_rpki_valid_response
):
    with (
        patch.object(RPKIValidator, "validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch(
            "bubo.standards.rpki.resolve_ips", new_callable=AsyncMock
        ) as mock_resolve,
        patch(
            "bubo.standards.rpki.get_asn_and_prefix", new_callable=AsyncMock
        ) as mock_asn,
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
        patch.object(RPKIValidator, "validate_rpki", new_callable=AsyncMock) as mock_validate,
        patch(
            "bubo.standards.rpki.resolve_ips", new_callable=AsyncMock
        ) as mock_resolve,
        patch(
            "bubo.standards.rpki.get_asn_and_prefix", new_callable=AsyncMock
        ) as mock_asn,
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
async def test_validator_instance_caching():
    """Test that validator instances are cached per URL"""
    url1 = "http://localhost:8323"
    url2 = "http://localhost:8324"

    rpki._validator_instances.clear()

    validator1a = _get_validator_instance(url1)
    validator1b = _get_validator_instance(url1)

    validator2 = _get_validator_instance(url2)

    assert validator1a is validator1b
    assert validator1a.routinator_url == url1

    assert validator1a is not validator2
    assert validator2.routinator_url == url2

    assert len(rpki._validator_instances) == 2
    assert rpki._validator_instances[url1] is validator1a
    assert rpki._validator_instances[url2] is validator2


@pytest.mark.asyncio
async def test_validator_state_management():
    """Test validator state management"""
    state = ValidatorState(timeout_threshold=3)

    assert not state.is_down
    assert state.timeout_count == 0

    state.increment_timeout()
    assert state.timeout_count == 1
    assert not state.is_down

    state.increment_timeout()
    state.increment_timeout()
    assert state.timeout_count == 3
    assert state.is_down

    state.reset_timeouts()
    assert state.timeout_count == 0

    state2 = ValidatorState()
    state2.mark_down()
    assert state2.is_down


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

    validator = RPKIValidator("http://localhost:8323")

    with patch("aiohttp.ClientSession", return_value=SessionContextManager()):
        result = await validator.validate_rpki("AS1234", "192.0.2.0/24")

        assert result == mock_json_result
        mock_response.raise_for_status.assert_called_once()
        mock_response.json.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_rpki_connection_error():
    from aiohttp import ClientConnectorError
    from unittest.mock import patch, MagicMock

    connection_key = MagicMock()
    os_error = OSError("Connection refused")
    connector_error = ClientConnectorError(connection_key, os_error)

    class SessionContextManager:
        def __init__(self):
            self.mock_session = MagicMock()

            self.mock_session.get = MagicMock(side_effect=connector_error)

        async def __aenter__(self):
            return self.mock_session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    validator = RPKIValidator("http://localhost:8323")

    with patch("aiohttp.ClientSession", return_value=SessionContextManager()):
        result = await validator.validate_rpki("AS1234", "192.0.2.0/24")

        assert result is None
        assert validator.state.is_down


@pytest.mark.asyncio
async def test_validate_rpki_timeout_error():
    """Test timeout handling and marking validator as down"""
    validator = RPKIValidator("http://localhost:8323", timeout_threshold=2)

    class SessionContextManager:
        def __init__(self):
            self.mock_session = MagicMock()
            self.mock_session.get = MagicMock(side_effect=asyncio.TimeoutError())

        async def __aenter__(self):
            return self.mock_session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch("aiohttp.ClientSession", return_value=SessionContextManager()):
        result1 = await validator.validate_rpki("AS1234", "192.0.2.0/24")
        assert result1 is None
        assert validator.state.timeout_count == 1
        assert not validator.state.is_down

        result2 = await validator.validate_rpki("AS1234", "192.0.2.0/24")
        assert result2 is None
        assert validator.state.timeout_count == 2
        assert validator.state.is_down


@pytest.mark.asyncio
async def test_validate_rpki_validator_down():
    """Test that validation is skipped when validator is marked as down"""
    validator = RPKIValidator("http://localhost:8323")
    validator.state.mark_down()

    result = await validator.validate_rpki("AS1234", "192.0.2.0/24")
    assert result is None


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
async def test_process_server_no_ipv4():
    """Test process_server when no IPv4 addresses are found."""
    validator = RPKIValidator("http://localhost:8323")

    with patch("bubo.standards.rpki.resolve_ips") as mock_resolve:
        mock_resolve.return_value = ([], ["2001:db8::1"])

        server = "test.example.com"
        domain = "example.com"
        results = {}
        stype = "domain_ns"

        await validator.process_server(server, domain, results, stype)

        assert domain in results
        assert stype in results[domain]
        assert server in results[domain][stype]
        assert results[domain][stype][server]["message"] == "No IPv4 addresses found"
        assert results[domain][stype][server]["ipv6"] == ["2001:db8::1"]


@pytest.mark.asyncio
async def test_process_server_no_asn_prefix():
    """Test process_server when ASN and prefix retrieval fails."""
    validator = RPKIValidator("http://localhost:8323")

    with (
        patch("bubo.standards.rpki.resolve_ips") as mock_resolve,
        patch("bubo.standards.rpki.get_asn_and_prefix") as mock_get_asn,
    ):
        mock_resolve.return_value = (["192.168.1.1"], [])
        mock_get_asn.return_value = (None, None)

        server = "test.example.com"
        domain = "example.com"
        results = {}
        stype = "domain_ns"

        await validator.process_server(server, domain, results, stype)

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
    validator = RPKIValidator("http://localhost:8323")

    with (
        patch("bubo.standards.rpki.resolve_ips") as mock_resolve,
        patch("bubo.standards.rpki.get_asn_and_prefix") as mock_get_asn,
        patch.object(validator, "validate_rpki") as mock_validate,
    ):
        mock_resolve.return_value = (["192.168.1.1"], [])
        mock_get_asn.return_value = ("AS12345", "192.168.1.0/24")
        mock_validate.return_value = None

        server = "test.example.com"
        domain = "example.com"
        results = {}
        stype = "domain_ns"

        await validator.process_server(server, domain, results, stype)

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
    with patch("bubo.standards.rpki.translate_server_type") as mock_translate:
        mock_translate.return_value = "Domain Nameservers"

        domain_results = {"example.com": {"domain_ns": {}}}

        result = await type_validity(domain_results)

        assert "example.com" in result
        assert "Domain Nameservers" in result["example.com"]
        assert result["example.com"]["Domain Nameservers"] is None


@pytest.mark.asyncio
async def test_run_no_domain_ns():
    """Test run when no domain nameservers are provided."""
    with (
        patch.object(RPKIValidator, "process_server") as mock_process_server,
        patch("bubo.standards.rpki.type_validity") as mock_validity,
    ):

        async def side_effect(server, domain, results, stype):
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
        patch.object(RPKIValidator, "process_server") as mock_process_server,
        patch("bubo.standards.rpki.type_validity") as mock_validity,
    ):

        async def side_effect(server, domain, results, stype):
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
        patch.object(RPKIValidator, "process_server") as mock_process_server,
        patch("bubo.standards.rpki.type_validity") as mock_validity,
    ):

        async def side_effect(server, domain, results, stype):
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


@pytest.mark.asyncio
async def test_run_validator_down():
    """Test run when validator is marked as down"""

    rpki._validator_instances.clear()
    validator = RPKIValidator("http://localhost:8323")
    validator.state.mark_down()
    rpki._validator_instances["http://localhost:8323"] = validator

    results, state = await run(
        "example.com",
        domain_ns=["ns1.example.com"],
        domain_mx=["mail.example.com"],
        mail_ns=[["ns1.mail.example.com"]],
        routinator_url="http://localhost:8323",
    )

    assert results == {}
    assert state == {
        "example.com": {"rpki_state": "unknown", "message": "RPKI validator unavailable"}
    }


@pytest.mark.asyncio
async def test_shared_state_across_calls():
    """Test that multiple calls to run() with same URL share validator state"""
    from aiohttp import ClientConnectorError
    from unittest.mock import patch, MagicMock

    rpki._validator_instances.clear()

    connection_key = MagicMock()
    os_error = OSError("Connection failed")
    connector_error = ClientConnectorError(connection_key, os_error)

    class SessionContextManager:
        def __init__(self):
            self.mock_session = MagicMock()

            self.mock_session.get = MagicMock(side_effect=connector_error)

        async def __aenter__(self):
            return self.mock_session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch("aiohttp.ClientSession", return_value=SessionContextManager()):
        with patch("bubo.standards.rpki.resolve_ips", return_value=(["192.0.2.1"], [])):
            with patch("bubo.standards.rpki.get_asn_and_prefix", return_value=("AS1234", "192.0.2.0/24")):
                results1, state1 = await run(
                    "example1.com",
                    domain_ns=["ns1.example1.com"],
                    domain_mx=[],
                    mail_ns=[],
                    routinator_url="http://localhost:8323",
                )

                results2, state2 = await run(
                    "example2.com",
                    domain_ns=["ns1.example2.com"],
                    domain_mx=[],
                    mail_ns=[],
                    routinator_url="http://localhost:8323",
                )

                assert results1 == {}
                assert state1 == {
                    "example1.com": {"rpki_state": "unknown", "message": "RPKI validator unavailable"}
                }
                assert results2 == {}
                assert state2 == {
                    "example2.com": {"rpki_state": "unknown", "message": "RPKI validator unavailable"}
                }


@pytest.fixture
def event_loop():
    """Create and provide an event loop for async tests."""
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


def test_validator_state_initialization():
    """Test ValidatorState initialization"""
    state = ValidatorState()
    assert not state.is_down
    assert state.timeout_count == 0
    assert state.timeout_threshold == 3

    custom_state = ValidatorState(timeout_threshold=5)
    assert custom_state.timeout_threshold == 5


def test_rpki_validator_initialization():
    """Test RPKIValidator initialization"""
    url = "http://test.example.com"
    validator = RPKIValidator(url, timeout_threshold=5)

    assert validator.routinator_url == url
    assert validator.state.timeout_threshold == 5
    assert not validator.state.is_down
