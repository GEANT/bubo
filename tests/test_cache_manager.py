# tests/test_cache_manager.py

import json
import os
from datetime import datetime, timedelta

import pytest

from core.cache_manager.cache_manager import DomainResultsCache


@pytest.fixture
def cache_dir(tmp_path):
    return tmp_path / "cache_manager"


@pytest.fixture
def sample_results():
    return {
        "validations": {
            "RPKI": {
                "results": {"domain.com": {"status": True}},
                "state": {"domain.com": {"Nameserver of Domain": "valid"}},
            },
            "DANE": {
                "results": {"domain.com": {"tlsa_records": []}},
                "state": {"domain.com": {"Nameserver of Domain": "not-valid"}},
            },
            "DNSSEC": {
                "results": {"domain.com": {"dnssec_status": {"is_signed": True}}},
                "state": {"domain.com": {"DNSSEC": True}},
            },
        },
        "domain_metadata": {"domain.com": {"country": "US", "institution": "Example"}},
    }


@pytest.fixture
def cache_manager(cache_dir):
    return DomainResultsCache(cache_dir=str(cache_dir))


def test_cache_initialization(cache_dir, cache_manager):
    assert os.path.exists(cache_dir)
    assert cache_manager.cache_duration == timedelta(days=1)


def test_cache_path_sanitization(cache_manager):
    domain = "test/domain.com"
    sanitized_path = cache_manager._get_cache_path(domain)
    assert "/" not in os.path.basename(sanitized_path)
    assert "_" in os.path.basename(sanitized_path)


def test_save_and_get_results(cache_manager, sample_results):
    domain = "domain.com"
    cache_manager.save_results(domain, sample_results)
    cached_results = cache_manager.get_results(domain, ignore_cache=False)
    assert cached_results is not None
    assert (
        cached_results["validations"]["RPKI"]["state"]["domain.com"][
            "Nameserver of Domain"
        ]
        == "valid"
    )

    # Pattern matching for structure
    assert all(
        standard in cached_results["validations"]
        for standard in ["RPKI", "DANE", "DNSSEC"]
    )
    assert "domain_metadata" in cached_results
    assert isinstance(
        cached_results["validations"]["DNSSEC"]["state"][domain]["DNSSEC"], bool
    )


def test_cache_expiration(cache_manager, sample_results):
    domain = "domain.com"

    expired_timestamp = datetime.now() - timedelta(days=2)
    cache_data = {"timestamp": expired_timestamp.isoformat(), "results": sample_results}
    cache_path = cache_manager._get_cache_path(domain)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(cache_data, f)

    cached_results = cache_manager.get_results(domain)
    assert cached_results is None


def test_ignore_cache_flag(cache_manager, sample_results):
    domain = "domain.com"
    cache_manager.save_results(domain, sample_results)

    # Should return None when ignore_cache is True
    cached_results = cache_manager.get_results(domain, ignore_cache=True)
    assert cached_results is None

    # Should return results when ignore_cache is False
    cached_results = cache_manager.get_results(domain, ignore_cache=False)
    assert cached_results is not None


def test_cache_duration_custom(cache_dir):
    custom_duration = timedelta(hours=12)
    cache_manager = DomainResultsCache(
        cache_dir=str(cache_dir), cache_duration=custom_duration
    )
    assert cache_manager.cache_duration == custom_duration


def test_invalid_cache_data(cache_manager, sample_results):
    domain = "domain.com"
    cache_path = cache_manager._get_cache_path(domain)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w") as f:
        f.write("invalid json data")

    cached_results = cache_manager.get_results(domain)
    assert cached_results is None


def test_multiple_domains(cache_manager, sample_results):
    domains = ["domain1.com", "domain2.com", "domain3.com"]

    for domain in domains:
        modified_results = sample_results.copy()
        modified_results["domain_metadata"] = {
            domain: {"country": "US", "institution": "Example"}
        }
        cache_manager.save_results(domain, modified_results)

    for domain in domains:
        cached_results = cache_manager.get_results(domain)
        assert cached_results is not None
        assert domain in cached_results["domain_metadata"]


def test_cache_update(cache_manager, sample_results):
    domain = "domain.com"
    cache_manager.save_results(domain, sample_results)
    updated_results = sample_results.copy()
    updated_results["validations"]["RPKI"]["state"][domain]["Nameserver of Domain"] = (
        "not-valid"
    )
    cache_manager.save_results(domain, updated_results)
    cached_results = cache_manager.get_results(domain)
    assert (
        cached_results["validations"]["RPKI"]["state"][domain]["Nameserver of Domain"]
        == "not-valid"
    )
