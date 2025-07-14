import os
from pathlib import Path


def get_cache_directory() -> Path:
    """Get the cache directory for IANA data.

    Returns:
        Path to the cache directory (bubo/cache/iana_data/)
    """
    current_file = Path(__file__).resolve()
    project_root = current_file.parent.parent.parent
    cache_dir = project_root / "cache" / "iana_data"

    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_iana_csv_path() -> Path:
    """Get the path to the IANA CSV file.

    Returns:
        Path to the IANA TLS parameters CSV file
    """
    env_path = os.environ.get("IANA_CIPHERS_CSV")
    if env_path:
        return Path(env_path)

    return get_cache_directory() / "iana_tls_parameters.csv"
