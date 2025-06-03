from dataclasses import dataclass


@dataclass
class CLIOptions:
    single: str | None = None
    batch: str | None = None
    max_concurrent: int = 48
    ignore_cache: bool = (False,)
    routinator_url: str = "http://localhost:8323"
    output_dir: str = "results"
