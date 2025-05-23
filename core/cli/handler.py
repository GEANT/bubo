import argparse
import os

from core.cli.models import CLIOptions
from core.validators.sanitizer import sanitize_domain
from core.io.file_processor import sanitize_file_path


class CLIHandler:
    """Handles CLI argument parsing and validation with improved security"""

    @staticmethod
    def parse_args() -> CLIOptions:
        parser = argparse.ArgumentParser(
            description="Internet and Email Compliance Checker",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )

        input_group = parser.add_mutually_exclusive_group(required=True)
        input_group.add_argument("--single", "-d", help="Single domain to validate")
        input_group.add_argument(
            "--batch", "-b", help="Batch mode - Path to file containing domains"
        )

        parser.add_argument(
            "--max-concurrent",
            "-mc",
            type=int,
            default=48,
            help="Maximum concurrent validations",
        )

        parser.add_argument(
            "--ignore-cache", "-ic", action="store_true", help="Force fresh validation"
        )

        parser.add_argument(
            "--routinator-url",
            "-ru",
            help="URL of the Routinator RPKI validator service (default from ROUTINATOR_URL env or http://localhost:8323)",
        )

        parser.add_argument(
            "--output-dir",
            "-o",
            help="Directory for storing reports (default: results)",
            default="results",
        )

        args = parser.parse_args()

        if args.single:
            args.single = sanitize_domain(args.single)
        if args.batch:
            args.batch = sanitize_file_path(args.batch)

        if args.max_concurrent < 1 or args.max_concurrent > 100:
            args.max_concurrent = 48

        if not args.routinator_url:
            args.routinator_url = os.getenv("ROUTINATOR_URL", "http://localhost:8323")
        else:
            if not args.routinator_url.startswith(("http://", "https://")):
                args.routinator_url = "http://" + args.routinator_url

        if args.output_dir:
            args.output_dir = os.path.abspath(args.output_dir)

        return CLIOptions(**vars(args))
