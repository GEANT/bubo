# core/report/generator.py

import os
from datetime import datetime
from shutil import copytree
from typing import Any

from jinja2 import Environment, FileSystemLoader

from core.logging.logger import setup_logger
from core.report.json_utils import convert_sets_to_lists, json_dumps
from core.report.statistics import generate_statistics_report

logger = setup_logger(__name__)


def setup_report_directories(
    base_dir: str, output_dir_name: str = "results"
) -> tuple[str, str]:
    """
    Create output directories for reports.

    Args:
        base_dir: Base directory of the project
        output_dir_name: Name or path of the output directory (default: "results")

    Returns:
        Tuple containing results directory path and dated output directory path
    """
    if os.path.isabs(output_dir_name):
        results_dir = output_dir_name
    else:
        results_dir = os.path.join(base_dir, output_dir_name)

    date_dir = os.path.join(results_dir, datetime.now().strftime("%Y-%m-%d"))

    os.makedirs(date_dir, exist_ok=True)

    return results_dir, date_dir


def generate_file_paths(
    results_dir: str, output_dir: str, output_file: str
) -> dict[str, str]:
    """
    Generate all necessary file paths for reports.

    Args:
        results_dir: Main results directory
        output_dir: Directory for dated output
        output_file: Base filename for the output file

    Returns:
        Dictionary containing all file paths
    """
    paths = {
        # HTML paths
        "report_html_path": os.path.join(output_dir, output_file),
        "report_final_html_path": os.path.join(results_dir, "index.html"),
        "stats_html_path": os.path.join(
            output_dir, output_file.replace(".html", "_stats.html")
        ),
        "stats_final_html_path": os.path.join(results_dir, "statistics.html"),
        # JSON paths
        "report_json_path": os.path.join(
            output_dir, output_file.replace(".html", ".json")
        ),
        "report_final_json_path": os.path.join(results_dir, "index.json"),
        "stats_json_path": os.path.join(
            output_dir, output_file.replace(".html", "_stats.json")
        ),
        "stats_final_json_path": os.path.join(results_dir, "statistics.json"),
    }

    return paths


def write_json_report(
    serializable_results: dict[str, Any], file_paths: dict[str, str]
) -> None:
    """
    Write JSON reports to both dated and main locations.

    Args:
        serializable_results: Processed validation results
        file_paths: Dictionary with file paths
    """
    try:
        with open(file_paths["report_json_path"], "w") as file:
            file.write(json_dumps(serializable_results, indent=2, sort_keys=True))
        logger.debug(f"Report json generated: {file_paths['report_json_path']}")

        with open(file_paths["report_final_json_path"], "w") as file:
            file.write(json_dumps(serializable_results, indent=2, sort_keys=True))
    except OSError as e:
        logger.error(
            f"Error writing report json to {file_paths['report_json_path']}: {e}"
        )


def copy_asset_directories(base_dir: str, output_dir: str, results_dir: str) -> None:
    """
    Copy CSS and JS asset directories to the output locations.

    Args:
        base_dir: Base directory of the project
        output_dir: Directory for dated output
        results_dir: Main results directory
    """
    for asset_type in ["css", "js"]:
        src_dir = os.path.join(base_dir, "templates", asset_type)
        dst_dir = os.path.join(output_dir, asset_type)
        dst_results_dir = os.path.join(results_dir, asset_type)

        try:
            copytree(src_dir, dst_dir, dirs_exist_ok=True)
            copytree(src_dir, dst_results_dir, dirs_exist_ok=True)
        except OSError as e:
            logger.error(f"Error copying directory {src_dir} to {dst_dir}: {e}")


def render_main_report(
    serializable_results: dict[str, Any],
    file_paths: dict[str, str],
    template_env: Environment,
) -> None:
    """
    Render and write the main HTML report to both dated and main locations.

    Args:
        serializable_results: Processed validation results
        file_paths: Dictionary with file paths
        template_env: Jinja2 Environment with templates loaded
    """
    template = template_env.get_template("index.html")
    rendered_html = template.render(
        validations=serializable_results["validations"],
        domain_metadata=serializable_results["domain_metadata"],
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        year=datetime.now().year,
        domains=list(serializable_results["validations"]["RPKI"]["state"].keys()),
    )

    # Write to dated location
    try:
        with open(file_paths["report_html_path"], "w") as file:
            file.write(rendered_html)
        logger.info(f"Report generated: {file_paths['report_html_path']}")
    except OSError as e:
        logger.error(f"Error writing report to {file_paths['report_html_path']}: {e}")

    # Write to main location
    try:
        with open(file_paths["report_final_html_path"], "w") as file:
            file.write(rendered_html)
    except OSError as e:
        logger.error(
            f"Error writing report to {file_paths['report_final_html_path']}: {e}"
        )


async def generate_html_report(
    results: dict[str, Any], output_file: str, output_dir: str = "results"
) -> None:
    """
    Generate HTML reports from validation results.

    Creates both the main report and statistics page.

    Args:
        results: Validation results dictionary
        output_file: Base filename for the output file
        output_dir: Directory to store the reports (default: "results")
    """
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    template_dir = os.path.join(base_dir, "templates")

    results_dir, output_dir_dated = setup_report_directories(base_dir, output_dir)

    file_paths = generate_file_paths(results_dir, output_dir_dated, output_file)

    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    serializable_results = convert_sets_to_lists(results)

    write_json_report(serializable_results, file_paths)

    copy_asset_directories(base_dir, output_dir_dated, results_dir)

    render_main_report(serializable_results, file_paths, env)

    try:
        await generate_statistics_report(
            serializable_results,
            file_paths["stats_final_html_path"],
            file_paths["stats_html_path"],
            file_paths["stats_json_path"],
            file_paths["stats_final_json_path"],
            env,
        )
    except Exception as e:
        logger.error(f"Error generating statistics report: {e}")
