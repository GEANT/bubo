# core/report/generator.py

import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from core.logging.logger import setup_logger
from core.report.json_utils import json_dumps, convert_sets_to_lists

logger = setup_logger(__name__)


async def generate_html_report(results, output_file):
    """
    Generate HTML reports from validation results.

    Creates both the main report and statistics page.

    Args:
        results: Validation results dictionary
        output_file: Base filename for the output file
    """
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    template_dir = os.path.join(base_dir, "templates")
    output_dir = os.path.join(base_dir, "results", datetime.now().strftime("%Y-%m-%d"))

    os.makedirs(output_dir, exist_ok=True)
    output_file_path = os.path.join(output_dir, output_file)

    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    serializable_results = convert_sets_to_lists(results)

    try:
        with open(output_file_path.replace(".html", ".json"), "w") as file:
            file.write(json_dumps(serializable_results, indent=2, sort_keys=True))
        logger.info(f"Json generated: {output_file_path.replace('.html', '.json')}")
    except IOError as e:
        logger.error(
            f"Error writing report to {output_file_path.replace('.html', '.json')}: {e}"
        )

    # Generate main report
    template = env.get_template("index.html")
    rendered_html = template.render(
        validations=serializable_results["validations"],
        domain_metadata=serializable_results["domain_metadata"],
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        year=datetime.now().year,
        domains=list(serializable_results["validations"]["RPKI"]["state"].keys()),
    )

    try:
        with open(output_file_path, "w") as file:
            file.write(rendered_html)
        logger.info(f"Report generated: {output_file_path}")
    except IOError as e:
        logger.error(f"Error writing report to {output_file_path}: {e}")

    try:
        with open(os.path.join(base_dir, "results", "index.html"), "w") as file:
            file.write(rendered_html)
        logger.info(
            f"Report generated: {os.path.join(base_dir, 'results', 'index.html')}"
        )
    except IOError as e:
        logger.error(
            f"Error writing report to {os.path.join(base_dir, 'results', 'index.html')}: {e}"
        )
