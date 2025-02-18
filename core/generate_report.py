# core/generate_report.py

import json
import logging
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from core.custom_logger.logger import setup_logger

setup_logger()
logger = logging.getLogger(__name__)


async def generate_html_report(results, output_file):
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    template_dir = os.path.join(base_dir, "templates")
    output_dir = os.path.join(base_dir, "results", datetime.now().strftime("%Y-%m-%d"))

    os.makedirs(output_dir, exist_ok=True)
    output_file_path = os.path.join(output_dir, output_file)

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=True
    )

    template = env.get_template('index.html')
    rendered_html = template.render(
        validations=results['validations'],
        domain_metadata=results['domain_metadata'],
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        year=datetime.now().year,
        domains=list(results['validations']['RPKI']['state'].keys())
    )

    # Write HTML output
    try:
        with open(output_file_path, "w") as file:
            file.write(rendered_html)
        logger.info(f"Report generated: {output_file_path}")
    except IOError as e:
        logger.error(f"Error writing report to {output_file_path}: {e}")

    # override index.html
    try:
        with open(os.path.join(base_dir, "results", "index.html"), "w") as file:
            file.write(rendered_html)
        logger.info(f"Report generated: {os.path.join(base_dir, 'results', 'index.html')}")
    except IOError as e:
        logger.error(f"Error writing report to {os.path.join(base_dir, 'results', 'index.html')}: {e}")

    # Write Json output
    try:
        with open(output_file_path.replace('.html', '.json'), "w") as file:
            file.write(json.dumps(results, indent=2, sort_keys=True))
        logger.info(f"Json generated: {output_file_path.replace('.html', '.json')}")
    except IOError as e:
        logger.error(f"Error writing report to {output_file_path.replace('.html', '.json')}: {e}")
