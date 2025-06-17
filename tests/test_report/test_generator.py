import os
from unittest.mock import mock_open, patch

from bubo.core.report.generator import (
    generate_file_paths,
    setup_report_directories,
    write_json_report,
)


def test_setup_report_directories(tmp_path):
    """Test setup_report_directories with relative path."""
    base_dir = str(tmp_path)
    output_dir_name = "test_results"

    results_dir, date_dir = setup_report_directories(base_dir, output_dir_name)

    assert results_dir == os.path.join(base_dir, output_dir_name)
    assert date_dir.startswith(results_dir)
    assert os.path.exists(results_dir)
    assert os.path.exists(date_dir)


def test_setup_report_directories_absolute_path(tmp_path):
    """Test setup_report_directories with absolute path."""
    base_dir = str(tmp_path)
    output_dir_name = str(tmp_path / "absolute_results")

    results_dir, date_dir = setup_report_directories(base_dir, output_dir_name)

    assert results_dir == output_dir_name
    assert date_dir.startswith(results_dir)
    assert os.path.exists(results_dir)
    assert os.path.exists(date_dir)


def test_generate_file_paths():
    """Test generate_file_paths function."""
    results_dir = "/path/to/results"
    output_dir = "/path/to/results/2023-01-01"
    output_file = "report.html"

    file_paths = generate_file_paths(results_dir, output_dir, output_file)

    assert file_paths["report_html_path"] == os.path.join(output_dir, output_file)
    assert file_paths["report_final_html_path"] == os.path.join(
        results_dir, "index.html"
    )
    assert file_paths["report_json_path"] == os.path.join(output_dir, "report.json")
    assert file_paths["report_final_json_path"] == os.path.join(
        results_dir, "index.json"
    )
    assert file_paths["stats_html_path"] == os.path.join(
        output_dir, "report_stats.html"
    )
    assert file_paths["stats_final_html_path"] == os.path.join(
        results_dir, "statistics.html"
    )
    assert file_paths["stats_json_path"] == os.path.join(
        output_dir, "report_stats.json"
    )
    assert file_paths["stats_final_json_path"] == os.path.join(
        results_dir, "statistics.json"
    )


def test_write_json_report():
    """Test write_json_report function."""
    serializable_results = {"test": "data"}
    file_paths = {
        "report_json_path": "/path/to/report.json",
        "report_final_json_path": "/path/to/index.json",
    }

    with (
        patch("bubo.core.report.generator.open", mock_open()) as mock_file,
        patch(
            "bubo.core.report.generator.json_dumps", return_value='{"test": "data"}'
        ) as mock_json_dumps,
    ):
        write_json_report(serializable_results, file_paths)

        mock_json_dumps.assert_called_with(
            serializable_results, indent=2, sort_keys=True
        )

        mock_file.assert_any_call(file_paths["report_json_path"], "w")
        mock_file.assert_any_call(file_paths["report_final_json_path"], "w")

        mock_file().write.assert_called_with('{"test": "data"}')
        assert mock_file().write.call_count == 2
