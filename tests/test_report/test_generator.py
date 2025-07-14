import os
from unittest.mock import MagicMock, mock_open, patch

import pytest
from jinja2 import Environment

from bubo.core.report.generator import (
    copy_asset_directories,
    generate_file_paths,
    generate_html_report,
    render_main_report,
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


def test_write_json_report_error_handling():
    """Test error handling in write_json_report function."""
    serializable_results = {"test": "data"}
    file_paths = {
        "report_json_path": "/path/to/report.json",
        "report_final_json_path": "/path/to/index.json",
    }

    with (
        patch("bubo.core.report.generator.open", side_effect=OSError("Test error")),
        patch("bubo.core.report.generator.logger.error") as mock_logger_error,
        patch("bubo.core.report.generator.json_dumps", return_value='{"test": "data"}'),
    ):
        write_json_report(serializable_results, file_paths)

        mock_logger_error.assert_called_once()
        assert "Test error" in mock_logger_error.call_args[0][0]


def test_copy_asset_directories():
    """Test copy_asset_directories function."""
    base_dir = "/base/dir"
    output_dir = "/output/dir"
    results_dir = "/results/dir"

    with patch("bubo.core.report.generator.copytree") as mock_copytree:
        copy_asset_directories(base_dir, output_dir, results_dir)

        mock_copytree.assert_any_call(
            os.path.join(base_dir, "templates", "css"),
            os.path.join(output_dir, "css"),
            dirs_exist_ok=True,
        )
        mock_copytree.assert_any_call(
            os.path.join(base_dir, "templates", "css"),
            os.path.join(results_dir, "css"),
            dirs_exist_ok=True,
        )
        mock_copytree.assert_any_call(
            os.path.join(base_dir, "templates", "js"),
            os.path.join(output_dir, "js"),
            dirs_exist_ok=True,
        )
        mock_copytree.assert_any_call(
            os.path.join(base_dir, "templates", "js"),
            os.path.join(results_dir, "js"),
            dirs_exist_ok=True,
        )


def test_copy_asset_directories_error_handling():
    """Test error handling in copy_asset_directories function."""
    base_dir = "/base/dir"
    output_dir = "/output/dir"
    results_dir = "/results/dir"

    with (
        patch("bubo.core.report.generator.copytree", side_effect=OSError("Test error")),
        patch("bubo.core.report.generator.logger.error") as mock_logger_error,
    ):
        copy_asset_directories(base_dir, output_dir, results_dir)

        mock_logger_error.assert_called()
        assert "Test error" in mock_logger_error.call_args[0][0]


def test_render_main_report():
    """Test render_main_report function."""
    serializable_results = {
        "validations": {"RPKI": {"state": {"example.com": {"status": "valid"}}}},
        "domain_metadata": {"example.com": {"country": "US"}},
    }
    file_paths = {
        "report_html_path": "/path/to/report.html",
        "report_final_html_path": "/path/to/index.html",
    }

    mock_template = MagicMock()
    mock_template.render.return_value = "<html>Test</html>"

    mock_env = MagicMock(spec=Environment)
    mock_env.get_template.return_value = mock_template

    with patch("bubo.core.report.generator.open", mock_open()) as mock_file:
        render_main_report(serializable_results, file_paths, mock_env)

        mock_env.get_template.assert_called_once_with("index.html")
        mock_template.render.assert_called_once()

        mock_file.assert_any_call(file_paths["report_html_path"], "w")
        mock_file.assert_any_call(file_paths["report_final_html_path"], "w")
        mock_file().write.assert_called_with("<html>Test</html>")
        assert mock_file().write.call_count == 2


def test_render_main_report_error_handling():
    """Test error handling in render_main_report function."""
    serializable_results = {
        "validations": {"RPKI": {"state": {"example.com": {"status": "valid"}}}},
        "domain_metadata": {"example.com": {"country": "US"}},
    }
    file_paths = {
        "report_html_path": "/path/to/report.html",
        "report_final_html_path": "/path/to/index.html",
    }

    mock_template = MagicMock()
    mock_template.render.return_value = "<html>Test</html>"

    mock_env = MagicMock(spec=Environment)
    mock_env.get_template.return_value = mock_template

    with (
        patch("bubo.core.report.generator.open", side_effect=OSError("Test error")),
        patch("bubo.core.report.generator.logger.error") as mock_logger_error,
    ):
        render_main_report(serializable_results, file_paths, mock_env)

        mock_logger_error.assert_called()
        assert "Test error" in mock_logger_error.call_args[0][0]


@pytest.mark.asyncio
async def test_generate_html_report():
    """Test generate_html_report function."""
    results = {
        "validations": {"RPKI": {"state": {"example.com": {"status": "valid"}}}},
        "domain_metadata": {"example.com": {"country": "US"}},
    }
    output_file = "report.html"
    output_dir = "results"

    with (
        patch("bubo.core.report.generator.setup_report_directories") as mock_setup_dirs,
        patch("bubo.core.report.generator.generate_file_paths") as mock_gen_paths,
        patch("bubo.core.report.generator.Environment") as mock_env_class,
        patch(
            "bubo.core.report.generator.convert_sets_to_lists", return_value=results
        ) as mock_convert,
        patch("bubo.core.report.generator.write_json_report") as mock_write_json,
        patch("bubo.core.report.generator.copy_asset_directories") as mock_copy_assets,
        patch("bubo.core.report.generator.render_main_report") as mock_render,
        patch(
            "bubo.core.report.generator.generate_statistics_report"
        ) as mock_gen_stats,
    ):
        mock_setup_dirs.return_value = (
            "/path/to/results",
            "/path/to/results/2023-01-01",
        )
        mock_gen_paths.return_value = {
            "report_html_path": "/path/to/report.html",
            "report_final_html_path": "/path/to/index.html",
            "stats_html_path": "/path/to/stats.html",
            "stats_final_html_path": "/path/to/statistics.html",
            "stats_json_path": "/path/to/stats.json",
            "stats_final_json_path": "/path/to/statistics.json",
        }
        mock_env_instance = MagicMock()
        mock_env_class.return_value = mock_env_instance
        mock_gen_stats.return_value = "<html>Stats</html>"

        await generate_html_report(results, output_file, output_dir)

        mock_setup_dirs.assert_called_once()
        mock_gen_paths.assert_called_once()
        mock_convert.assert_called_once_with(results)
        mock_write_json.assert_called_once()
        mock_copy_assets.assert_called_once()
        mock_render.assert_called_once()
        mock_gen_stats.assert_called_once()


@pytest.mark.asyncio
async def test_generate_html_report_statistics_error():
    """Test generate_html_report with error in statistics generation."""
    results = {
        "validations": {"RPKI": {"state": {"example.com": {"status": "valid"}}}},
        "domain_metadata": {"example.com": {"country": "NL"}},
    }
    output_file = "report.html"
    output_dir = "results"

    with (
        patch("bubo.core.report.generator.setup_report_directories") as mock_setup_dirs,
        patch("bubo.core.report.generator.generate_file_paths") as mock_gen_paths,
        patch("bubo.core.report.generator.Environment") as mock_env_class,
        patch(
            "bubo.core.report.generator.convert_sets_to_lists", return_value=results
        ) as mock_convert,
        patch("bubo.core.report.generator.write_json_report") as mock_write_json,
        patch("bubo.core.report.generator.copy_asset_directories") as mock_copy_assets,
        patch("bubo.core.report.generator.render_main_report") as mock_render,
        patch(
            "bubo.core.report.generator.generate_statistics_report",
            side_effect=Exception("Stats error"),
        ) as mock_gen_stats,
        patch(
            "bubo.core.report.generator.generate_scoreboard_report"
        ) as mock_gen_scoreboard,
        patch("bubo.core.report.generator.logger.error") as mock_logger_error,
    ):
        mock_setup_dirs.return_value = (
            "/path/to/results",
            "/path/to/results/2025-01-01",
        )
        mock_gen_paths.return_value = {
            "report_html_path": "/path/to/report.html",
            "report_final_html_path": "/path/to/index.html",
            "stats_html_path": "/path/to/report_stats.html",
            "stats_final_html_path": "/path/to/statistics.html",
            "stats_json_path": "/path/to/report_stats.json",
            "stats_final_json_path": "/path/to/statistics.json",
            "scoreboard_html_path": "/path/to/report_scoreboard.html",
            "scoreboard_final_html_path": "/path/to/scoreboard.html",
            "scoreboard_json_path": "/path/to/report_scoreboard.json",
            "scoreboard_final_json_path": "/path/to/scoreboard.json",
        }
        mock_env_instance = MagicMock()
        mock_env_class.return_value = mock_env_instance

        await generate_html_report(results, output_file, output_dir)

        mock_setup_dirs.assert_called_once()
        mock_gen_paths.assert_called_once()
        mock_convert.assert_called_once_with(results)
        mock_write_json.assert_called_once()
        mock_copy_assets.assert_called_once()
        mock_render.assert_called_once()

        mock_gen_stats.assert_called_once()

        mock_gen_scoreboard.assert_called_once()

        mock_logger_error.assert_called()

        expected_error_msg = "Error generating statistics report: Stats error"
        actual_calls = [str(call.args[0]) for call in mock_logger_error.call_args_list]
        assert any(expected_error_msg in call for call in actual_calls), (
            f"Expected error message not found. Actual calls: {actual_calls}"
        )
