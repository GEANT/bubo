# tests/test_file_processing.py

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from unittest.mock import patch, mock_open
from start import process_file


@pytest.mark.asyncio
async def test_process_csv_file():
    csv_content = (
        "Domain,Country,Institution\n"
        "example.com,US,Example Corp\n"
        "example.org,UK,Example Org\n"
    )

    csv_mock = mock_open(read_data=csv_content)
    with patch('builtins.open', csv_mock):
        result = await process_file('domains.csv')

        assert len(result) == 2
        assert isinstance(result, list)
        assert all(isinstance(item, dict) for item in result)
        assert all(key in result[0] for key in ['Domain', 'Country', 'Institution'])
        sorted_result = sorted(result, key=lambda x: x['Domain'])
        assert sorted_result[0]['Domain'] == 'example.com'
        assert sorted_result[1]['Domain'] == 'example.org'


@pytest.mark.asyncio
async def test_process_txt_file():
    txt_content = (
        "example.com\n"
        "example.org\n"
    )

    txt_mock = mock_open(read_data=txt_content)
    with patch('builtins.open', txt_mock):
        result = await process_file('domains.txt')
        assert len(result) == 2
        assert result[0] == {'Domain': 'example.com', 'Country': '', 'Institution': ''}
        assert result[1] == {'Domain': 'example.org', 'Country': '', 'Institution': ''}


@pytest.mark.asyncio
async def test_process_invalid_file():
    with pytest.raises(Exception), \
            patch('pathlib.Path.exists', return_value=False):
        await process_file('nonexistent.xyz')