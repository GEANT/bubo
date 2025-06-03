# core/json_utils.py

import json
from typing import Any


class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that properly handles Python-specific data types:
    - Sets are converted to lists
    - Other non-serializable types can be added here as needed
    """

    def default(self, obj: Any) -> Any:
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


def json_dumps(obj: Any, **kwargs) -> str:
    """
    Serialize object to JSON string, handling Python-specific data types.

    Args:
        obj: Object to serialize
        **kwargs: Additional keyword arguments for json.dumps

    Returns:
        JSON string representation
    """
    return json.dumps(obj, cls=CustomJSONEncoder, **kwargs)


def json_dump(obj: Any, fp, **kwargs) -> None:
    """
    Serialize object as JSON to file-like object, handling Python-specific data types.

    Args:
        obj: Object to serialize
        fp: File-like object to write to
        **kwargs: Additional keyword arguments for json.dump
    """
    json.dump(obj, fp, cls=CustomJSONEncoder, **kwargs)


def convert_sets_to_lists(obj: Any) -> Any:
    """
    Recursively convert all sets to lists in a nested structure.
    This is useful when you need to ensure JSON serializability before serialization.

    Args:
        obj: Object to convert

    Returns:
        Object with all sets converted to lists
    """
    if isinstance(obj, dict):
        return {k: convert_sets_to_lists(v) for k, v in obj.items()}
    elif isinstance(obj, (list | set)):
        return [convert_sets_to_lists(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_sets_to_lists(item) for item in obj)
    else:
        return obj
