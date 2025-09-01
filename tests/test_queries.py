import ast
import importlib
import sys
import warnings
from pathlib import Path


def _collect_query_strings(mod):
    """Yield query strings from the queries module."""
    for name in dir(mod):
        value = getattr(mod, name)
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict) and isinstance(value.get("query"), str):
            yield value["query"]


def test_queries_import_no_warnings(recwarn):
    """Import core.queries and ensure no warnings are emitted."""
    warnings.simplefilter("always")
    sys.modules.pop("core.queries", None)
    importlib.import_module("core.queries")
    assert len(recwarn) == 0


def test_queries_unique_variable_names():
    """Ensure each variable in core/queries.py is defined only once."""
    path = Path("core/queries.py")
    tree = ast.parse(path.read_text())
    names = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.append(target.id)
    duplicates = {n for n in names if names.count(n) > 1}
    assert not duplicates, f"Duplicate variable names found: {duplicates}"


def test_queries_no_unsupported_characters():
    """Validate each query string contains no unsupported characters."""
    mod = importlib.import_module("core.queries")
    for query in _collect_query_strings(mod):
        assert "!" not in query, "Unsupported character '!' found in query"
