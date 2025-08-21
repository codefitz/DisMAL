import importlib
import sys
import warnings


def test_queries_import_no_warnings(recwarn):
    """Import core.queries and ensure no warnings are emitted."""
    warnings.simplefilter("always")
    sys.modules.pop("core.queries", None)
    importlib.import_module("core.queries")
    assert len(recwarn) == 0
