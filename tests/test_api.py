import os
import sys
import types

sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.api import get_json, search_results, show_runs, get_outposts

class DummyResponse:
    def __init__(self, status_code=200, data="{}", reason="OK", url="http://x"):
        self.status_code = status_code
        self._data = data
        self.reason = reason
        self.url = url
        self.ok = status_code == 200
    def json(self):
        import json
        return json.loads(self._data)

class DummySearch:
    def __init__(self, response):
        self._response = response
    def search(self, query, format="object", limit=500):
        return self._response

class DummyDisco:
    def __init__(self, response):
        self._response = response
    @property
    def get_discovery_runs(self):
        return self._response

def test_get_json_success():
    resp = DummyResponse(200, '{"a":1}')
    assert get_json(resp) == {"a":1}

def test_get_json_bad_json():
    resp = DummyResponse(200, 'not-json')
    assert get_json(resp) == {}

def test_search_results_fallback():
    resp = DummyResponse(200, '[{"ok": true}]')
    search = DummySearch(resp)
    assert search_results(search, {"query": "q"}) == [{"ok": True}]


def test_show_runs_handles_bad_response(capsys):
    resp = DummyResponse(401, 'not-json', reason="Unauthorized")
    disco = DummyDisco(resp)
    args = types.SimpleNamespace(export=False, file=None)

    show_runs(disco, args)

    captured = capsys.readouterr()
    assert "No runs in progress." in captured.out

def test_get_outposts_uses_deleted_false():
    """Verify get_outposts calls the correct API path."""
    class DummyAppliance:
        def __init__(self):
            self.requested = None

        def get(self, path):
            self.requested = path
            return DummyResponse(200, "[]")

    app = DummyAppliance()
    get_outposts(app)

    assert app.requested == "/discovery/outposts?deleted=false"
