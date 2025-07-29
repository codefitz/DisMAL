import os
import sys
import types

sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.api import get_json, search_results, show_runs, get_outposts, map_outpost_credentials
import core.api as api_mod

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

def test_get_json_returns_list_directly():
    data = [{"x": 1}]
    # When a list is passed in, get_json should return it unchanged
    assert get_json(data) == data

def test_get_json_returns_dict_directly():
    data = {"a": 1}
    assert get_json(data) == data

def test_search_results_fallback():
    resp = DummyResponse(200, '[{"ok": true}]')
    search = DummySearch(resp)
    assert search_results(search, {"query": "q"}) == [{"ok": True}]


def test_search_results_sanitizes_dict_query():
    captured = {}

    class CaptureSearch:
        def search(self, query, format="object", limit=500):
            captured["q"] = query
            return DummyResponse(200, "[]")

    search = CaptureSearch()
    query = {"query": "search Foo\nshow bar as 'Bar'"}

    search_results(search, query)

    assert captured["q"] == {"query": 'search Foo show bar as \\"Bar\\"'}


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


def test_map_outpost_credentials_strips_scheme(monkeypatch):
    """Outpost targets should not include protocol."""

    def fake_get_outposts(app):
        return [{"url": "https://op.example.com"}]

    class DummyCreds:
        def get_vault_credentials(self):
            return DummyResponse(200, '[{"uuid": "u1"}]')
        def get_vault_credential(self, uuid):
            return DummyResponse(200, "{}")

    class DummyOutpost:
        def credentials(self):
            return DummyCreds()

    captured = {}

    def fake_outpost(target, token, api_version=None, ssl_verify=None, limit=None, offset=None):
        captured["target"] = target
        return DummyOutpost()

    monkeypatch.setattr(api_mod, "get_outposts", fake_get_outposts)
    monkeypatch.setattr(api_mod.tideway, "outpost", fake_outpost, raising=False)

    mapping = map_outpost_credentials(types.SimpleNamespace(token="t"))

    assert captured["target"] == "op.example.com"
    assert mapping == {"u1": "https://op.example.com"}

