import os
import sys
import types
import json
import logging

sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.api import get_json, search_results, show_runs, get_outposts, map_outpost_credentials
import core.api as api_mod
from core import queries
import core.access as access

class DummyResponse:
    def __init__(self, status_code=200, data="{}", reason="OK", url="http://x"):
        self.status_code = status_code
        self._data = data
        self.reason = reason
        self.url = url
        self.ok = status_code == 200
        self.text = data
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

class RecorderDisco(DummyDisco):
    def __init__(self, response):
        super().__init__(response)
        self.patches = []

    def patch_discovery_run(self, rid, payload):
        self.patches.append((rid, payload))
        return DummyResponse(200, "{}")

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

def test_search_results_error_json():
    resp = DummyResponse(404, '{"error": "missing"}')
    search = DummySearch(resp)
    assert search_results(search, {"query": "q"}) == {"error": "missing"}


def test_search_results_error_non_json():
    resp = DummyResponse(500, 'Internal Server Error')
    search = DummySearch(resp)
    assert search_results(search, {"query": "q"}) == {"error": "Internal Server Error"}


def test_show_runs_handles_bad_response(capsys):
    resp = DummyResponse(401, 'not-json', reason="Unauthorized")
    disco = DummyDisco(resp)
    args = types.SimpleNamespace(export=False, file=None)

    show_runs(disco, args)

    captured = capsys.readouterr()
    assert "No runs in progress." in captured.out


def test_show_runs_minimal_args(capsys):
    """show_runs should handle args without optional attributes."""
    resp = DummyResponse(401, 'not-json', reason="Unauthorized")
    disco = DummyDisco(resp)
    args = types.SimpleNamespace()

    show_runs(disco, args)

    captured = capsys.readouterr()
    assert "No runs in progress." in captured.out


def test_show_runs_prints_summary(capsys):
    resp = DummyResponse(200, '[{"run_id": "1", "status": "running"}]')
    disco = DummyDisco(resp)
    args = types.SimpleNamespace()

    show_runs(disco, args)

    captured = capsys.readouterr()
    assert "Active discovery runs: 1" in captured.out
    assert "1" in captured.out
    assert "running" in captured.out
    assert "{" not in captured.out


def test_show_runs_debug_prints_json(capsys):
    resp = DummyResponse(200, '[{"run_id": "1", "status": "running"}]')
    disco = DummyDisco(resp)
    args = types.SimpleNamespace(debugging=True)

    show_runs(disco, args)

    captured = capsys.readouterr()
    assert "'run_id': '1'" in captured.out
    assert "'status': 'running'" in captured.out


def test_show_runs_excavate_routes_to_define_csv(monkeypatch):
    resp = DummyResponse(200, '[{"run_id": "1", "status": "running"}]')
    disco = DummyDisco(resp)
    recorded = {}

    def fake_define_csv(args, header, data, path, file, target, typ):
        recorded["header"] = header
        recorded["data"] = data

    monkeypatch.setattr(api_mod.output, "define_csv", fake_define_csv)

    args = types.SimpleNamespace(excavate=["active_runs"], reporting_dir="/tmp", target="appl")

    show_runs(disco, args)

    assert recorded["header"] == ["Run Id", "Status"]
    assert recorded["data"] == [["1", "running"]]


def test_discovery_runs_emits_ints_and_camel_headers(monkeypatch):
    runs = [{
        "range_id": "r1",
        "done": "1",
        "pre_scanning": "2",
        "scanning": "3",
        "total": "4",
    }]
    disco = DummyDisco(DummyResponse(200, json.dumps(runs)))
    captured = {}

    def fake_define_csv(args, header, rows, path, file, target, typ):
        captured["header"] = header
        captured["rows"] = rows

    monkeypatch.setattr(api_mod.output, "define_csv", fake_define_csv)

    args = types.SimpleNamespace(target="appl", output_file=None)

    api_mod.discovery_runs(disco, args, "/tmp")

    assert captured["header"] == ["Discovery Instance", "Done", "Pre Scanning", "Range Id", "Scanning", "Total"]
    assert captured["rows"] == [["appl", 1, 2, "r1", 3, 4]]
    row = captured["rows"][0]
    for index in [1, 2, 4, 5]:
        assert isinstance(row[index], int)

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
    monkeypatch.setattr(api_mod.access, "ping", lambda host: 0)

    mapping = map_outpost_credentials(types.SimpleNamespace(token="t"))

    assert captured["target"] == "op.example.com"
    assert mapping == {"u1": "https://op.example.com"}


def test_map_outpost_credentials_skips_unreachable(monkeypatch, capsys, caplog):
    def fake_get_outposts(app):
        return [{"url": "https://op.example.com"}]

    called = {"outpost": False}

    def fake_outpost(*args, **kwargs):
        called["outpost"] = True
        return None

    monkeypatch.setattr(api_mod, "get_outposts", fake_get_outposts)
    monkeypatch.setattr(api_mod.tideway, "outpost", fake_outpost, raising=False)
    monkeypatch.setattr(api_mod.access, "ping", lambda host: 1)

    with caplog.at_level(logging.WARNING):
        mapping = map_outpost_credentials(types.SimpleNamespace(token="t"))
    captured = capsys.readouterr()

    assert mapping == {}
    assert not called["outpost"]
    msg = "Outpost https://op.example.com is not available"
    assert msg in captured.out
    assert msg in caplog.text


def test_search_results_cleans_query(monkeypatch):
    """Ensure newlines removed and single quotes preserved."""

    captured = {}

    class Recorder:
        def search(self, query, format="object", limit=500):
            captured["query"] = query
            return DummyResponse(200, "[]")

    qry = "search Device\nwhere name = 'foo'\n"
    search_results(Recorder(), {"query": qry})

    sent = captured["query"]["query"]
    assert "\n" not in sent
    assert "'foo'" in sent
    assert '\\"foo\\"' not in sent


def test_search_results_sanitizes_once(monkeypatch):
    """Ensure query sanitization occurs exactly once."""

    class CountingStr(str):
        calls = 0

        def replace(self, old, new, count=-1):
            CountingStr.calls += 1
            return CountingStr(super().replace(old, new, count))

    captured = {}

    class Recorder:
        def search(self, query, format="object", limit=500):
            captured["query"] = query
            return DummyResponse(200, "[]")

    CountingStr.calls = 0
    qry = CountingStr("search Device\nwhere name = 'foo'\r")
    search_results(Recorder(), {"query": qry})

    sent = captured["query"]["query"]
    assert "\n" not in sent
    assert "\r" not in sent
    assert CountingStr.calls == 2


def test_search_results_wraps_str_query(monkeypatch):
    """Ensure plain string queries are wrapped and sanitized."""

    captured = {}

    class Recorder:
        def search(self, query, format="object", limit=500):
            captured["query"] = query
            return DummyResponse(200, "[]")

    qry = "search Device\nwhere name = 'foo'\r"
    search_results(Recorder(), qry)

    sent = captured["query"]
    assert isinstance(sent, dict)
    assert "query" in sent
    assert "\n" not in sent["query"]
    assert "\r" not in sent["query"]


def test_search_results_returns_error_payload(caplog):
    resp = DummyResponse(400, '{"msg": "bad"}', reason="Bad")
    search = DummySearch(resp)

    with caplog.at_level("ERROR"):
        result = search_results(search, {"query": "q"})

    assert result == {"msg": "bad"}
    assert "Bad" in caplog.text

def test_search_results_list_table():
    search = DummySearch([["A", "B"], [1, 2]])
    result = search_results(search, {"query": "q"})
    assert result == [{"A": 1, "B": 2}]


def test_capture_candidates_writes_csv(monkeypatch):
    results = [
        {
            "access_method": "SNMP v2c",
            "request_time": "2025-08-06T17:02:48.981762+00:00",
            "hostname": "hpi19e815",
            "os": "HP ETHERNET MULTI-ENVIRONMENT",
            "failure_reason": None,
            "syscontact": None,
            "syslocation": None,
            "sysdescr": "HP ETHERNET MULTI-ENVIRONMENT",
            "sysobjectid": "0.0",
        }
    ]

    monkeypatch.setattr(api_mod, "search_results", lambda *a, **k: results)
    monkeypatch.setattr(api_mod.tools, "completage", lambda *a, **k: 0)

    captured = {}

    def fake_define_csv(args, header, rows, path, *a):
        captured["header"] = header
        captured["rows"] = rows
        captured["path"] = path

    monkeypatch.setattr(
        api_mod,
        "output",
        types.SimpleNamespace(define_csv=fake_define_csv),
    )

    args = types.SimpleNamespace(output_file=None, target="appl")

    api_mod.capture_candidates(types.SimpleNamespace(), args, "/tmp")

    expected_header = ["Discovery Instance"] + [api_mod.tools.snake_to_camel(h) for h in sorted(results[0].keys())]
    expected_row = [
        "appl"
    ] + [
        (results[0][k] if results[0][k] is not None else "N/A")
        for k in sorted(results[0])
    ]

    assert captured["header"] == expected_header
    assert captured["rows"][0] == expected_row
    assert captured["path"].endswith(api_mod.defaults.capture_candidates_filename)


def test_update_schedule_timezone_applies_offset():
    runs = [{"range_id": "r1", "schedule": {"start_times": [10, 23]}}]
    resp = DummyResponse(200, json.dumps(runs))
    disco = RecorderDisco(resp)
    args = types.SimpleNamespace(schedule_timezone="Etc/GMT+5", reset_schedule_timezone=False)

    api_mod.update_schedule_timezone(disco, args)

    assert disco.patches == [("r1", {"schedule": {"start_times": [5, 18]}})]


def test_update_schedule_timezone_reset():
    runs = [{"range_id": "r1", "schedule": {"start_times": [10]}}]
    resp = DummyResponse(200, json.dumps(runs))
    disco = RecorderDisco(resp)
    args = types.SimpleNamespace(schedule_timezone="Etc/GMT+5", reset_schedule_timezone=True)

    api_mod.update_schedule_timezone(disco, args)

    assert disco.patches[0][1]["schedule"]["start_times"] == [15]

def test_host_util_converts_numeric_columns(monkeypatch):
    sample = [
        {
            "hostname": "h1",
            "hashed_hostname": "hash",
            "os": "Linux",
            "OS_Type": "Linux",
            "virtual": False,
            "cloud": False,
            "Endpoint": "ep",
            "Running Software Instances": "1",
            "Candidate Software Instances": "2",
            "Running Processes": "3",
            "Running Services (Windows)": "4",
        }
    ]

    monkeypatch.setattr(api_mod, "search_results", lambda *a, **k: sample)
    monkeypatch.setattr(api_mod.tools, "completage", lambda *a, **k: 0)

    recorded = {}

    def fake_define_csv(args, header, rows, path, *a):
        recorded["header"] = header
        recorded["rows"] = rows

    monkeypatch.setattr(api_mod.output, "define_csv", fake_define_csv)

    args = types.SimpleNamespace(target="appl", output_file=None)

    api_mod.host_util(None, args, "/tmp")

    header = recorded["header"]
    row = recorded["rows"][0]
    index_map = {h: i for i, h in enumerate(header)}
    for col in [
        "Running Software Instances",
        "Candidate Software Instances",
        "Running Processes",
        "Running Services (Windows)",
    ]:
        assert isinstance(row[index_map[col]], int)
    assert "OS_Type" in header

