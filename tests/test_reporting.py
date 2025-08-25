import os
import sys
import types
import pytest

sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import core.reporting as reporting

class DummyResponse:
    status_code = 401
    ok = False
    reason = "Unauthorized"
    url = "http://x"
    def json(self):
        return {}

class DummySearch:
    def search(self, query, format="object", limit=500):
        return DummyResponse()

class DummyCreds:
    def get_vault_credentials(self):
        return DummyResponse()


def _run_with_patches(monkeypatch, func):
    monkeypatch.setattr(reporting.builder, "unique_identities", lambda s: [])
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "map_outpost_credentials", lambda *a, **k: {})
    called = {}
    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=lambda *a, **k: called.setdefault("ran", True)))
    args = types.SimpleNamespace(output_csv=False, output_file=None, token=None, target="http://x")
    func(DummySearch(), DummyCreds(), args)
    assert "ran" in called


def test_queries_prioritize_credential_over_slave():
    """Ensure credential UUIDs are preferred over slave IDs in queries."""
    assert "(credential or slave)" in reporting.queries.credential_success
    assert "(credential or slave)" in reporting.queries.credential_failure


def test_discovery_access_handles_bad_api(monkeypatch):
    _run_with_patches(monkeypatch, reporting.discovery_access)


def test_discovery_analysis_handles_bad_api(monkeypatch):
    _run_with_patches(monkeypatch, reporting.discovery_analysis)


def test_successful_runs_without_scan_data(monkeypatch):
    call = {"n": 0}

    def fake_get_json(*a, **k):
        call["n"] += 1
        if call["n"] == 1:
            return [{"uuid": "u1", "label": "c", "index": 1, "enabled": True}]
        return []

    monkeypatch.setattr(reporting.api, "get_json", fake_get_json)
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])
    called = {}
    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=lambda *a, **k: called.setdefault("ran", True)))
    args = types.SimpleNamespace(output_csv=False, output_file=None, token=None, target="http://x")
    reporting.successful(DummyCreds(), DummySearch(), args)
    assert "ran" in called


def test_successful_combines_query_results(monkeypatch):
    calls = []

    def fake_search_results(search, query):
        calls.append(query)
        if query is reporting.queries.credential_success:
            return [{"UUID": "u1", "Session_Type": "ssh", "Count": 2}]
        if query is reporting.queries.deviceinfo_success:
            return [{"UUID": "u1", "Session_Type": "ssh", "Count": 3}]
        if query is reporting.queries.credential_failure:
            return [{"UUID": "u1", "Session_Type": "ssh", "Count": 4}]
        return []

    call = {"n": 0}

    def fake_get_json(*a, **k):
        call["n"] += 1
        if call["n"] == 1:
            return [
                {
                    "uuid": "u1",
                    "label": "c",
                    "index": 1,
                    "enabled": True,
                    "username": "user",
                    "usage": "",
                    "iprange": None,
                    "exclusions": None,
                }
            ]
        return []

    monkeypatch.setattr(reporting.api, "get_json", fake_get_json)
    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["data"] = data
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(output_csv=False, output_file=None, token=None, target="http://x")

    reporting.successful(DummyCreds(), DummySearch(), args)

    assert set(calls) == {
        reporting.queries.credential_success,
        reporting.queries.deviceinfo_success,
        reporting.queries.credential_failure,
    }
    row = captured["data"][0]
    assert row[6] == 5
    assert row[7] == 4
    assert row[8] == pytest.approx(5 / 9)

def test_successful_flags_active_with_failures_only(monkeypatch):
    call = {"n": 0}

    def fake_search_results(search, query):
        if query is reporting.queries.credential_failure:
            return [{"UUID": "u1", "Session_Type": "ssh", "Count": 1}]
        return []
    def fake_get_json(*a, **k):
        call["n"] += 1
        if call["n"] == 1:
            return [
                {
                    "uuid": "u1",
                    "label": "c",
                    "index": 1,
                    "enabled": True,
                    "username": "user",
                    "usage": "",
                    "iprange": None,
                    "exclusions": None,
                }
            ]
        return []

    monkeypatch.setattr(reporting.api, "get_json", fake_get_json)
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])
    monkeypatch.setattr(
        reporting.api,
        "map_outpost_credentials",
        lambda app: {"u1": {"id": "op1", "url": "http://op"}},
    )
    monkeypatch.setattr(
        reporting.tideway, "appliance", lambda target, token: types.SimpleNamespace(), raising=False
    )

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["data"] = data
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(output_csv=False, output_file=None, token=None, target="http://x")

    reporting.successful(DummyCreds(), DummySearch(), args)

    row = captured["data"][0]
    assert "Outpost ID" in captured["headers"]
    assert "Outpost URL" in captured["headers"]
    assert row[-2] == "op1"
    assert row[-1] == "http://op"
    assert row[5] == "ssh"
    assert row[6] == 0
    assert row[7] == 1
    assert row[9] == "Enabled"


def test_credential_queries_show_credential_first():
    clause = "(credential or slave) as 'UUID'"
    assert clause in reporting.queries.credential_success
    assert clause in reporting.queries.credential_failure


def test_successful_uses_token_file(monkeypatch, tmp_path):
    file_path = tmp_path / "token.txt"
    file_path.write_text("abc")

    captured = {}

    class DummyApp:
        def __init__(self, token):
            self.token = token

    def fake_appliance(target, token):
        captured["token"] = token
        return DummyApp(token)

    monkeypatch.setattr(reporting.tideway, "appliance", fake_appliance, raising=False)
    monkeypatch.setattr(reporting.api, "map_outpost_credentials", lambda app: {})
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])
    monkeypatch.setattr(reporting.builder, "unique_identities", lambda s: [])
    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=lambda *a, **k: None))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        token=None,
        f_token=str(file_path),
        target="http://x",
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    assert captured["token"] == "abc"


def test_discovery_access_with_dropped_only(monkeypatch):
    class DummyDF(dict):
        def __init__(self, data):
            super().__init__({k: {0: v[0] if isinstance(v, list) else v} for k, v in data.items()})

        def __getitem__(self, key):
            return self.get(key)

        def __setitem__(self, key, value):
            dict.__setitem__(self, key, {0: value})

        def to_dict(self):
            return self

    monkeypatch.setattr(reporting.builder, "unique_identities", lambda s: [])

    def fake_search_results(search, query):
        if query is reporting.queries.last_disco:
            return []
        if query is reporting.queries.dropped_endpoints:
            return [{"Endpoint": "1.2.3.4", "End": "2024-01-01 00:00:00", "Run": "r", "Start": "2024-01-01 00:00:00", "End_State": "DarkSpace"}]
        return []

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "map_outpost_credentials", lambda *a, **k: {})
    monkeypatch.setattr(reporting.pd, "DataFrame", lambda data: DummyDF(data), raising=False)
    monkeypatch.setattr(reporting.pd, "cut", lambda *a, **k: "recent", raising=False)

    called = {}
    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=lambda *a, **k: called.setdefault("ran", True)))
    args = types.SimpleNamespace(output_csv=False, output_file=None, token=None, target="http://x")

    reporting.discovery_access(DummySearch(), DummyCreds(), args)

    assert "ran" in called
