import os
import sys
import types

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
