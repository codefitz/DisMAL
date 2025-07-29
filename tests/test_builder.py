import os
import sys
import types

sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import core.builder as builder


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


def test_overlapping_handles_bad_api(monkeypatch):
    called = {}

    def fake_report(*a, **k):
        called["ran"] = True

    monkeypatch.setattr(builder, "output", types.SimpleNamespace(report=fake_report))
    args = types.SimpleNamespace(output_csv=False, output_file=None)

    # Should not raise even though API call fails
    builder.overlapping(DummySearch(), args)

    # If the function returned early, fake_report won't be called
    assert "ran" not in called


def test_ordering_inserts_instance_and_outpost(monkeypatch):
    captured = {}

    def fake_report(data, headers, args, name=None):
        captured["data"] = data
        captured["headers"] = headers
        captured["name"] = name

    monkeypatch.setattr(builder, "output", types.SimpleNamespace(report=fake_report))
    monkeypatch.setattr(builder.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(builder.api, "map_outpost_credentials", lambda app: {"u1": "http://op"})
    monkeypatch.setattr(builder.tideway, "appliance", lambda target, token: types.SimpleNamespace(), raising=False)
    monkeypatch.setattr(
        builder.api,
        "get_json",
        lambda *a, **k: [{"uuid": "u1", "label": "c", "index": 1, "types": [], "scopes": ["s"]}],
    )

    creds = types.SimpleNamespace(update_cred=lambda *a, **k: None, get_vault_credentials=None)
    args = types.SimpleNamespace(output_csv=False, output_file=None, target="appl", token=None, f_token=None, excavate=["suggest_cred_opt"])

    builder.ordering(creds, DummySearch(), args, False)

    assert captured["name"] == "suggest_cred_opt"
    assert captured["headers"][0] == "Discovery Instance"
    assert "Scope" in captured["headers"]
    assert "Outpost URL" in captured["headers"]
    assert captured["data"]
    assert captured["data"][0][0] == "appl"


def _setup_schedule_patches(monkeypatch, cred_list, excludes, scan_ranges):
    seq = iter([cred_list, excludes, scan_ranges])

    monkeypatch.setattr(builder.api, "get_json", lambda *a, **k: next(seq))
    monkeypatch.setattr(builder.tools, "range_to_ips", lambda r: [r])
    monkeypatch.setattr(builder.tools, "sortlist", lambda l, dv=None: list(l))
    monkeypatch.setattr(builder.tools, "completage", lambda *a, **k: 0)

    search = types.SimpleNamespace(search=lambda *a, **k: None)
    vault = types.SimpleNamespace(get_vault_credentials=None)
    args = types.SimpleNamespace(output_csv=False, output_file=None)

    captured = {}

    def fake_report(data, heads, args, name=None):
        captured["data"] = data
        captured["heads"] = heads

    monkeypatch.setattr(builder, "output", types.SimpleNamespace(report=fake_report))

    return vault, search, args, captured


def test_scheduling_empty_excludes(monkeypatch, capsys):
    cred = [{"uuid": "u1", "label": "c1", "index": 1, "ip_range": "10.0.0.0/24"}]
    vault, search, args, captured = _setup_schedule_patches(
        monkeypatch,
        cred,
        [],
        [{"results": [{"Scan_Range": ["10.0.0.0/24"], "ID": 1, "Label": "r", "Level": "L", "Date_Rules": ""}]}],
    )

    builder.scheduling(vault, search, args)
    out = capsys.readouterr().out

    assert "No exclude ranges found" in out
    assert captured["data"]
    assert any(row[1] == "Scan Range" for row in captured["data"])


def test_scheduling_empty_scan_ranges(monkeypatch, capsys):
    cred = [{"uuid": "u1", "label": "c1", "index": 1, "ip_range": "10.0.0.0/24"}]
    excludes = [{"results": [{"Scan_Range": ["10.0.0.0/24"], "ID": 1, "Label": "r", "Date_Rules": ""}]}]

    vault, search, args, captured = _setup_schedule_patches(
        monkeypatch,
        cred,
        excludes,
        [],
    )

    builder.scheduling(vault, search, args)
    out = capsys.readouterr().out

    assert "No scan ranges found" in out
    assert captured["data"]
    assert any(row[1] == "Exclude Range" for row in captured["data"])


def test_scheduling_empty_both(monkeypatch):
    cred = [{"uuid": "u1", "label": "c1", "index": 1}]
    vault, search, args, captured = _setup_schedule_patches(
        monkeypatch,
        cred,
        [],
        [],
    )

    builder.scheduling(vault, search, args)

    assert captured["data"] == []

