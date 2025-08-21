import os
import sys
import types
import ipaddress
import pytest

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


def test_ip_analysis_handles_bad_api(monkeypatch):
    called = {}

    def fake_report(*a, **k):
        called["ran"] = True

    monkeypatch.setattr(builder, "output", types.SimpleNamespace(report=fake_report))
    args = types.SimpleNamespace(output_csv=False, output_file=None)

    # Should not raise even though API call fails
    builder.ip_analysis(DummySearch(), args)

    # When the API call fails the function should still report an empty result
    assert "ran" in called


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
    args = types.SimpleNamespace(output_csv=False, output_file=None, target="appl", token=None, f_token=None, excavate=["suggested_cred_opt"])

    builder.ordering(creds, DummySearch(), args, False)

    # Verify the new key is propagated through the report and that only
    # weighted credentials are included with populated Scope and OutpostUrl.
    assert captured["name"] == "suggested_cred_opt"
    assert captured["headers"] == [
        "Discovery Instance",
        "Credential",
        "Current Index",
        "Weighting",
        "New Index",
        "Scope",
        "Outpost URL",
    ]
    assert captured["data"] == [["appl", "c", 1, 99, 0, "s", "http://op"]]


def _setup_schedule_patches(monkeypatch, cred_list, excludes, scan_ranges):
    seq = iter([cred_list, excludes, scan_ranges])

    monkeypatch.setattr(builder.api, "get_json", lambda *a, **k: next(seq))
    monkeypatch.setattr(
        builder.tools,
        "range_to_ips",
        lambda r: [ipaddress.ip_network(r, strict=False)] if r else [],
    )
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

def _setup_overlap_patches(monkeypatch, scan_ranges, excludes, search_results_returns=None):
    seq = iter([scan_ranges, excludes])

    monkeypatch.setattr(builder.api, "get_json", lambda *a, **k: next(seq))
    results_iter = iter(search_results_returns or [])
    monkeypatch.setattr(builder.api, "search_results", lambda *a, **k: next(results_iter, []))
    monkeypatch.setattr(
        builder.tools,
        "range_to_ips",
        lambda r: [ipaddress.ip_network(r, strict=False)] if r else [],
    )
    monkeypatch.setattr(builder.tools, "sortdic", lambda l: list(l))
    monkeypatch.setattr(builder.tools, "sortlist", lambda l, dv=None: list(l))
    monkeypatch.setattr(builder.tools, "completage", lambda *a, **k: 0)
    monkeypatch.setattr(builder.tools, "getr", lambda d, k, default=None: d.get(k, default))

    search = types.SimpleNamespace(search=lambda *a, **k: None)
    args = types.SimpleNamespace(output_csv=False, output_file=None)

    captured = {}

    def fake_report(data, heads, args, name=None):
        captured["data"] = data
        captured["heads"] = heads

    monkeypatch.setattr(builder, "output", types.SimpleNamespace(report=fake_report))

    return search, args, captured


def _setup_ip_analysis_patches(monkeypatch, scan_ranges, excludes):
    seq = iter([scan_ranges, excludes])
    monkeypatch.setattr(builder.api, "get_json", lambda *a, **k: next(seq))
    monkeypatch.setattr(builder.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(
        builder.tools,
        "range_to_ips",
        lambda r: [ipaddress.ip_network(r, strict=False)] if r else [],
    )
    monkeypatch.setattr(builder.tools, "sortlist", lambda l, dv=None: list(l))
    monkeypatch.setattr(builder.tools, "completage", lambda *a, **k: 0)
    monkeypatch.setattr(builder.tools, "getr", lambda d, k, default=None: d.get(k, default))
    search = types.SimpleNamespace(search=lambda *a, **k: None)
    args = types.SimpleNamespace(output_csv=False, output_file=None)
    captured = {}

    def fake_report(data, heads, args, name=None):
        captured["data"] = data

    monkeypatch.setattr(builder, "output", types.SimpleNamespace(report=fake_report))

    return search, args, captured


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


def test_scheduling_creates_empty_csv(monkeypatch):
    cred = [{"uuid": "u1", "label": "c1", "index": 1}]
    seq = iter([cred, [], []])

    monkeypatch.setattr(builder.api, "get_json", lambda *a, **k: next(seq))
    monkeypatch.setattr(
        builder.tools,
        "range_to_ips",
        lambda r: [ipaddress.ip_network(r, strict=False)] if r else [],
    )
    monkeypatch.setattr(builder.tools, "sortlist", lambda l, dv=None: list(l))
    monkeypatch.setattr(builder.tools, "completage", lambda *a, **k: 0)

    search = types.SimpleNamespace(search=lambda *a, **k: None)
    vault = types.SimpleNamespace(get_vault_credentials=None)

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        excavate=["schedules"],
        reporting_dir="out",
    )

    called = {}

    def fake_csv_file(data, heads, filename):
        called["file"] = filename

    monkeypatch.setattr(builder.output, "csv_file", fake_csv_file)

    builder.scheduling(vault, search, args)

    assert called["file"].endswith("schedules.csv")


def test_scheduling_scan_ranges_no_results_key(monkeypatch):
    cred = [{"uuid": "u1", "label": "c1", "index": 1, "ip_range": "10.0.0.0/24"}]
    scan_ranges = [{"Scan_Range": ["10.0.0.0/24"], "ID": 1, "Label": "r", "Level": "L", "Date_Rules": ""}]

    vault, search, args, captured = _setup_schedule_patches(
        monkeypatch,
        cred,
        [],
        scan_ranges,
    )

    builder.scheduling(vault, search, args)

    assert captured["data"]
    assert any(row[1] == "Scan Range" for row in captured["data"])

def test_scheduling_counts_numeric(monkeypatch):
    cred = [{"uuid": "u1", "label": "c1", "index": 1, "ip_range": "10.0.0.0/24"}]
    excludes = [
        {
            "results": [
                {"Scan_Range": ["10.0.0.0/24"], "ID": 1, "Label": "ex", "Date_Rules": ""}
            ]
        }
    ]
    scan_ranges = [
        {
            "results": [
                {
                    "Scan_Range": ["10.0.0.0/24"],
                    "ID": 2,
                    "Label": "sr",
                    "Level": "L",
                    "Date_Rules": "",
                }
            ]
        }
    ]

    vault, search, args, captured = _setup_schedule_patches(
        monkeypatch, cred, excludes, scan_ranges
    )
    args.output_csv = True

    builder.scheduling(vault, search, args)

    for row in captured["data"]:
        assert isinstance(row[3], int)
        assert isinstance(row[6], int)


def test_overlapping_scan_ranges_no_results_key(monkeypatch):
    scan_ranges = [{"Scan_Range": ["10.0.0.0/24"], "ID": 1, "Label": "r", "Level": "L", "Date_Rules": ""}]
    excludes = [{"results": []}]

    seq = iter([scan_ranges, excludes])
    monkeypatch.setattr(builder.api, "get_json", lambda *a, **k: next(seq))
    monkeypatch.setattr(builder.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(
        builder.tools,
        "range_to_ips",
        lambda r: [ipaddress.ip_network(r, strict=False)] if r else [],
    )
    monkeypatch.setattr(builder.tools, "sortdic", lambda l: list(l))
    monkeypatch.setattr(builder.tools, "sortlist", lambda l, dv=None: list(l))
    monkeypatch.setattr(builder.tools, "completage", lambda *a, **k: 0)
    monkeypatch.setattr(builder.tools, "getr", lambda d, k, default=None: d.get(k, default))

    called = {}

    def fake_report(data, heads, args, name=None):
        called["data"] = data

    monkeypatch.setattr(builder, "output", types.SimpleNamespace(report=fake_report))

    search = types.SimpleNamespace(search=lambda *a, **k: None)
    args = types.SimpleNamespace(output_csv=False, output_file=None)

    builder.ip_analysis(search, args)

    assert "data" in called


def test_ip_analysis_empty_excludes(monkeypatch, capsys):
    scan_ranges = [{"results": [{"Scan_Range": ["10.0.0.0/24"], "ID": 1, "Label": "r", "Level": "L", "Date_Rules": ""}]}]
    search, args, captured = _setup_ip_analysis_patches(monkeypatch, scan_ranges, [])

    builder.ip_analysis(search, args)
    out = capsys.readouterr().out

    assert "No exclude ranges found" in out
    assert captured["data"] == []


def test_ip_analysis_empty_scan_ranges(monkeypatch, capsys):
    search, args, captured = _setup_ip_analysis_patches(monkeypatch, [], [{"results": []}])

    builder.ip_analysis(search, args)
    out = capsys.readouterr().out

    assert "No scan ranges found" in out


def test_ip_analysis_dict_responses(monkeypatch):
    scan_ranges = {
        "results": [
            {"Scan_Range": ["10.0.0.0/24"], "Label": "r1"},
            {"Scan_Range": ["10.0.0.0/24"], "Label": "r2"},
        ]
    }
    excludes = {
        "results": [{"Scan_Range": ["10.0.1.0/24"], "Label": "ex"}] 
    }
    search, args, captured = _setup_ip_analysis_patches(monkeypatch, scan_ranges, excludes)

    builder.ip_analysis(search, args)

    assert captured["data"] == [["10.0.0.0/24", ["r1", "r2"]]]


def test_ip_analysis_list_responses(monkeypatch):
    scan_ranges = [
        {"Scan_Range": ["10.0.0.0/24"], "Label": "r1"},
        {"Scan_Range": ["10.0.0.0/24"], "Label": "r2"},
    ]
    excludes = [
        {"Scan_Range": ["10.0.1.0/24"], "Label": "ex"}
    ]
    search, args, captured = _setup_ip_analysis_patches(monkeypatch, scan_ranges, excludes)

    builder.ip_analysis(search, args)

    assert captured["data"] == [["10.0.0.0/24", ["r1", "r2"]]]


def test_overlapping_unscanned_connections(monkeypatch):
    search_results_returns = [
        [],
        [{"Unscanned Host IP Address": "192.0.2.1"}],
    ]
    search, args, captured = _setup_overlap_patches(
        monkeypatch, [], [], search_results_returns
    )

    builder.overlapping(search, args)

    assert ["192.0.2.1", "Seen but unscanned."] in captured["data"]


def test_unique_identities_handles_bad_api(monkeypatch):
    monkeypatch.setattr(builder.tools, "completage", lambda *a, **k: 0)

    def fake_search_results(api, query):
        return {"error": "fail"}

    monkeypatch.setattr(builder.api, "search_results", fake_search_results)

    result = builder.unique_identities(None)
    assert result == []


def test_unique_identities_merges_device_data(monkeypatch):
    monkeypatch.setattr(builder.tools, "completage", lambda *a, **k: 0)
    monkeypatch.setattr(builder.tools, "sortlist", lambda l, dv=None: sorted(set(l)))

    devices = [
        {
            "DA_Endpoint": "10.0.0.1",
            "Inferred_All_IP_Addrs": ["10.0.0.1", "10.0.0.2"],
            "Device_Sysname": "host1",
        },
        {
            "DA_Endpoint": "10.0.0.2",
            "Inferred_All_IP_Addrs": ["10.0.0.2"],
            "Device_Sysname": "host2",
        },
    ]
    da_results = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]

    seq = iter([devices, da_results])
    monkeypatch.setattr(builder.api, "search_results", lambda *a, **k: next(seq))

    result = builder.unique_identities(None)
    assert result == [
        {
            "originating_endpoint": "10.0.0.1",
            "list_of_ips": ["10.0.0.1", "10.0.0.2"],
            "list_of_names": ["host1"],
            "coverage_pct": pytest.approx(100.0),
        },
        {
            "originating_endpoint": "10.0.0.2",
            "list_of_ips": ["10.0.0.1", "10.0.0.2"],
            "list_of_names": ["host1", "host2"],
            "coverage_pct": pytest.approx(100.0),
        },
    ]

def test_get_scans_uses_networks(monkeypatch):
    import ipaddress

    # Ensure legacy helper is not used
    monkeypatch.setattr(
        builder.tools,
        "range_to_ips",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("range_to_ips used")),
    )

    results = [{"Scan_Range": ["192.168.0.0/30"], "Label": "r1"}]
    ip_list = [ipaddress.ip_address("192.168.0.1")]

    assert builder.get_scans(results, ip_list) == ["r1"]


def test_get_scans_caches_ranges(monkeypatch):
    import ipaddress

    monkeypatch.setattr(
        builder.tools,
        "range_to_ips",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("range_to_ips used")),
    )

    builder._range_to_networks.cache_clear()

    results = [{"Scan_Range": ["192.168.0.0/30"], "Label": "r1"}]
    ip_list = [ipaddress.ip_address("192.168.0.1")]

    builder.get_scans(results, ip_list)
    info1 = builder._range_to_networks.cache_info()
    builder.get_scans(results, ip_list)
    info2 = builder._range_to_networks.cache_info()

    assert info2.hits > info1.hits

