import os
import sys
import types
import pytest
import core.builder as builder
import core.output as output
import json

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
    monkeypatch.setattr(reporting.builder, "unique_identities", lambda s, *a, **k: [])
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    called = {}
    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=lambda *a, **k: called.setdefault("ran", True)))
    args = types.SimpleNamespace(output_csv=False, output_file=None, token=None, target="http://x", include_endpoints=None, endpoint_prefix=None)
    func(DummySearch(), DummyCreds(), args)
    assert "ran" in called


def test_successful_uses_default_thread_limit(monkeypatch):
    captured = {}

    class DummyExecutor:
        def __init__(self, max_workers=None):
            captured["max_workers"] = max_workers

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def submit(self, fn, *args, **kwargs):
            class DummyFuture:
                def result(self_inner):
                    return []

            return DummyFuture()

    monkeypatch.setattr(reporting, "ThreadPoolExecutor", DummyExecutor)
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda c: c)
    monkeypatch.setattr(reporting.tools, "session_get", lambda r: {})
    monkeypatch.setattr(reporting.output, "report", lambda *a, **k: None)
    monkeypatch.setattr(reporting.tools, "completage", lambda *a, **k: 0)
    monkeypatch.setattr(reporting.tools, "getr", lambda d, k, default=None: d.get(k, default))
    monkeypatch.setattr(reporting.tools, "range_to_ips", lambda r: [])

    class Creds:
        def get_vault_credentials(self):
            return types.SimpleNamespace(json=lambda: [], ok=True, text="[]", status_code=200)

    class Search:
        def search(self, query, format="object", limit=500, offset=0):
            return types.SimpleNamespace(json=lambda: [], ok=True, text="[]", status_code=200)

    args = types.SimpleNamespace(output_csv=False, output_file=None)
    reporting.successful(Creds(), Search(), args)
    assert captured["max_workers"] == 2


def test_successful_respects_custom_thread_limit(monkeypatch):
    captured = {}

    class DummyExecutor:
        def __init__(self, max_workers=None):
            captured["max_workers"] = max_workers

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def submit(self, fn, *args, **kwargs):
            class DummyFuture:
                def result(self_inner):
                    return []

            return DummyFuture()

    monkeypatch.setattr(reporting, "ThreadPoolExecutor", DummyExecutor)
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda c: c)
    monkeypatch.setattr(reporting.tools, "session_get", lambda r: {})
    monkeypatch.setattr(reporting.output, "report", lambda *a, **k: None)
    monkeypatch.setattr(reporting.tools, "completage", lambda *a, **k: 0)
    monkeypatch.setattr(reporting.tools, "getr", lambda d, k, default=None: d.get(k, default))
    monkeypatch.setattr(reporting.tools, "range_to_ips", lambda r: [])

    class Creds:
        def get_vault_credentials(self):
            return types.SimpleNamespace(json=lambda: [], ok=True, text="[]", status_code=200)

    class Search:
        def search(self, query, format="object", limit=500, offset=0):
            return types.SimpleNamespace(json=lambda: [], ok=True, text="[]", status_code=200)

    args = types.SimpleNamespace(output_csv=False, output_file=None, max_threads=5)
    reporting.successful(Creds(), Search(), args)
    assert captured["max_workers"] == 5


def test_successful_writes_all_credentials(tmp_path, monkeypatch):
    """credential_success.csv should include more than the default 500 rows."""

    total = 600

    vaultcreds = [
        {
            "uuid": f"cred{i}",
            "label": f"cred{i}",
            "index": i,
            "types": "ssh",
            "username": "user",
            "iprange": None,
            "exclusions": None,
            "enabled": True,
            "usage": "",
        }
        for i in range(total)
    ]

    vault_resp = types.SimpleNamespace(
        status_code=200,
        ok=True,
        text=json.dumps(vaultcreds),
        json=lambda: vaultcreds,
    )

    class Creds:
        def get_vault_credentials(self):
            return vault_resp

    class Search:
        def search(self, query, format="object", limit=500, offset=0):
            return types.SimpleNamespace(status_code=200, ok=True, text="[]", json=lambda: [])

    monkeypatch.setattr(reporting.builder, "get_credentials", lambda c: c)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.tools, "getr", lambda d, k, default=None: d.get(k, default))
    monkeypatch.setattr(reporting.tools, "range_to_ips", lambda r: [])
    monkeypatch.setattr(reporting.tools, "completage", lambda *a, **k: 0)

    def session_get(results):
        return {f"cred{i}": ["ssh", 1] for i in range(total)}

    monkeypatch.setattr(reporting.tools, "session_get", session_get)

    called_limits = []

    def fake_search_results(api_endpoint, query, limit=500, *args, **kwargs):
        called_limits.append(limit)
        return [{} for _ in range(total)]

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)

    args = types.SimpleNamespace(
        output_file=str(tmp_path / "credential_success.csv"),
        output_csv=False,
        output_cli=False,
        output_null=False,
        token=None,
        target="app",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(Creds(), Search(), args)

    with open(tmp_path / "credential_success.csv") as f:
        lines = f.readlines()

    assert len(lines) == total + 1  # header + data
    assert all(l == 0 for l in called_limits)

def test_device_ids_report_includes_coverage(monkeypatch):
    sample = [
        {
            "originating_endpoint": "10.0.0.1",
            "list_of_ips": ["10.0.0.1"],
            "list_of_names": ["h1"],
            "coverage_pct": 50.0,
        }
    ]
    monkeypatch.setattr(builder, "unique_identities", lambda *a, **k: sample)

    captured = {}

    def fake_report(data, headers, args, name=None):
        captured["data"] = data
        captured["headers"] = headers
        captured["name"] = name

    monkeypatch.setattr(output, "report", fake_report)

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        include_endpoints=None,
        endpoint_prefix=None,
    )

    identities = builder.unique_identities(None, args.include_endpoints, args.endpoint_prefix)
    data = []
    for identity in identities:
        data.append(
            [
                identity["originating_endpoint"],
                identity["list_of_ips"],
                identity["list_of_names"],
                identity["coverage_pct"],
            ]
        )

    output.report(
        data,
        ["Origating Endpoint", "List of IPs", "List of Names", "Coverage %"],
        args,
        name="device_ids",
    )

    assert captured["data"]
    assert captured["headers"][-1] == "Coverage %"
    assert captured["data"][0][-1] == 50.0


def test_unique_identities_uses_da_endpoint(monkeypatch):
    monkeypatch.setattr(builder.tools, "completage", lambda *a, **k: 0)
    seq = iter([[], [{"DiscoveryAccess.endpoint": "10.0.0.1"}]])
    monkeypatch.setattr(builder.api, "search_results", lambda *a, **k: next(seq))

    result = builder.unique_identities(None)

    assert result == [
        {
            "originating_endpoint": "10.0.0.1",
            "list_of_ips": [],
            "list_of_names": [],
            "coverage_pct": 0.0,
        }
    ]


def test_devices_report_contains_data(monkeypatch):
    identities = [
        {
            "originating_endpoint": "1.1.1.1",
            "list_of_ips": ["1.1.1.1"],
            "list_of_names": ["host"],
        }
    ]
    result = [
        {
            "DiscoveryAccess.endpoint": "1.1.1.1",
            "DeviceInfo.hostname": "host",
            "DiscoveryAccess.starttime": "2024-01-01 00:00:00 UTC",
            "DiscoveryRun.label": "run1",
            "DeviceInfo.last_credential": "cred-uuid",
            "DiscoveryAccess.result": "ok",
            "DiscoveryAccess.end_state": "finished",
            "DeviceInfo.kind": "server",
            "DeviceInfo.last_access_method": "ssh",
        }
    ]
    monkeypatch.setattr(reporting.builder, "unique_identities", lambda *a, **k: identities)
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: result)
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])
    monkeypatch.setattr(reporting.tools, "get_credential", lambda *a, **k: {"label": "cred1", "username": "user1"})
    monkeypatch.setattr(reporting.tools, "list_of_lists", lambda *a, **k: a[2])
    monkeypatch.setattr(reporting.tools, "sortlist", lambda l, dv=None: l)

    captured = {}

    def fake_report(data, headers, args, name=None):
        captured["data"] = data
        captured["headers"] = headers
        captured["name"] = name

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.devices(DummySearch(), DummyCreds(), args)

    assert captured["name"] == "devices"
    assert captured["data"]


def test_discovery_access_handles_bad_api(monkeypatch):
    _run_with_patches(monkeypatch, reporting.discovery_access)

def test_discovery_analysis_handles_bad_api(monkeypatch):
    _run_with_patches(monkeypatch, reporting.discovery_analysis)


def test_discovery_run_analysis_handles_bad_api(monkeypatch):
    _run_with_patches(monkeypatch, reporting.discovery_run_analysis)


def test_discovery_access_outputs_records(monkeypatch):
    sample = [
        {"endpoint": "1.1.1.1", "hostname": "h1"},
        {"endpoint": "2.2.2.2", "hostname": "h2"},
    ]

    monkeypatch.setattr(reporting, "_gather_discovery_data", lambda *a, **k: sample)

    captured = {}

    def fake_report(data, headers, args, name=None):
        captured["data"] = data
        captured["headers"] = headers
        captured["name"] = name

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        include_endpoints=None,
        endpoint_prefix=None,
    )

    result = reporting.discovery_access(DummySearch(), DummyCreds(), args)

    assert result == sample
    assert captured["name"] == "discovery_access"
    assert captured["headers"] == ["endpoint", "hostname"]
    assert captured["data"] == [["1.1.1.1", "h1"], ["2.2.2.2", "h2"]]


def test_discovery_run_analysis_outputs_records(monkeypatch):
    sample = [
        {
            "DiscoveryRun.valid_ranges": "1.1.1.1/32",
            "DiscoveryRun.label": "Run1",
            "DiscoveryRun.end_time": "2024-01-01",
            "DiscoveryRun.range_summary": "1 IP",
            "DiscoveryRun.outpost_name": "op1",
            "ScanRange.label": "SR1",
            "ScanRange.scan_kind": "Scheduled",
            "ScanRange.range": "1.1.1.1/32",
            "ScanRange.schedule": "Once",
            "DiscoveryRun.total_endpoints": 1,
            "DiscoveryRun.active_endpoints": 1,
            "DiscoveryRun.dropped": 0,
            "DiscoveryRun.scan_kinds": ["Normal"],
        }
    ]

    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: sample)

    captured = {}

    def fake_report(data, headers, args, name=None):
        captured["data"] = data
        captured["headers"] = headers
        captured["name"] = name

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(output_csv=False, output_file=None)

    reporting.discovery_run_analysis(DummySearch(), DummyCreds(), args)

    assert captured["name"] == "discovery_run_analysis"
    expected_headers = list(sample[0].keys())
    assert captured["headers"] == expected_headers
    assert captured["data"] == [list(sample[0].values())]


def test_successful_runs_without_scan_data(monkeypatch):
    call = {"n": 0}

    def fake_get_json(*a, **k):
        call["n"] += 1
        if call["n"] == 1:
            return [{"uuid": "u1", "label": "c", "index": 1, "enabled": True}]
        return []

    monkeypatch.setattr(reporting.api, "get_json", fake_get_json)
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])
    called = {}
    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=lambda *a, **k: called.setdefault("ran", True)))
    args = types.SimpleNamespace(output_csv=False, output_file=None, token=None, target="http://x", include_endpoints=None, endpoint_prefix=None)
    reporting.successful(DummyCreds(), DummySearch(), args)
    assert "ran" in called


def test_successful_combines_query_results(monkeypatch):
    calls = []

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.credential_success:
            calls.append(query)
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": 2}]
        if query is reporting.queries.deviceinfo_success:
            calls.append(query)
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": 3}]
        if query is reporting.queries.credential_failure:
            calls.append(query)
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": 4}]
        if query is reporting.queries.credential_success_7d:
            calls.append(query)
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": 1}]
        if query is reporting.queries.deviceinfo_success_7d:
            calls.append(query)
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": 1}]
        if query is reporting.queries.credential_failure_7d:
            calls.append(query)
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": 1}]
        if query is reporting.queries.outpost_credentials:
            calls.append(query)
            return []
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
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["data"] = data
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(output_csv=False, output_file=None, token=None, target="http://x", include_endpoints=None, endpoint_prefix=None)

    reporting.successful(DummyCreds(), DummySearch(), args)

    assert set(calls) == {
        reporting.queries.credential_success,
        reporting.queries.deviceinfo_success,
        reporting.queries.credential_failure,
        reporting.queries.credential_success_7d,
        reporting.queries.deviceinfo_success_7d,
        reporting.queries.credential_failure_7d,
        reporting.queries.outpost_credentials,
    }
    assert "Success % 7 Days" in captured["headers"]
    row = captured["data"][0]
    assert row[6] == 5
    assert row[7] == 4
    assert row[8] == pytest.approx(5 / 9)
    assert row[9] == pytest.approx(2 / 3)


def test_successful_coerces_string_counts(monkeypatch):
    """Counts provided as strings should be converted to numbers."""

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.credential_success:
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": "2"}]
        if query is reporting.queries.deviceinfo_success:
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": "3"}]
        if query is reporting.queries.credential_failure:
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": "4"}]
        if query is reporting.queries.credential_success_7d:
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": "1"}]
        if query is reporting.queries.deviceinfo_success_7d:
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": "1"}]
        if query is reporting.queries.credential_failure_7d:
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": "1"}]
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
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["row"] = data[0]
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    row = captured["row"]
    assert row[6] == 5
    assert row[7] == 4
    assert isinstance(row[6], int)
    assert isinstance(row[7], int)
    assert isinstance(row[8], float)
    assert isinstance(row[9], float)


def test_successful_emits_row_when_deviceinfo_7d_empty(monkeypatch):
    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.credential_success:
            return []
        if query is reporting.queries.deviceinfo_success:
            return []
        if query is reporting.queries.credential_failure:
            return []
        if query is reporting.queries.credential_success_7d:
            return []
        if query is reporting.queries.deviceinfo_success_7d:
            return []
        if query is reporting.queries.credential_failure_7d:
            return [
                {
                    "SessionResult.credential_or_slave": "u1",
                    "SessionResult.session_type": "ssh",
                    "Count": 1,
                }
            ]
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

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)
    monkeypatch.setattr(reporting.api, "get_json", fake_get_json)
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["data"] = data
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    assert len(captured["data"]) == 1
    headers = captured["headers"]
    row = captured["data"][0]
    assert row[headers.index("Successes")] == 0
    assert row[headers.index("Failures")] == 0
    assert row[headers.index("Success % 7 Days")] == 0


@pytest.mark.parametrize("output_csv", [False, True])
def test_successful_reports_zero_counts_for_inactive_credential(monkeypatch, output_csv):
    cred = {
        "uuid": "u1",
        "label": "c",
        "index": 1,
        "enabled": True,
        "username": "user",
        "usage": "",
        "iprange": None,
        "exclusions": None,
        "types": "ssh",
    }

    call = {"n": 0}

    def fake_get_json(*a, **k):
        call["n"] += 1
        if call["n"] == 1:
            return [cred]
        return []

    monkeypatch.setattr(reporting.api, "get_json", fake_get_json)
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])
    monkeypatch.setattr(reporting.tools, "completage", lambda *a, **k: 0)

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["row"] = data[0]
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=output_csv,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    row = captured["row"]
    headers = captured["headers"]
    assert row[headers.index("Successes")] == 0
    assert row[headers.index("Failures")] == 0


@pytest.mark.parametrize("output_csv", [False, True])
def test_successful_marks_explicit_zero_count_active(monkeypatch, output_csv):
    cred = {
        "uuid": "u1",
        "label": "c",
        "index": 1,
        "enabled": True,
        "username": "user",
        "usage": "",
        "iprange": None,
        "exclusions": None,
        "types": "ssh",
    }

    call = {"n": 0}

    def fake_get_json(*a, **k):
        call["n"] += 1
        if call["n"] == 1:
            return [cred]
        return []

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.credential_success:
            return [
                {
                    "SessionResult.slave_or_credential": "u1",
                    "SessionResult.session_type": "ssh",
                    "Count": 0,
                }
            ]
        return []

    monkeypatch.setattr(reporting.api, "get_json", fake_get_json)
    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])
    monkeypatch.setattr(reporting.tools, "completage", lambda *a, **k: 0)

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["row"] = data[0]
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=output_csv,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    row = captured["row"]
    headers = captured["headers"]
    assert row[headers.index("Successes")] == 0
    assert row[headers.index("Failures")] == 0
    assert row[headers.index("State")] == "Enabled"


def test_successful_includes_outpost_credentials(monkeypatch):
    out_cred = {
        "uuid": "u1",
        "label": "c",
        "index": 1,
        "enabled": True,
        "username": "user",
        "usage": "",
        "iprange": None,
        "exclusions": None,
    }

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.credential_success:
            return [
                {
                    "SessionResult.credential_or_slave": "/prefix/u1",
                    "SessionResult.session_type": "ssh",
                    "Count": 2,
                }
            ]
        if query is reporting.queries.credential_failure:
            return [
                {
                    "SessionResult.credential_or_slave": "/prefix/u1",
                    "SessionResult.session_type": "ssh",
                    "Count": 1,
                }
            ]
        if query is reporting.queries.outpost_credentials:
            return [{"credential": "u1", "outpost": "op1"}]
        return []

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [out_cred])
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {"op1": {"url": "http://op1", "credentials": []}})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["row"] = data[0]
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    row = captured["row"]
    headers = captured["headers"]
    assert row[headers.index("Successes")] == 2
    assert row[headers.index("Failures")] == 1
    assert row[-1] == "http://op1"


def test_successful_shows_zero_percent_when_no_success_7d(monkeypatch):
    """If there are no successes in last 7 days, percent should be 0."""

    out_cred = {
        "uuid": "u1",
        "label": "c",
        "index": 1,
        "enabled": True,
        "username": "user",
        "usage": "",
        "iprange": None,
        "exclusions": None,
    }

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.credential_success:
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": 2}]
        if query is reporting.queries.credential_failure:
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": 1}]
        if query is reporting.queries.credential_failure_7d:
            return [{"SessionResult.credential_or_slave": "u1", "SessionResult.session_type": "ssh", "Count": 1}]
        return []

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [out_cred])
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["row"] = data[0]
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    row = captured["row"]
    headers = captured["headers"]
    assert row[headers.index("Success % 7 Days")] == 0


def test_successful_handles_prefixed_and_mixed_case_credential_paths(monkeypatch):
    """Query results may return object-path prefixes and mixed-case UUIDs."""

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.credential_success:
            return [
                {
                    "SessionResult.credential_or_slave": "Credential/U1",
                    "SessionResult.session_type": "ssh",
                    "Count": 2,
                }
            ]
        if query is reporting.queries.deviceinfo_success:
            return [
                {
                    "DeviceInfo.last_credential": "Credential/U1",
                    "DeviceInfo.access_method": "ssh",
                    "Count": 3,
                }
            ]
        if query is reporting.queries.credential_failure:
            return [
                {
                    "SessionResult.credential_or_slave": "Credential/U1",
                    "SessionResult.session_type": "ssh",
                    "Count": 4,
                }
            ]
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
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["row"] = data[0]
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    headers = captured["headers"]
    row = captured["row"]
    idx_s = headers.index("Successes")
    idx_f = headers.index("Failures")
    assert row[idx_s] == 5
    assert row[idx_f] == 4


def test_successful_uses_uuid_for_failures(monkeypatch):
    """Failure queries may only include a raw 'uuid' field."""

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.credential_failure:
            return [
                {
                    "uuid": "Credential/u1",
                    "SessionResult.session_type": "ssh",
                    "Count": 4,
                }
            ]
        if query is reporting.queries.credential_failure_7d:
            return [
                {"uuid": "u1", "SessionResult.session_type": "ssh", "Count": 1}
            ]
        if any(
            query == q
            for q in [
                reporting.queries.credential_success,
                reporting.queries.deviceinfo_success,
                reporting.queries.credential_success_7d,
                reporting.queries.deviceinfo_success_7d,
                reporting.queries.outpost_credentials,
            ]
        ):
            return []
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
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["headers"] = headers
        captured["row"] = data[0]

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    headers = captured["headers"]
    row = captured["row"]
    idx_s = headers.index("Successes")
    idx_f = headers.index("Failures")
    assert row[idx_s] == 0
    assert row[idx_f] == 4


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
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])
    monkeypatch.setattr(reporting.builder, "unique_identities", lambda s, *a, **k: [])
    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=lambda *a, **k: None))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        token=None,
        f_token=str(file_path),
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(DummyCreds(), DummySearch(), args)

    assert captured["token"] == "abc"


def test_discovery_analysis_includes_raw_timestamp(monkeypatch):
    class DummyDF(dict):
        def __init__(self, data):
            super().__init__({k: {0: v[0] if isinstance(v, list) else v} for k, v in data.items()})

        def __getitem__(self, key):
            return self.get(key)

        def __setitem__(self, key, value):
            dict.__setitem__(self, key, {0: value})

        def to_dict(self):
            return self

    monkeypatch.setattr(reporting.builder, "unique_identities", lambda s, *a, **k: [])

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.last_disco:
            return [
                {
                    "Endpoint": "1.1.1.1",
                    "Scan_Endtime": "2024-01-01 00:00:00",
                    "Scan_Endtime_Raw": "2024-01-01T00:00:00+00:00",
                    "End_State": "OK",
                }
            ]
        if query is reporting.queries.dropped_endpoints:
            return [
                {
                    "Endpoint": "2.2.2.2",
                    "End": "2024-01-02 00:00:00",
                    "End_Raw": "2024-01-02T00:00:00+00:00",
                    "Run": "r",
                    "Start": "2024-01-02 00:00:00",
                    "End_State": "DarkSpace",
                }
            ]
        return []

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.pd, "DataFrame", lambda data: DummyDF(data), raising=False)
    monkeypatch.setattr(reporting.pd, "cut", lambda *a, **k: "recent", raising=False)

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["data"] = data
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=True,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.discovery_analysis(DummySearch(), DummyCreds(), args)

    idx = captured["headers"].index("scan_end_raw")
    disco_row = next(row for row in captured["data"] if row[0] == "1.1.1.1")
    dropped_row = next(row for row in captured["data"] if row[0] == "2.2.2.2")

    assert disco_row[idx] == "2024-01-01T00:00:00+00:00"
    assert dropped_row[idx] == "2024-01-02T00:00:00+00:00"


def test_discovery_analysis_merges_latest_fields(monkeypatch):
    """Fields missing from the chosen record are populated from the latest."""

    class DummyDF(dict):
        def __init__(self, data):
            super().__init__({k: {0: v[0] if isinstance(v, list) else v} for k, v in data.items()})

        def __getitem__(self, key):
            return self.get(key)

        def __setitem__(self, key, value):
            dict.__setitem__(self, key, {0: value})

        def to_dict(self):
            return self

    monkeypatch.setattr(reporting.builder, "unique_identities", lambda s, *a, **k: [])

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query is reporting.queries.last_disco:
            return [
                {
                    "Endpoint": "1.1.1.1",
                    "Hostname": "oldhost",
                    "Scan_Endtime": "2024-01-01 00:00:00",
                    "Scan_Endtime_Raw": "2024-01-01T00:00:00+00:00",
                    "End_State": "OK",
                },
                {
                    "Endpoint": "1.1.1.1",
                    "Scan_Endtime": "2024-01-02 00:00:00",
                    "Scan_Endtime_Raw": "2024-01-02T00:00:00+00:00",
                    "End_State": "Failed",
                    "Host_Node_Updated": "2024-01-02 00:00:00",
                },
                {
                    "Endpoint": "3.3.3.3",
                    "Scan_Endtime": "2024-01-03 00:00:00",
                    "Scan_Endtime_Raw": "2024-01-03T00:00:00+00:00",
                    "End_State": "OK",
                    "DeviceInfo.last_credential": "cred1",
                },
            ]
        if query is reporting.queries.dropped_endpoints:
            return []
        return []

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)
    monkeypatch.setattr(
        reporting.api,
        "get_json",
        lambda *a, **k: [{"uuid": "cred1", "label": "CRED", "username": "user"}],
    )
    monkeypatch.setattr(reporting.api, "get_outpost_credential_map", lambda *a, **k: {})
    monkeypatch.setattr(reporting.pd, "DataFrame", lambda data: DummyDF(data), raising=False)
    monkeypatch.setattr(reporting.pd, "cut", lambda *a, **k: "recent", raising=False)

    captured = {}

    def fake_report(data, headers, args, name=""):
        captured["data"] = data
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=True,
        output_file=None,
        token=None,
        target="http://x",
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.discovery_analysis(DummySearch(), DummyCreds(), args)

    headers = captured["headers"]
    rows = {row[0]: row for row in captured["data"]}
    first = rows["1.1.1.1"]
    second = rows["3.3.3.3"]

    assert first[headers.index("device_name")] == "oldhost"
    assert first[headers.index("inferred_node_updated")] == "2024-01-02 00:00:00"
    assert second[headers.index("credential_name")] == "CRED"


def test_outpost_creds_builds_rows(monkeypatch):
    op_map = {"op1": {"url": "http://op1", "credentials": ["c1", "c2"]}}

    monkeypatch.setattr(
        reporting.api, "get_outpost_credential_map", lambda search, app: op_map
    )
    monkeypatch.setattr(
        reporting.api,
        "get_json",
        lambda *a, **k: [
            {"uuid": "c1", "label": "Cred1"},
            {"uuid": "c2", "label": "Cred2"},
        ],
    )

    captured = {}

    def fake_report(data, headers, args, name=None):
        captured["data"] = data
        captured["headers"] = headers
        captured["name"] = name

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    creds = types.SimpleNamespace(get_vault_credentials=None)
    args = types.SimpleNamespace(output_csv=False, output_file=None)

    reporting.outpost_creds(creds, None, object(), args)

    assert captured["name"] == "outpost_creds"
    assert captured["headers"] == [
        "Outpost",
        "Outpost Id",
        "Credential UUID",
        "Credential Label",
    ]
    assert captured["data"] == [
        ["http://op1", "op1", "c1", "Cred1"],
        ["http://op1", "op1", "c2", "Cred2"],
    ]


def test_successful_handles_dict_results(monkeypatch):
    cred = {
        "uuid": "u1",
        "index": 1,
        "label": "cred1",
        "username": "user1",
        "enabled": True,
        "types": "ssh",
        "usage": "",
        "ip_range": None,
        "ip_exclusion": None,
    }

    creds = types.SimpleNamespace()
    creds.get_vault_credentials = lambda: None

    def fake_get_json(arg):
        if arg == creds.get_vault_credentials:
            return [cred]
        return []

    monkeypatch.setattr(reporting.api, "get_json", fake_get_json)

    def fake_search_results(search, query, limit=500, *args, **kwargs):
        if query == reporting.queries.credential_success:
            return {
                "results": [
                    {
                        "SessionResult.slave_or_credential": "credential/u1",
                        "SessionResult.session_type": "ssh",
                        "Count": 2,
                    }
                ]
            }
        if query == reporting.queries.deviceinfo_success:
            return {
                "results": [
                    {
                        "DeviceInfo.last_credential": "credential/u1",
                        "DeviceInfo.access_method": "ssh",
                        "Count": 1,
                    }
                ]
            }
        return {"results": []}

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)

    captured = {}

    def fake_report(data, headers, args, name=None):
        captured["data"] = data
        captured["headers"] = headers

    monkeypatch.setattr(reporting, "output", types.SimpleNamespace(report=fake_report))

    args = types.SimpleNamespace(
        output_csv=False,
        output_file=None,
        target=None,
        include_endpoints=None,
        endpoint_prefix=None,
    )

    reporting.successful(creds, DummySearch(), args)

    headers = captured["headers"]
    row = captured["data"][0]

    assert row[headers.index("State")] == "Enabled"
    assert row[headers.index("Successes")] == 3


def test_successful_cli_parses_new_headers(monkeypatch):
    cred = {
        "uuid": "u1",
        "label": "c",
        "username": "user",
        "iprange": None,
        "exclusions": None,
        "enabled": True,
        "types": "ssh",
        "usage": "",
        "internal_store": "",
    }

    def fake_remote_cmd(cmd, client):
        if cmd.startswith("tw_vault_control"):
            return json.dumps(cred)
        if reporting.queries.credential_success in cmd:
            return (
                "SessionResult.credential_or_slave,uuid,SessionResult.session_type,SessionResult.outpost,Count\n"
                "credential/u1,credential/u1,ssh,op1,2\n"
            )
        if reporting.queries.deviceinfo_success in cmd:
            return (
                "DeviceInfo.last_credential,DeviceInfo.access_method,Count\n"
                "credential/u1,ssh,3\n"
            )
        if reporting.queries.credential_failure in cmd:
            return (
                "SessionResult.credential_or_slave,uuid,SessionResult.session_type,SessionResult.outpost,Count\n"
                "credential/u1,credential/u1,ssh,op1,4\n"
            )
        return ""

    monkeypatch.setattr(reporting.access, "remote_cmd", fake_remote_cmd)
    monkeypatch.setattr(reporting.tools, "extract_credential", lambda d: d)

    captured = {}

    def fake_csv_file(data, headers, filename):
        captured["data"] = data
        captured["headers"] = headers

    monkeypatch.setattr(reporting.output, "csv_file", fake_csv_file)

    args = types.SimpleNamespace(target="appl")

    reporting.successful_cli("client", args, "user", "pass", ".")

    row = captured["data"][0]
    assert row[5] == 5  # successes
    assert row[6] == 4  # failures
