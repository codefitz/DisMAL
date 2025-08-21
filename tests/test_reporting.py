import os
import sys
import types
import pytest
import core.builder as builder
import core.output as output

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

    assert captured["headers"][-1] == "Coverage %"
    assert captured["data"][0][-1] == 50.0


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

    def fake_search_results(search, query):
        calls.append(query)
        if query is reporting.queries.credential_success:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": 2}]
        if query is reporting.queries.deviceinfo_success:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": 3}]
        if query is reporting.queries.credential_failure:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": 4}]
        if query is reporting.queries.credential_success_7d:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": 1}]
        if query is reporting.queries.deviceinfo_success_7d:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": 1}]
        if query is reporting.queries.credential_failure_7d:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": 1}]
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
    }
    assert "Success % 7 Days" in captured["headers"]
    row = captured["data"][0]
    assert row[6] == 5
    assert row[7] == 4
    assert row[8] == pytest.approx(5 / 9)
    assert row[9] == pytest.approx(2 / 3)


def test_successful_coerces_string_counts(monkeypatch):
    """Counts provided as strings should be converted to numbers."""

    def fake_search_results(search, query):
        if query is reporting.queries.credential_success:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": "2"}]
        if query is reporting.queries.deviceinfo_success:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": "3"}]
        if query is reporting.queries.credential_failure:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": "4"}]
        if query is reporting.queries.credential_success_7d:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": "1"}]
        if query is reporting.queries.deviceinfo_success_7d:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": "1"}]
        if query is reporting.queries.credential_failure_7d:
            return [{"SessionResult.uuid": "u1", "SessionResult.session_type": "ssh", "SessionResult.count": "1"}]
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

    monkeypatch.setattr(
        reporting.api,
        "get_outpost_credential_map",
        lambda *a, **k: {"u1": "http://op"},
    )
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [out_cred])
    monkeypatch.setattr(reporting.api, "search_results", lambda *a, **k: [])
    monkeypatch.setattr(reporting.builder, "get_credentials", lambda entry: entry)
    monkeypatch.setattr(reporting.builder, "get_scans", lambda *a, **k: [])
    monkeypatch.setattr(
        reporting.tideway, "appliance", lambda target, token: object(), raising=False
    )

    captured = {}

    def fake_report(data, headers, args, name=""):
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

    assert captured["row"][-1] == "http://op"


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

    def fake_search_results(search, query):
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

    def fake_search_results(search, query):
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
                    "Last_Credential": "cred1",
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
