import types
import datetime
import core.reporting as reporting

class DummySearch:
    pass

class DummyCreds:
    def get_vault_credentials(self):
        return None

def _setup_pandas(monkeypatch, when_values):
    class DummyDF(dict):
        def __init__(self, data):
            self.data = data
        def __getitem__(self, key):
            return self.data[key]
        def __setitem__(self, key, value):
            self.data[key] = value
        def to_dict(self):
            return {k: {0: v} for k, v in self.data.items()}
    counter = {"i": 0}
    def fake_df(data):
        return DummyDF(data)
    def fake_cut(col, bins, labels, right=False):
        v = when_values[counter["i"]]
        counter["i"] += 1
        return v
    monkeypatch.setattr(reporting.pd, "DataFrame", fake_df, raising=False)
    monkeypatch.setattr(reporting.pd, "cut", fake_cut, raising=False)

def _run(monkeypatch, discos, dropped, when_values):
    def fake_chunked(_search):
        class DummyChunkDF(dict):
            def __init__(self, records):
                self.records = records
                self.empty = not bool(records)
            def to_dict(self, orient="records"):
                return self.records
        return DummyChunkDF(discos)

    def fake_search_results(search, query, *args, **kwargs):
        if query is reporting.queries.dropped_endpoints:
            return dropped
        return []

    monkeypatch.setattr(reporting, "chunked_last_disco", fake_chunked)
    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)
    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [{"uuid": "c1", "label": "cred1", "username": "u"}])
    monkeypatch.setattr(reporting.tools, "get_credential", lambda creds, uuid: creds[0])
    monkeypatch.setattr(reporting.builder, "unique_identities", lambda *a, **k: [])
    _setup_pandas(monkeypatch, when_values)
    args = types.SimpleNamespace(include_endpoints=None, endpoint_prefix=None)
    return reporting._gather_discovery_data(DummySearch(), DummyCreds(), args)

def test_prefers_named_and_updates_timestamp(monkeypatch):
    older = {
        "DiscoveryAccess.endpoint": "1.2.3.4",
        "DeviceInfo.hostname": "h1",
        "DiscoveryAccess.scan_endtime": "2024-01-01 00:05:00 +0000",
        "DiscoveryRun.endtime": "2024-01-01 00:05:00 +0000",
        "DiscoveryRun.starttime": "2024-01-01 00:00:00 +0000",
        "DiscoveryAccess.scan_starttime": "2024-01-01 00:00:00 +0000",
        "DiscoveryRun.label": "r1",
        "DiscoveryAccess.end_state": "Complete",
        "DiscoveryAccess.previous_end_state": "DarkSpace",
        "DeviceInfo.last_credential": "c1",
    }
    newer = dict(older)
    newer.update({
        "DeviceInfo.hostname": None,
        "DeviceInfo.last_credential": None,
        "DiscoveryAccess.scan_endtime": "2024-02-01 00:05:00 +0000",
        "DiscoveryRun.endtime": "2024-02-01 00:05:00 +0000",
        "DiscoveryRun.starttime": "2024-02-01 00:00:00 +0000",
        "DiscoveryAccess.scan_starttime": "2024-02-01 00:00:00 +0000",
    })
    result = _run(monkeypatch, [older, newer], [], ["old", "new"])
    assert len(result) == 1
    record = result[0]
    assert record["hostname"] == "h1"
    assert record["credential_name"] == "cred1"
    ts_new = datetime.datetime.strptime("2024-02-01 00:05:00", "%Y-%m-%d %H:%M:%S")
    assert record["timestamp"] == ts_new
    assert record["when_was_that"] == "new"

def test_picks_latest_when_no_names(monkeypatch):
    older = {
        "DiscoveryAccess.endpoint": "1.2.3.4",
        "DeviceInfo.hostname": None,
        "DiscoveryAccess.scan_endtime": "2024-01-01 00:05:00 +0000",
        "DiscoveryRun.endtime": "2024-01-01 00:05:00 +0000",
        "DiscoveryRun.starttime": "2024-01-01 00:00:00 +0000",
        "DiscoveryAccess.scan_starttime": "2024-01-01 00:00:00 +0000",
        "DiscoveryRun.label": "r1",
        "DiscoveryAccess.end_state": "Complete",
        "DiscoveryAccess.previous_end_state": "DarkSpace",
        "DeviceInfo.last_credential": None,
    }
    newer = dict(older)
    newer.update({
        "DiscoveryAccess.scan_endtime": "2024-02-01 00:05:00 +0000",
        "DiscoveryRun.endtime": "2024-02-01 00:05:00 +0000",
        "DiscoveryRun.starttime": "2024-02-01 00:00:00 +0000",
        "DiscoveryAccess.scan_starttime": "2024-02-01 00:00:00 +0000",
    })
    result = _run(monkeypatch, [older, newer], [], ["old", "new"])
    assert len(result) == 1
    record = result[0]
    ts_new = datetime.datetime.strptime("2024-02-01 00:05:00", "%Y-%m-%d %H:%M:%S")
    assert record["timestamp"] == ts_new
    assert record.get("hostname") is None
    assert record.get("credential_name") is None
    assert record["when_was_that"] == "new"


def test_dropped_record_includes_consistency(monkeypatch):
    dropped = {
        "Endpoint": "1.2.3.4",
        "Run": "r1",
        "Start": "2024-02-01 00:00:00 +0000",
        "End": "2024-02-01 00:05:00 +0000",
        "End_State": "DarkSpace",
        "Reason_Not_Updated": None,
    }
    result = _run(monkeypatch, [], [dropped], ["recent"])
    assert len(result) == 1
    record = result[0]
    assert record["consistency"] == "Always DarkSpace"
