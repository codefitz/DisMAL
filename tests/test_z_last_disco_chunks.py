import importlib
import types
import sys
import importlib
import logging

# Ensure real pandas is available for this test
sys.modules.pop("pandas", None)
import pandas as pd  # noqa: F401

import core.reporting as reporting
import core.queries as queries
import core.api as api

# Reload reporting to bind the real pandas module
importlib.reload(reporting)


class DummySearch:
    pass


def test_chunked_last_disco_merges(monkeypatch):
    """The chunked query pieces are joined into a single DataFrame."""

    device_keys = [{"DiscoveryAccess.id": 1, "DeviceInfo.id": 10}]
    run_keys = [{"DiscoveryAccess.id": 1, "DiscoveryRun.id": 20}]
    inferred_keys = [{"DiscoveryAccess.id": 1, "InferredElement.id": 30}]
    session_keys = [{"DiscoveryAccess.id": 1, "SessionResult.id": 40}]
    interface_keys = [{"DiscoveryAccess.id": 1, "NetworkInterface.id": 50}]

    access_data = [
        {
            "DiscoveryAccess.id": 1,
            "DiscoveryAccess.end_state": "OK",
            "DiscoveryAccess.previous_id": 2,
            "DiscoveryAccess.next_id": None,
        },
        {
            "DiscoveryAccess.id": 2,
            "DiscoveryAccess.end_state": "Fail",
            "DiscoveryAccess.previous_id": None,
            "DiscoveryAccess.next_id": 1,
        },
    ]
    device_data = [
        {
            "DeviceInfo.id": 10,
            "DeviceInfo.hostname": "h",
            "DeviceInfo.last_access_method": "ssh",
            "DeviceInfo.last_slave": None,
            "DeviceInfo.probed_os": None,
        }
    ]
    run_data = [{"DiscoveryRun.id": 20, "DiscoveryRun.label": "r"}]
    session_data = [
        {
            "SessionResult.id": 40,
            "SessionResult.success": True,
            "SessionResult.session_type": "telnet",
            "SessionResult.provider": None,
        }
    ]
    inferred_data = [
        {
            "InferredElement.id": 30,
            "InferredElement.__all_ip_addrs": "1.1.1.1",
        }
    ]
    interface_data = [
        {"NetworkInterface.id": 50, "NetworkInterface.ip_addr": "1.1.1.1"}
    ]

    def fake_search_results(_search, query, *args, **kwargs):
        if query is queries.last_disco_key_deviceinfo:
            return device_keys
        if query is queries.last_disco_key_run:
            return run_keys
        if query is queries.last_disco_key_inferred:
            return inferred_keys
        if query is queries.last_disco_key_session:
            return session_keys
        if query is queries.last_disco_key_interface:
            return interface_keys
        if query is queries.last_disco_access:
            return access_data
        if query is queries.last_disco_deviceinfo:
            return device_data
        if query is queries.last_disco_run:
            return run_data
        if query is queries.last_disco_session:
            return session_data
        if query is queries.last_disco_inferred:
            return inferred_data
        if query is queries.last_disco_interface:
            return interface_data
        return []

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)

    df = reporting.chunked_last_disco(DummySearch())

    assert df.loc[0, "DiscoveryAccess.previous_end_state"] == "Fail"
    assert df.loc[0, "DiscoveryAccess.access_method"] == "ssh"
    assert df.loc[0, "DiscoveryAccess.current_access"] == "ssh"
    assert bool(df.loc[0, "DiscoveryAccess.session_results_logged"]) is True


def test_chunked_last_disco_matches_wide(monkeypatch):
    """Chunked output matches the original wide query for small fixtures."""

    device_keys = [{"DiscoveryAccess.id": 1, "DeviceInfo.id": 10}]
    run_keys = [{"DiscoveryAccess.id": 1, "DiscoveryRun.id": 20}]
    inferred_keys = [{"DiscoveryAccess.id": 1, "InferredElement.id": 30}]
    session_keys = [{"DiscoveryAccess.id": 1, "SessionResult.id": 40}]
    interface_keys = [{"DiscoveryAccess.id": 1, "NetworkInterface.id": 50}]

    access_data = [
        {
            "DiscoveryAccess.id": 1,
            "DiscoveryAccess.end_state": "OK",
            "DiscoveryAccess.previous_id": 2,
            "DiscoveryAccess.next_id": None,
        },
        {
            "DiscoveryAccess.id": 2,
            "DiscoveryAccess.end_state": "Fail",
            "DiscoveryAccess.previous_id": None,
            "DiscoveryAccess.next_id": 1,
        },
    ]
    device_data = [
        {
            "DeviceInfo.id": 10,
            "DeviceInfo.hostname": "h",
            "DeviceInfo.last_access_method": "ssh",
            "DeviceInfo.last_slave": None,
            "DeviceInfo.probed_os": None,
        }
    ]
    run_data = [{"DiscoveryRun.id": 20, "DiscoveryRun.label": "r"}]
    session_data = [
        {
            "SessionResult.id": 40,
            "SessionResult.success": True,
            "SessionResult.session_type": "telnet",
            "SessionResult.provider": None,
        }
    ]
    inferred_data = [
        {
            "InferredElement.id": 30,
            "InferredElement.__all_ip_addrs": "1.1.1.1",
        }
    ]
    interface_data = [
        {"NetworkInterface.id": 50, "NetworkInterface.ip_addr": "1.1.1.1"}
    ]

    wide_data = [
        {
            "DiscoveryAccess.id": 1,
            "DiscoveryAccess.previous_id": 2,
            "DiscoveryAccess.next_id": None,
            "DeviceInfo.id": 10,
            "DiscoveryRun.id": 20,
            "InferredElement.id": 30,
            "SessionResult.id": 40,
            "NetworkInterface.id": 50,
            "DiscoveryAccess.end_state": "OK",
            "DeviceInfo.hostname": "h",
            "DeviceInfo.last_access_method": "ssh",
            "DeviceInfo.last_slave": None,
            "DeviceInfo.probed_os": None,
            "DiscoveryRun.label": "r",
            "SessionResult.success": True,
            "SessionResult.session_type": "telnet",
            "SessionResult.provider": None,
            "InferredElement.__all_ip_addrs": "1.1.1.1",
            "NetworkInterface.ip_addr": "1.1.1.1",
            "DiscoveryAccess.previous_end_state": "Fail",
            "DiscoveryAccess.access_method": "ssh",
            "DiscoveryAccess.current_access": "ssh",
            "DiscoveryAccess.session_results_logged": True,
        }
    ]

    def fake_search_results(_search, query, *args, **kwargs):
        if query is queries.last_disco:
            return wide_data
        if query is queries.last_disco_key_deviceinfo:
            return device_keys
        if query is queries.last_disco_key_run:
            return run_keys
        if query is queries.last_disco_key_inferred:
            return inferred_keys
        if query is queries.last_disco_key_session:
            return session_keys
        if query is queries.last_disco_key_interface:
            return interface_keys
        if query is queries.last_disco_access:
            return access_data
        if query is queries.last_disco_deviceinfo:
            return device_data
        if query is queries.last_disco_run:
            return run_data
        if query is queries.last_disco_session:
            return session_data
        if query is queries.last_disco_inferred:
            return inferred_data
        if query is queries.last_disco_interface:
            return interface_data
        return []

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)

    chunked = reporting.chunked_last_disco(DummySearch())
    wide = pd.DataFrame(wide_data)

    pd.testing.assert_frame_equal(
        chunked.sort_index(axis=1), wide.sort_index(axis=1), check_dtype=False
    )


def test_chunked_last_disco_warns_on_partial_timeout(monkeypatch, capsys):
    """Failures in a sub-query trigger a warning but return partial data."""

    device_keys = [{"DiscoveryAccess.id": 1, "DeviceInfo.id": 10}]

    access_data = [
        {
            "DiscoveryAccess.id": 1,
            "DiscoveryAccess.end_state": "OK",
            "DiscoveryAccess.previous_id": None,
            "DiscoveryAccess.next_id": None,
        }
    ]
    device_data = [
        {
            "DeviceInfo.id": 10,
            "DeviceInfo.last_access_method": "ssh",
            "DeviceInfo.last_slave": None,
            "DeviceInfo.probed_os": None,
        }
    ]

    def fake_search_results(_search, query, *args, **kwargs):
        if query is queries.last_disco_key_deviceinfo:
            return device_keys
        if query is queries.last_disco_key_run:
            return {"error": "timeout"}
        if query is queries.last_disco_access:
            return access_data
        if query is queries.last_disco_deviceinfo:
            return device_data
        return []

    monkeypatch.setattr(reporting.api, "search_results", fake_search_results)

    reporting.chunked_last_disco(DummySearch())
    captured = capsys.readouterr()
    assert "partial data" in captured.out

def test_chunked_last_disco_timeout(monkeypatch, caplog):
    """Timeouts in any chunk return an empty DataFrame."""

    def raise_timeout(_search, query, *args, **kwargs):
        raise api.APITimeoutError()

    monkeypatch.setattr(reporting.api, "search_results", raise_timeout)
    with caplog.at_level(logging.WARNING):
        df = reporting.chunked_last_disco(DummySearch())
    assert df.empty
    assert any("timed out" in r.message for r in caplog.records)

