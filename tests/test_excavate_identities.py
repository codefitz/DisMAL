import sys
import types

# Stub out optional dependencies used by the project so imports succeed
sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())

sys.argv = [sys.argv[0]]

import dismal


def test_excavate_devices_and_ids_calls_unique_once(monkeypatch):
    """Ensure device and device_ids reports share identity lookup."""

    calls = {"count": 0}

    def fake_unique(
        search, include_endpoints=None, endpoint_prefix=None, max_endpoints=None
    ):
        calls["count"] += 1
        return [
            {
                "originating_endpoint": "1.1.1.1",
                "list_of_ips": ["1.1.1.1"],
                "list_of_names": ["h1"],
            }
        ]

    monkeypatch.setattr(dismal.builder, "unique_identities", fake_unique)

    captured = {}

    def fake_devices(search, creds, args, identities=None):
        captured["ids"] = identities

    monkeypatch.setattr(dismal.reporting, "devices", fake_devices)
    monkeypatch.setattr(dismal.output, "report", lambda *a, **k: None)

    for name in ["ordering", "scheduling", "ip_analysis"]:
        monkeypatch.setattr(dismal.builder, name, lambda *a, **k: None)

    api_funcs = [
        "success",
        "excludes",
        "show_runs",
        "discovery_runs",
        "tpl_export",
        "eca_errors",
        "open_ports",
        "host_util",
        "orphan_vms",
        "missing_vms",
        "near_removal",
        "removed",
        "oslc",
        "slc",
        "dblc",
        "snmp",
        "capture_candidates",
        "agents",
        "expected_agents",
        "software_users",
        "tku",
        "outpost_creds",
        "vault",
        "hostname",
        "sensitive",
    ]
    for name in api_funcs:
        monkeypatch.setattr(dismal.api, name, lambda *a, **k: None)

    monkeypatch.setattr(dismal.reporting, "discovery_run_analysis", lambda *a, **k: None)

    monkeypatch.setattr(dismal.access, "api_target", lambda args: True)
    monkeypatch.setattr(
        dismal.api,
        "init_endpoints",
        lambda target, args: (None, object(), object(), None, None),
    )
    monkeypatch.setattr(dismal.access, "login_target", lambda target, args: (None, None))
    monkeypatch.setattr(dismal.os.path, "exists", lambda path: True)
    monkeypatch.setattr(dismal.os, "makedirs", lambda *a, **k: None)

    args = types.SimpleNamespace(
        version=False,
        wakey=False,
        target="appl",
        access_method="api",
        username=None,
        password=None,
        f_passwd=None,
        token=None,
        f_token=None,
        noping=True,
        output_path=None,
        excavate=[],
        output_csv=False,
        output_file=None,
        include_endpoints=None,
        endpoint_prefix=None,
        a_query=None,
        a_kill_run=None,
        schedule_timezone=None,
        reset_schedule_timezone=False,
        sysadmin=None,
        tideway=None,
        clear_queue=False,
        tw_user=None,
        servicecctl=None,
        debugging=False,
        output_cli=False,
        output_null=False,
        a_enable=None,
        f_enablelist=None,
        a_opt=None,
        a_removal=None,
        f_remlist=None,
    )

    dismal.run_for_args(args)
    import logging
    logging.basicConfig(level=logging.WARNING, force=True)

    assert calls["count"] == 1
    assert captured["ids"]

