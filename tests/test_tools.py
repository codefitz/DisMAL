import os
import sys
import ipaddress

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import core.tools as tools


def test_range_to_ips_empty():
    assert tools.range_to_ips("") == []
    assert tools.range_to_ips(None) == []


def test_range_to_ips_single_ip():
    result = tools.range_to_ips("192.168.1.1")
    assert result == [ipaddress.ip_network("192.168.1.1/32")]


def test_range_to_ips_subnet():
    result = tools.range_to_ips("192.168.1.0/30")
    expected = [ipaddress.ip_network("192.168.1.0/30")]
    assert result == expected


def test_range_to_ips_cloud_or_all():
    assert tools.range_to_ips("cloud-endpoint") == ["cloud-endpoint"]
    assert tools.range_to_ips("0.0.0.0/0,::/0") == ["0.0.0.0/0,::/0"]


def test_dequote_removes_quotes():
    assert tools.dequote('"hello"') == "hello"


def test_dequote_no_change():
    assert tools.dequote("hello") == "hello"
    assert tools.dequote("'hello'") == "'hello'"

def test_json2csv_returns_headers_and_map():
    data = [{"Person.first_name": "Jane", "Person.last_name": "Doe"}]
    header, rows, lookup = tools.json2csv(data, return_map=True)
    assert header == ["Person.first_name", "Person.last_name"]
    assert rows == [["Jane", "Doe"]]
    assert lookup == {
        "Person.first_name": "Person.first_name",
        "Person.last_name": "Person.last_name",
    }


def test_session_get_falls_back_to_uuid():
    results = [
        {
            "uuid": "Credential/u1",
            "SessionResult.session_type": "ssh",
            "Count": "1",
        }
    ]
    assert tools.session_get(results) == {"u1": ["ssh", 1]}


def test_session_get_normalizes_uuid_case():
    results = [
        {
            "uuid": "Credential/ABCDEF",
            "SessionResult.session_type": "ssh",
            "Count": "1",
        }
    ]
    assert tools.session_get(results) == {"abcdef": ["ssh", 1]}


def test_session_get_dict_wrapper():
    payload = {
        "results": [
            {
                "uuid": "Credential/u1",
                "SessionResult.session_type": "ssh",
                "Count": "1",
            },
            {
                "uuid": "Credential/u2",
                "SessionResult.session_type": "snmp",
                "Count": "3",
            },
        ]
    }
    assert tools.session_get(payload) == {
        "u1": ["ssh", 1],
        "u2": ["snmp", 3],
    }
