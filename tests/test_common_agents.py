import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import common_agents


def test_expected_and_missing_agents_detection():
    csv_data = (
        "Host_Name,Running_Software\n"
        "host1,AgentA;AgentB\n"
        "host2,AgentA;AgentC\n"
        "host3,AgentA;AgentB\n"
    )
    records = common_agents.parse_agent_csv(csv_data)
    expected = common_agents.get_expected_agents(records, threshold=0.6)
    assert expected == {"AgentA", "AgentB"}
    missing = common_agents.find_missing_agents(records, expected)
    assert missing == [{"Host_Name": "host2", "Missing_Agents": ["AgentB"]}]

