import pytest
import yaml


@pytest.fixture
def multi_appliance_config(tmp_path):
    """Create temporary config.yaml with two appliance entries."""
    token_file = tmp_path / "token_file.txt"
    token_file.write_text("file-token")

    config = {
        "appliances": [
            {"target": "app1", "token": "tok1"},
            {"target": "app2", "token_file": str(token_file), "password": "pw2"},
        ]
    }

    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))
    return config_path, str(token_file)
