#!/usr/bin/env python3
"""Run the devices report using configuration from config.yaml.

This script loads API connection details from a local config.yaml file and
executes the devices report without requiring any command-line arguments.
"""

import io
import logging
import os
import sys
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
import yaml

# Dependencies from the DisMAL core modules
from core.access import api_target  # core.access.api_target
from core.api import (
    init_endpoints,  # core.api.init_endpoints
    get_json,  # core.api.get_json
    devices_lookup,  # core.api.devices_lookup
)
from core.builder import unique_identities  # core.builder.unique_identities
from core.reporting import devices  # core.reporting.devices


def load_config(path: str) -> dict:
    """Load the YAML configuration file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def build_args(config: dict) -> Namespace:
    """Build an argparse Namespace compatible with DisMAL modules."""
    # Use the first appliance entry if a list is provided
    appliance = None
    appliances = config.get("appliances")
    if isinstance(appliances, list) and appliances:
        appliance = appliances[0]
    else:
        appliance = config

    args = Namespace(
        access_method=appliance.get("access_method", config.get("access_method", "api")),
        target=appliance.get("target"),
        username=appliance.get("username", config.get("username")),
        password=appliance.get("password", config.get("password")),
        token=appliance.get("token", config.get("token")),
        f_token=appliance.get("token_file", config.get("token_file")),
        f_passwd=appliance.get("password_file", config.get("password_file")),
        output_cli=True,
        output_csv=False,
        output_file=None,
        output_null=False,
        include_endpoints=False,
        endpoint_prefix=None,
        excavate=None,
        noping=config.get("noping", False),
        debugging=config.get("debug", False),
        reporting_dir=None,
    )

    if args.target:
        report_dir = os.path.join(os.getcwd(), f"output_{args.target.replace('.', '_')}")
        os.makedirs(report_dir, exist_ok=True)
        args.reporting_dir = report_dir

    return args


class Tee(io.TextIOBase):
    """Simple tee object to duplicate writes to multiple streams."""

    def __init__(self, *streams: io.TextIOBase):
        self.streams = streams

    def write(self, data: str) -> int:  # pragma: no cover - trivial
        for stream in self.streams:
            stream.write(data)
        return len(data)

    def flush(self) -> None:  # pragma: no cover - trivial
        for stream in self.streams:
            stream.flush()


def main() -> None:
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    config = load_config(config_path)
    args = build_args(config)
    log_dir = args.reporting_dir or os.getcwd()
    log_path = os.path.join(log_dir, "devices_test.log")

    with open(log_path, "w", encoding="utf-8") as log_file:
        tee = Tee(sys.stdout, log_file)
        with redirect_stdout(tee), redirect_stderr(tee):
            logging.basicConfig(
                level=logging.DEBUG,
                format="%(asctime)s [%(levelname)s] %(message)s",
                stream=sys.stdout,
            )
            logging.debug("Loaded configuration from %s", config_path)

            target = api_target(args)  # core.access.api_target
            logging.debug("Resolved API target: %s", target)
            _, search, creds, _, _ = init_endpoints(target, args)  # core.api.init_endpoints
            logging.debug("Initialized API endpoints")

            # Gather dependencies used within the devices report for easier debugging
            vault_creds = get_json(creds.get_vault_credentials)  # core.api.get_json
            logging.debug("Fetched vault credentials: %s", vault_creds is not None)
            identities = unique_identities(
                search, args.include_endpoints, args.endpoint_prefix
            )
            logging.debug("Collected %s unique identities", len(identities))
            lookup = devices_lookup(search, include_network=True)
            logging.debug(
                "Retrieved %s device lookup entries", len(lookup)
            )

            devices(search, creds, args, identities=identities)  # core.reporting.devices
            logging.debug("Devices report completed")


if __name__ == "__main__":
    main()
