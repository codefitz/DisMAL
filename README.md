# DisMAL - Discovery-Mod-And-Lookup Toolkit

This toolkit is for use with BMC Discovery.

Can do a number of powerful reports and modifications with both API and CLI (appliance) based commands.

Use at your own risk.

## Installation

1. Clone this repository and change into the project directory.
2. Ensure Python 3 is installed on your system.
3. Install the required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

   This project requires the following packages:

   - pandas
   - paramiko
   - tideway *(obtain from a BMC Discovery appliance)*
   - pyautogui
   - tabulate
   - cidrize

   The `tideway` module is distributed with BMC Discovery and must be obtained from a BMC Discovery appliance because it is not available on PyPI.

4. *(Optional)* Install additional development requirements for running the test suite:

   ```bash
   pip install -r requirements-dev.txt
   ```

   Development dependencies:

   - pytest

## Configuration

A template configuration file is provided at `config.yaml.template`. Copy it to
`config.yaml` and replace the placeholder values with your appliance details
and credentials:

```bash
cp config.yaml.template config.yaml
```

Then edit `config.yaml` and set values for `appliances`, `token_file`,
`username`, `password_file`, `access_method`, `noping`, and `debug`.

## Running the test suite

Run all tests with:

```bash
python3 -m pytest
```

## Usage

`dismal.py` exposes many reporting and administration commands.
Appliance credentials can be supplied directly on the command line or via files.

Basic example using API access:

```bash
python3 dismal.py --access_method api \
    -i <appliance_host> -u <username> -p <password> \
    --sysadmin audit
```

Running a CLI report requires the tideway password:

```bash
python3 dismal.py --access_method cli \
    -i <appliance_host> -u <username> -p <password> \
    -w <tideway_password> --tideway disk_info
```

The options `-P`, `-T` and `-W` can be used to read the UI password, API token and tideway password from files instead of providing them inline.

By default, reports are saved to an `output_<appliance>` directory in the current working directory.
Use the `--stdout` option to suppress file output and print results directly to the terminal.
Use `--max-threads <N>` to limit the number of worker threads used for API
requests. The default is a conservative `2` and can also be set in
`config.yaml` via `max_threads`.

### YAML configuration

Default arguments can be supplied in a YAML file.  By default `dismal.py`
looks for `config.yaml` in the current working directory.  A different file
may be provided with `--config <file>`.  Values from the YAML are used as the
defaults for command-line options, but any flags supplied on the CLI take
precedence.

The file may also contain an `appliances` list to run the same command against
multiple Discovery targets with individual credentials.

Example `config.yaml`:

```yaml
access_method: api
username: admin
password: secret
noping: true
appliances:
  - target: appliance1.example.com
    username: alice
    password: alicepass
  - target: appliance2.example.com
    token: ABCDEF123456
```

Run the tool using the configuration:

```bash
python3 dismal.py --config config.yaml --sysadmin audit
```

CLI flags override YAML values, so `--access_method cli` on the command line
would replace any `access_method` defined in the file.

### Endpoint filtering

Device-centric reports can now be limited to a subset of endpoints.  Supplying
`--include-endpoints` with one or more IP addresses, or `--endpoint-prefix`
with a partial address, will restrict searches and speed up processing.  For
example:

```bash
python3 dismal.py --access_method api -i <appliance_host> -u <username> -p <password> \
    --excavate device_ids --include-endpoints 10.0.0.1 10.0.0.2
```

Only the two specified endpoints are queried and reported on.

The resulting device-IDs report includes a **Guide %** column indicating
the proportion of unique IP addresses seen for each originating endpoint
compared to the total endpoints examined.

## Reports

The toolkit now offers a broad range of reports. Selected examples include:

- **active_scans** – list active Discovery Runs; add `--queries` to run via search query.
- **credential_success** – report on credential success with totals and success percentages.
- **device_ids** – list unique device identities with a Guide % for each originating endpoint.
- **devices** – summarize unique device profiles with last access and credential details.
- **discovery_analysis** – export latest access details for each endpoint and compare consecutive runs to highlight state changes.
- **discovery_run_analysis** – summarises DiscoveryRun details including ranges, endpoint totals, and scan kinds.
- **expected_agents** – analyse installed software and list hosts missing common agents.
- **ip_analysis** – run IP analysis report.
- **schedules** – export discovery schedules along with the credentials that will be used.
- **suggested_cred_opt** – display suggested order of credentials based on restricted IPs, exclusions, success/failure, privilege and type.

Run `python3 dismal.py --help` to see the complete list as new reports continue to be added.

To flag hosts missing common agents:

```bash
python3 dismal.py --access_method api -i <appliance> -u <user> -p <password> \
    --excavate expected_agents
```

To inspect the raw output of a particular query without any post-processing,
append the `--queries` flag.  Results are exported as CSV files prefixed with
`qry_`:

```bash
python3 dismal.py --access_method api -i <appliance> -u <user> -p <password> \
    --excavate credential_success --queries
```

The example above writes one CSV for each underlying query (for example,
`qry_credential_success.csv` and `qry_deviceinfo_success.csv`) to the output
directory for further analysis.
