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

## Reports

One report focuses on Discovery Access history:

- **discovery_analysis** – exports the latest access details for each endpoint and compares consecutive runs to highlight state changes.
- **ip_analysis** – Run IP analysis report.
More reports are included.
Run `python3 dismal.py --help` to see the complete list.
