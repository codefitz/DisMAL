# DisMAL - Discovery-Mod-And-Lookup Toolkit

This toolkit is for use with BMC Discovery.

Can do a number of powerful reports and modifications with both API and CLI (appliance) based commands.

Use at your own risk.

## Installation

1. Clone this repository and change into the project directory.
2. Ensure Python 3 is installed on your system.
3. Install the required Python packages:

   ```bash
   pip install pandas paramiko tabulate cidrize tideway
   ```

   The `tideway` module is distributed with BMC Discovery and may need to be
   installed from your appliance rather than PyPI.

## Usage

`dismal.py` exposes many reporting and administration commands. Appliance
credentials can be supplied directly on the command line or via files.

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

The options `-P`, `-T` and `-W` can be used to read the UI password, API token
and tideway password from files instead of providing them inline.
