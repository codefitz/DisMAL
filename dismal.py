# DisMAL Main
# 
# Author: Wes Moskal-Fitzpatrick
#
# For use with BMC Discovery
#
vers = "\nDisMAL Version: 0.0.1\n"

import sys
import os
import datetime
import logging
import argparse
from argparse import RawTextHelpFormatter

from core import access, cli, api, builder, output, reporting, tools

logfile = 'dismal_%s.log' % ( str(datetime.date.today() ))

argv = sys.argv[1:]
pwd = os.getcwd()

parser = argparse.ArgumentParser(description='DisMAL Toolkit',formatter_class=RawTextHelpFormatter)
# API Access Controls
parser.add_argument('--discovery', dest='discovery',  type=str, required=False, help='The Discovery API target.\n\n', metavar='<ip_or_hostname>')
parser.add_argument('--token', dest='token',  type=str, required=False, help='The Discovery API token without "Bearer".\n\n',metavar='<api_token>')
parser.add_argument('--username', dest='username',  type=str, required=False, help='A login username for Discovery.\n\n',metavar='<username>')
parser.add_argument('--password', dest='password',  type=str, required=False, help='The password to login.\n\n',metavar='<password>')
parser.add_argument('--twpass', dest='twpass',  type=str, required=False, help='The tideway user password for a Discovery appliance.\n\n',metavar='<tideway_password>')
parser.add_argument('--token_file', dest='f_token', type=str, required=False, help='Plaintext file containing API token string without "Bearer".\n\n', metavar='<filename>')
parser.add_argument('--passwd_file', dest='f_passwd', type=str, required=False, help='Plaintext file containing password string.\n\n', metavar='<filename>')
parser.add_argument('-v', '--version', dest='version', action='store_true', required=False, help='Version info for this app.\n\n')
parser.add_argument('--noping', dest='noping', action='store_true', required=False, help="Don't ping target before running the tool.\n\n")

# Data Quality Reports
parser.add_argument('--device', dest='r_device', type=str, required=False, help='Run devices report on a device node (Host, NetworkDevice, Printer, SNMPManagedDevice, StorageDevice, ManagementController)\n\n',metavar='<device_name>')
parser.add_argument('--devices', dest='r_devices',  action='store_true', required=False, help='Run devices access analysis report - showing credentials used from last session results.\n\n')
parser.add_argument('--device_ids', dest='r_device_ids', action='store_true', required=False, help='Export a list of unique device identies.\n\n')
parser.add_argument('--ipaddr', dest='r_ipaddr', type=str, required=False, help='Search specific IP address for DiscoveryAccess results.\n\n',metavar='<ip_address>')
parser.add_argument('--cred_device', dest='r_cred_device', type=str, required=False, help='Run devices report for a specific credential\n\n',metavar='<UUID>')
parser.add_argument('--cred_order', dest='r_weigh', action='store_true', required=False, help="Display suggested order of credentials based on restricted ips, excluded ips, success/failure, privilege, type\n\n")
parser.add_argument('--query', dest='a_query', type=str, required=False, help='Run a query.\n\n',metavar='<query string>')
parser.add_argument('--success', dest='r_success',  action='store_true', required=False, help='Run credential success report.\n\n')
parser.add_argument('--schedules', dest='r_schedules', action='store_true', required=False, help='Analysis report on which credentials will be used by with scan/exclude.\n\n')
parser.add_argument('--scan_overlaps', dest='r_overlaps',  action='store_true', required=False, help='Run overlapping range analysis report.\n\n')
parser.add_argument('--disco_access', dest='r_disco_access',  action='store_true', required=False, help='Export all DiscoveryAccess including dropped endpoints.\n\n')
parser.add_argument('--disco_analysis', dest='r_disco_analysis',  action='store_true', required=False, help='Run analysis report on all DiscoveryAccess including dropped endpoints.\n\n')
parser.add_argument('--active_runs', dest='r_activeruns', action='store_true', required=False, help='List active Discovery Runs.\n\n')
parser.add_argument('--baseline_cli', dest='r_baselinecli', action='store_true', required=False, help='Run the CLI baseline command.\n\n')

# DQ Output Modifiers
parser.add_argument('--null', dest='nullreport',  action='store_true', required=False, help='Run report functions but do not output data (used for debugging).\n\n')
parser.add_argument('-c', '--csv', dest='csv_export', action='store_true', required=False, help='Output CSV format.\n\n')
parser.add_argument('-f', '--file', dest='f_name', type=str, required=False, help='Output file for CSV format.\n\n',metavar='<filename>')

# UI Management
parser.add_argument('--cred_remove', dest='a_removal', type=str, required=False, help='Delete a credential from the system (with prompt).\n\n',metavar='<UUID>')
parser.add_argument('--cred_enable', dest='a_enable', type=str, required=False, help='Enable/Disable a credential.\n\n',metavar='<UUID>')
parser.add_argument('--cred_remove_list', dest='f_remlist', type=str, required=False, help='Specify a list of credentials to delete (no prompt).\n\n',metavar='<filename>')
parser.add_argument('--cred_enable_list', dest='f_enablelist', type=str, required=False, help='Specify a list of credentials to enable/disable.\n\n',metavar='<filename>')
parser.add_argument('--cred_optimise', dest='a_opt', action='store_true', required=False, help='Optimise credentials based on restricted ips, excluded ips, success/failure, privilege, type\n\n')
parser.add_argument('--kill_run', dest='a_kill_run', type=str, required=False, help='Nicely kill a discovery run that is jammed.\n\n',metavar='<argument>')

# CLI Management
parser.add_argument('--user', dest='a_user_man', type=str, required=False, help='Manage a GUI user (requires tideway login).\n\n',metavar='<login_id>')
parser.add_argument('--services', dest='a_services', type=str, required=False, help='Takes CLI arguments for tw_service_control.\n\n',metavar='<argument>')
parser.add_argument('--kill_scanning', dest='a_killemall', action='store_true', required=False, help='Clear the Discovery Run queue (use only if you know what you\'re doing).\n\n')

# Hidden Options
parser.add_argument('-k', '--keep-awake', dest='wakey', action='store_true', required=False, help=argparse.SUPPRESS)
parser.add_argument('--debug', dest='debugging',  action='store_true', required=False, help=argparse.SUPPRESS)

global args
args = parser.parse_args()

if args.keep:
    if not tools.in_wsl():
        # pyautogui can't run in WSL as there is no screen, but need to keep function for Linux desktop
        import pyautogui
        print("Press CTRL+C to exit.")
        while True:
            pyautogui.moveRel(5,0, duration=0)
            pyautogui.moveRel(-5,0, duration=0)
            pyautogui.press('shift')
            pyautogui.PAUSE = 60

reporting_dir = pwd + "/output_" + args.discovery.replace(".","_")

if not os.path.exists(reporting_dir):
    os.makedirs(reporting_dir)

logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w',force=True)
logger = logging.getLogger("_dismal_")
if args.debugging:
    logger.setLevel(logging.DEBUG)

logger.info(vers)

if args.noping:
    msg = "Ping check off for %s..."%args.discovery
    print(msg)
else:
    exit_code = access.ping(args.discovery)
    if exit_code == 0:
        msg = "%s: successful ping!"%args.discovery
        print(msg)
        logger.info(msg)
    else:
        msg = "%s not found (ping)\nExit code: %s"%(args.discovery, exit_code)
        print(msg)
        logger.critical(msg)
        sys.exit(1)

if args.version:
    print(vers)
    if not args.discovery:
        sys.exit(0)

# Validate access methods
discovery, token, client, api_access, ssh_access, system_user = access.method(args)

### Tideway CLI Management ###

if ssh_access:

    if args.a_user_man:
        cli.user_management(args, client)

    if args.a_services:
        cli.service_management(args, client)

    if args.a_killemall:
        cli.clear_queue(client)

    if system_user:

        if args.r_baselinecli:
            cli.baseline(client, args, reporting_dir)

if api_access:

    ##### Setup Endpoints #######

    try:
        search = discovery.data()
    except:
        msg = "Error getting Data endpoint from %s\n" % (args.discovery)
        print(msg)
        logger.error(msg)
        sys.exit(1)

    try:
        disco = discovery.discovery()
    except:
        msg = "Error getting Discovery endpoint from %s\n" % (args.discovery)
        print(msg)
        logger.error(msg)
        sys.exit(1)

    try:
        creds = discovery.credentials()
    except:
        msg = "Error getting Credentials endpoint from %s\n" % (args.discovery)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    
    ####### API Management #######

    if args.r_activeruns:
        ## Lookup a Device
        api.show_runs(disco, args)

    if args.a_kill_run:
        api.cancel_run(disco, args)

    if args.a_removal:
        lookup = builder.get_credential(search, creds, args.a_removal, args)
        if lookup:
            go_ahead = input("Are you sure you want to delete this credential? (Y/y) ")
            if go_ahead == "y" or go_ahead == "Y":
                success = api.remove_cred(creds, args)
                if success:
                    msg = "Credential %s deleted from %s." % (args.a_removal, args.discovery)
                else:
                    msg = "Credential %s was not deleted\n%s" % (args.a_removal, success)
                print(msg)
                logger.info(msg)

    if args.f_remlist:
        exists = os.path.isfile(args.f_remlist)
        if exists:
            with open(args.remlist) as f:
                for line in f:
                    success = api.remove_cred(creds, line.strip())
                    if success:
                        msg = "Credential %s deleted from %s." % (line.strip(), args.discovery)
                    else:
                        msg = "Credential %s was not deleted\n%s" % (line.strip(), success)
                    logger.info(msg)

    if args.a_enable:
        active = api.update_cred(creds, args.a_enable)
        if active is not None:
            if active:
                msg = "Credential %s Activated.\n" % (args.a_enable)
            else:
                msg = "Credential %s Deactivated.\n" % (args.a_enable)
        else:
            msg = "Unable to determine %s credential state.\n" % (args.a_enable)
        print(msg)
        logger.info(msg)

    if args.f_enablelist:
        exists = os.path.isfile(args.f_enablelist)
        if exists:
            go_ahead = input("This will switch the 'enabled' status of all credentials\nEnabled -> Disabled\nDisabled -> Enabled\n\nContinue? (Y/y) ")
            if go_ahead == "y" or go_ahead == "Y":
                with open(args.f_enablelist) as f:
                    for line in f:
                        active = api.update_cred(creds, line.strip())
                        if active is not None:
                            if active:
                                msg = "Credential %s Activated.\n" % (line.strip())
                            else:
                                msg = "Credential %s Deactivated.\n" % (line.strip())
                        else:
                            msg = "Unable to determine %s credential state.\n" % (line.strip())
                        logger.info(msg)

    if args.a_opt:
        builder.ordering(creds, search, args)

    if args.schedules:
        builder.scheduling(creds, search, args)

    if args.r_device_ids:
        identities = builder.unique_identities(disco)
        data = []
        for identity in identities:
            data.append([identity['originating_endpoint'],identity['list_of_ips'],identity['list_of_names']])
        output.report(data, [ "Origating Endpoint", "List of IPs", "List of Names" ], args)

    if args.overlaps:
        builder.overlapping(disco, args)

    ######### Reporting ##########

    if args.a_query:
        api.query(search, args)

    if args.r_cred_device:
        builder.get_credential(search, creds, args.r_cred_device, args)

    if args.r_device:
        builder.get_device(args.r_device, search, creds, args)

    if args.r_success:
        print("\nCredential Success")
        print("------------------")
        reporting.successful(creds, search, args)

    if args.r_devices:
        reporting.devices(search, creds, args)

    if args.r_ipaddr:
        reporting.ipaddr(args.r_ipaddr, search, creds, args)

    if args.r_disco_access:
        reporting.discovery_access(search, creds, args)

    if args.r_disco_analysis:
        reporting.discovery_analysis(search, creds, args)

if client:
    client.close()

print(os.linesep)