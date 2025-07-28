# DisMAL Toolkit
# 
# Author: Wes Moskal-Fitzpatrick
#
# For use with BMC Discovery
#
vers = "0.1.3"

import argparse
import datetime
import logging
import os
import sys
from argparse import RawTextHelpFormatter

from core import access, api, builder, cli, curl, output, reporting, tools

logfile = 'dismal_%s.log'%( str(datetime.date.today() ))

argv = sys.argv[1:]
pwd  = os.getcwd()

parser = argparse.ArgumentParser(description='DisMAL Toolkit for BMC Discovery v%s'%vers,formatter_class=RawTextHelpFormatter)
parser.add_argument('-v', '--version', dest='version', action='store_true', required=False, help='Version info for this app.\n\n')

# Access Inputs
access_inputs = parser.add_argument_group("Discovery Target Access Methods")
access_inputs.add_argument('-a','--access_method', dest='access_method', choices=['api', 'cli', 'all'], required=False, help='''
Method to get data:
"api" - Use API commands only.
"cli" - Use CLI commands only.
"all" - Use API and CLI commands (default).
\n''',default='all',metavar='<method>')
access_inputs.add_argument('-i','--discovery_instance', dest='target',  type=str, required=False, help='The Discovery or Outpost target.\n\n', metavar='<ip_or_hostname>')
access_inputs.add_argument('-u','--username',           dest='username',  type=str, required=False, help='A login username for Discovery.\n\n',metavar='<username>')
access_inputs.add_argument('-p','--password',           dest='password',  type=str, required=False, help='The login password for Discovery.\n\n',metavar='<password>')
access_inputs.add_argument('-P','--password_file',      dest='f_passwd', type=str, required=False, help='Plaintext file containing password string.\n\n', metavar='<filename>')
access_inputs.add_argument('-t','--token',              dest='token',  type=str, required=False, help='The Discovery API token without "Bearer".\n\n',metavar='<api_token>')
access_inputs.add_argument('-T','--token_file',         dest='f_token', type=str, required=False, help='Plaintext file containing API token string without "Bearer".\n\n', metavar='<filename>')
access_inputs.add_argument('-w','--tw_password',        dest='twpass',  type=str, required=False, help='The tideway user password for a Discovery appliance.\n\n',metavar='<tideway_password>')
access_inputs.add_argument('-W','--tw_password_file',   dest='f_twpasswd', type=str, required=False, help='Plaintext file containing tideway password string.\n\n', metavar='<filename>')
access_inputs.add_argument('--noping',                  dest='noping', action='store_true', required=False, help="Don't ping target before running the tool (needed for Helix).\n\n")

# DQ Output Modifiers
outputs = parser.add_argument_group("Output Options")
outputs.add_argument('-c', '--csv',     dest='output_csv', action='store_true', required=False, help='Output to CLI in CSV format.\n\n')
outputs.add_argument('-f', '--file',    dest='output_file', type=str, required=False, help='Output file (TXT/CSV format).\n\n',metavar='<filename>')
outputs.add_argument('-s', '--path',    dest='output_path', type=str, required=False, help='Path to save bulk files (default=pwd).\n\n',metavar='<path>')
outputs.add_argument('--null',          dest='output_null',  action='store_true', required=False, help='Run report functions but do not output data (used for debugging).\n\n')
outputs.add_argument('--stdout',       dest='output_cli', action='store_true', required=False, help='Print results to CLI instead of writing to output directory.\n\n')

# Hidden Options
parser.add_argument('-k', '--keep-awake',   dest='wakey', action='store_true', required=False, help=argparse.SUPPRESS)
parser.add_argument('--debug',              dest='debugging',  action='store_true', required=False,
                    help='Enable debug logging including full API responses.\n\n')

# CLI Appliance Management
cli_management = parser.add_argument_group("CLI Appliance Management")
cli_management.add_argument('--tideway', dest='tideway', type=str, required=False, help= '''
CLI management reports export.
\nOptions:
"certificates"  - TLS info
"cli_users"     - CLI user logins
"clustering"    - Cluster configuration
"cmdb_errors"   - CMDB error log
"core_dumps"    - List of core dumps
"disk_info"     - Disk info
"dns_resolution"- DNS information
"ds_status"     - Datastore compaction logs
"host_info"     - Appliance host information
"ldap"          - LDAP configuration
"ntp"           - Date and timezone info
"reasoning"     - Reasoning info
"reports_model" - Reports model data
"syslog"        - Syslog configuration
"tax_deprecated"- Taxonomy deprecation issues
"tree"          - Full filesystem tree of appliance
"tw_config_dump"- tw_config_dump output
"tw_crontab"    - Crontab configuration
"tw_options"    - tw_options analysis
"ui_errors"     - UI error info
"vmware_tools"  - VMware Tools status
\n
''',metavar='<report>')
cli_management.add_argument('--kill_scanning',  dest='clear_queue', action='store_true', required=False, help='Clear the Discovery Run queue (use only if you know what you\'re doing).\n\n')
cli_management.add_argument('--user_management',dest='tw_user', type=str, required=False, help='Manage a GUI user (requires tideway login).\n\n',metavar='<login_id>')
cli_management.add_argument('--services',       dest='servicecctl', type=str, required=False, help='Takes CLI arguments for tw_service_control.\n\n',metavar='<argument>')

# Discovery Administration
administration = parser.add_argument_group("Discovery Administration")
administration.add_argument('--sysadmin', dest='sysadmin', type=str, required=False, help= '''
Management reports to export.
\nOptions:
"api_version"   - API version info
"audit"         - Audit report
"baseline"      - Run the baseline command
"cmdbsync"      - CMDB sync details
"events"        - Event logs
"knowledge"     - List Knowledge uploads
"licensing"     - License reports
"platforms"     - Platform scripts
"users"         - List of local UI logins
\n
''',metavar='<report>')
administration.add_argument('--query',              dest='a_query', type=str, required=False, help='Run an ad-hoc query.\n\n',metavar='<query string>')
administration.add_argument('--cred_enable',        dest='a_enable', type=str, required=False, help='Enable/Disable a credential.\n\n',metavar='<UUID>')
administration.add_argument('--cred_enable_list',   dest='f_enablelist', type=str, required=False, help='Specify a list of credentials to enable/disable.\n\n',metavar='<filename>')
administration.add_argument('--cred_optimise',      dest='a_opt', action='store_true', required=False, help='Optimise credentials based on restricted ips, excluded ips, success/failure, privilege, type\n\n')
administration.add_argument('--cred_remove',        dest='a_removal', type=str, required=False, help='Delete a credential from the system (with prompt).\n\n',metavar='<UUID>')
administration.add_argument('--cred_remove_list',   dest='f_remlist', type=str, required=False, help='Specify a list of credentials to delete (no prompt).\n\n',metavar='<filename>')
administration.add_argument('--kill_run',           dest='a_kill_run', type=str, required=False, help='Nicely kill a discovery run that is jammed.\n\n',metavar='<argument>')

# Excavation (Boosted Reports)
excavation = parser.add_argument_group("Excavation (Boosted Reports)")
excavation.add_argument('--excavate', dest='excavate', type=str, required=False, help= '''
Excavation reports - for automated beneficial reporting and deeper analysis.
Providing no <report> or using "default" will run all options that do not require a value.
\nOptions:
"active_runs"               - List active Discovery Runs
"credential_success"        - Report on credential success with total number of accesses, success %% and ranges
"db_lifecycle"              - Export Database lifecycle report
"device" <name>             - Report on a specific device node by name (Host, NetworkDevice, Printer, SNMPManagedDevice, StorageDevice, ManagementController)
"device_ids"                - Export list of unique device identities
"devices"                   - Report of unique device profiles - includes last DiscoveryAccess and last _successful_ DiscoveryAccess results with credential details
"devices_with_cred" <UUID>  - Run devices report for a specific credential
"discovery_access"          - Report of all DiscoveryAccesses and dropped endpoints with credential details, consistency if available
"discovery_analysis"        - Report of unique DiscoveryAccesses and dropped endpoints with credential details, consistency analysis and end state change
"eca_errors"                - Export list of ECA Errors
"excludes"                  - Export of exclude schedules
"export_tpl"                - Export TPL
"host_utilisation"          - Export of Hosts which appear to be underutilised (less than 3 running SIs)
"hostname"                  - Print hostname
"installed_agents"          - Analysis of installed agents
"ipaddr" <ip_address>       - Search specific IP address for DiscoveryAccess results
"missing_vms"               - Report of Hypervisor Hosts that have VMs which have not been discovered
"near_removal"              - Export list of devices near removal
"open_ports"                - Export of open ports analysis
"orphan_vms"                - Report of Virtual Machines that are not related to a container Host
"os_lifecycle"              - Export OS lifecycle report
"overlapping_ips"           - Run overlapping range analysis report
"pattern_modules"           - Summary of installed pattern modules
"removed"                   - Export list of devices removed in the last 7 days (aged out)
"schedules"                 - Export of schedules with additional list of which credentials will be used with scan/exclude
"sensitive_data"            - Export Sensitive Data anaylsis
"si_lifecycle"              - Export SoftwareInstance lifecycle report
"si_user_accounts"          - Software with running process usernames
"suggest_cred_opt"          - Display suggested order of credentials based on restricted ips, excluded ips, success/failure, privilege, type
"tku"                       - TKU version summary
"unrecognised_snmp"         - Report of unrecognised SNMP devices (Model > Device)
"vault"                     - Vault details
"default"                   - Run all options that do not require a value
\n
''',metavar='<report> [value]',nargs='*')
excavation.add_argument('--resolve-hostnames', dest='resolve_hostnames', action='store_true', required=False,
                        help='Ping guest full names and record the resolved IP address in results.')

global args
args = parser.parse_args()

# Detect if --excavate was provided with no report or with 'default'
excavate_default = False
if args.excavate is not None:
    if len(args.excavate) == 0 or args.excavate[0] == "default":
        excavate_default = True

if args.version:
    print(vers)
    if not args.target:
        sys.exit(0)

if args.wakey:
    if not tools.in_wsl():
        # pyautogui can't run in WSL as there is no screen, but need to keep function for Linux desktop
        import pyautogui
        print("Press CTRL+C to exit.")
        while True:
            pyautogui.moveRel(5,0, duration=0)
            pyautogui.moveRel(-5,0, duration=0)
            pyautogui.press('shift')
            pyautogui.PAUSE = 60

if args.target:
    if args.output_path:
        reporting_dir = args.output_path + "/output_" + args.target.replace(".","_")
    else:
        reporting_dir = pwd + "/output_" + args.target.replace(".","_")
    if not os.path.exists(reporting_dir):
        os.makedirs(reporting_dir)
    args.reporting_dir = reporting_dir

logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w', force=True)
logger = logging.getLogger("_dismal_")
if args.debugging:
    logging.getLogger().setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)

logger.info("DisMAL Version %s"%vers)

if args.noping:
    msg = "Ping check off for %s..."%args.target
    print(msg)
else:
    if args.target:
        exit_code = access.ping(args.target)
        if exit_code == 0:
            msg = "%s: successful ping!"%args.target
            print(msg)
            logger.info(msg)
        else:
            msg = "%s not found (ping)\nExit code: %s"%(args.target, exit_code)
            print(msg)
            logger.critical(msg)
            sys.exit(1)

# Validate access methods
api_target = None
cli_target = None
## API
if args.access_method=="api":
    api_target = access.api_target(args)
    disco, search, creds, vault, knowledge = api.init_endpoints(api_target, args)
    system_user, system_passwd = access.login_target(None, args)

## Client
if args.access_method=="cli":
    cli_target, tw_passwd = access.cli_target(args)
    ## System User Access
    system_user, system_passwd = access.login_target(cli_target, args)

## All
if args.access_method=="all":
    api_target = access.api_target(args)
    disco, search, creds, vault, knowledge = api.init_endpoints(api_target, args)
    cli_target, tw_passwd = access.cli_target(args)
    system_user, system_passwd = access.login_target(cli_target, args)

if args.access_method == "all":

    curl_cmd = True

    if cli_target:

        cli.certificates(cli_target, args, reporting_dir)
        cli.etc_passwd(cli_target, args, reporting_dir)
        cli.cluster_info(cli_target, args, reporting_dir)
        cli.cmdb_errors(cli_target, args, reporting_dir)
        cli.core_dumps(cli_target, args, reporting_dir)
        cli.df_h(cli_target, args, reporting_dir)
        cli.resolv_conf(cli_target, args, reporting_dir)
        cli.ds_compact(cli_target, args, reporting_dir)
        cli.host_info(cli_target, args, reporting_dir)
        cli.ldap(cli_target, args, reporting_dir)
        cli.timedatectl(cli_target, args, reporting_dir)
        cli.reasoning(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.reports_model(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.syslog(cli_target, args, tw_passwd, reporting_dir)
        cli.tax_deprecated(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.tree(cli_target, args, reporting_dir)
        cli.tw_config_dump(cli_target, args, reporting_dir)
        cli.tw_crontab(cli_target, args, reporting_dir)
        cli.tw_options(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.ui_errors(cli_target, args, reporting_dir)
        cli.vmware_tools(cli_target, args, tw_passwd, reporting_dir)
        cli.audit(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.baseline(cli_target, args, reporting_dir)
        cli.cmdb_sync(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.tw_events(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.export_platforms(cli_target, args, system_user, system_passwd, reporting_dir)
        curl.platform_scripts(args, system_user, system_passwd, reporting_dir+"/platforms")
        curl_cmd = False
        cli.knowledge(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.licensing(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.tw_list_users(cli_target, args, reporting_dir)
        reporting.successful_cli(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.schedules(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.excludes(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.sensitive(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.tplexport(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.eca_errors(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.open_ports(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.host_util(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.orphan_vms(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.missing_vms(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.near_removal(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.removed(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.os_lifecycle(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.software_lifecycle(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.db_lifecycle(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.unrecognised_snmp(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.installed_agents(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.software_usernames(cli_target, args, system_user, system_passwd, reporting_dir)
        cli.module_summary(cli_target, args, system_user, system_passwd, reporting_dir)

    if api_target:

        api.admin(disco, args, reporting_dir)
        api.audit(search, args, reporting_dir)
        api.baseline(disco, args, reporting_dir)
        api.cmdb_config(search, args, reporting_dir)
        if curl_cmd:
            curl.platform_scripts(args, system_user, system_passwd, reporting_dir+"/platforms")
        api.modules(search, args, reporting_dir)
        api.licensing(search, args, reporting_dir)     
        reporting.devices(search, creds, args)
        builder.ordering(creds, search, args, False)
        api.success(creds, search, args, reporting_dir)
        builder.scheduling(creds, search, args)
        api.excludes(search, args, reporting_dir)
        builder.overlapping(search, args)
        reporting.discovery_access(search, creds, args)
        reporting.discovery_analysis(search, creds, args)
        api.show_runs(disco, args)
        api.discovery_runs(disco, args, reporting_dir)
        api.tpl_export(search, args, reporting_dir)
        api.eca_errors(search, args, reporting_dir)
        api.open_ports(search, args, reporting_dir)
        api.host_util(search, args, reporting_dir)
        api.orphan_vms(search, args, reporting_dir)
        api.missing_vms(search, args, reporting_dir)
        api.near_removal(search, args, reporting_dir)
        api.removed(search, args, reporting_dir)
        api.snmp(search, args, reporting_dir)
        api.oslc(search, args, reporting_dir)
        api.slc(search, args, reporting_dir)
        api.dblc(search, args, reporting_dir)
        api.agents(search, args, reporting_dir)
        api.software_users(search, args, reporting_dir)
        api.tku(knowledge, args, reporting_dir)

if args.access_method=="cli":

    if args.tideway == "certificates":
        cli.certificates(cli_target, args, reporting_dir)

    if args.tideway == "cli_users":
        cli.etc_passwd(cli_target, args, reporting_dir)

    if args.tideway == "clustering":
        cli.cluster_info(cli_target, args, reporting_dir)

    if args.tideway == "cmdb_errors":
        cli.cmdb_errors(cli_target, args, reporting_dir)

    if args.tideway == "core_dumps":
        cli.core_dumps(cli_target, args, reporting_dir)

    if args.tideway == "disk_info":
        cli.df_h(cli_target, args, reporting_dir)

    if args.tideway == "dns_resolution":
        cli.resolv_conf(cli_target, args, reporting_dir)

    if args.tideway == "ds_status":
        cli.ds_compact(cli_target, args, reporting_dir)

    if args.tideway == "host_info":
        cli.host_info(cli_target, args, reporting_dir)

    if args.tideway == "ldap":
        cli.ldap(cli_target, args, reporting_dir)

    if args.tideway == "ntp":
        cli.timedatectl(cli_target, args, reporting_dir)

    if args.tideway == "reasoning":
        cli.reasoning(cli_target, args, system_user, system_passwd, reporting_dir)

    if args.tideway == "reports_model":
        cli.reports_model(cli_target, args, system_user, system_passwd, reporting_dir)

    if args.tideway == "syslog":
        cli.syslog(cli_target, args, tw_passwd, reporting_dir)

    if args.tideway == "tax_deprecated":
        cli.tax_deprecated(cli_target, args, system_user, system_passwd, reporting_dir)

    if args.tideway == "tree":
        cli.tree(cli_target, args, reporting_dir)

    if args.tideway == "tw_config_dump":
        cli.tw_config_dump(cli_target, args, reporting_dir)

    if args.tideway == "tw_crontab":
        cli.tw_crontab(cli_target, args, reporting_dir)

    if args.tideway == "tw_options":
        cli.tw_options(cli_target, args, system_user, system_passwd, reporting_dir)

    if args.tideway == "ui_errors":
        cli.ui_errors(cli_target, args, reporting_dir)

    if args.tideway == "vmware_tools":
        cli.vmware_tools(cli_target, args, tw_passwd, reporting_dir)

    if args.clear_queue:
        cli.clear_queue(cli_target)

    if args.tw_user:
        cli.user_management(cli_target, args)

    if args.servicecctl:
        cli.service_management(cli_target, args)

    if args.sysadmin == "audit":
        cli.audit(cli_target, args, system_user, system_passwd, reporting_dir)

    if args.sysadmin == "baseline":
        cli.baseline(cli_target, args, reporting_dir)

    if args.sysadmin == "cmdbsync":
        cli.cmdb_sync(cli_target, args, system_user, system_passwd, reporting_dir)

    if args.sysadmin == "events":
        cli.tw_events(cli_target, args, system_user, system_passwd, reporting_dir)

    if args.sysadmin == "platforms":
        cli.export_platforms(cli_target, args, system_user, system_passwd, reporting_dir)
        curl.platform_scripts(args, system_user, system_passwd, reporting_dir+"/platforms")

    if args.sysadmin == "knowledge":
        cli.knowledge(cli_target, args, system_user, system_passwd, reporting_dir)
    
    if args.sysadmin == "licensing":
        cli.licensing(cli_target, args, system_user, system_passwd, reporting_dir)

    if args.sysadmin == "users":
        cli.tw_list_users(cli_target, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "credential_success"):
        reporting.successful_cli(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "schedules"):
        cli.schedules(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "excludes"):
        cli.excludes(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "sensitive_data"):
        cli.sensitive(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "export_tpl"):
        cli.tplexport(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "eca_errors"):
        cli.eca_errors(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "open_ports"):
        cli.open_ports(cli_target, args, system_user, system_passwd, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "host_utilisation"):
        cli.host_util(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "orphan_vms"):
        cli.orphan_vms(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "missing_vms"):
        cli.missing_vms(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "near_removal"):
        cli.near_removal(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "removed"):
        cli.removed(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "os_lifecycle"):
        cli.os_lifecycle(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "software_lifecycle"):
        cli.software_lifecycle(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "db_lifecycle"):
        cli.db_lifecycle(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "unrecogised_snmp"):
        cli.unrecognised_snmp(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "installed_agents"):
        cli.installed_agents(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "si_user_accounts"):
        cli.software_usernames(cli_target, args, system_user, system_passwd, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "pattern_modules"):
        cli.module_summary(cli_target, args, system_user, system_passwd, reporting_dir)

if args.access_method=="api":

    if args.sysadmin == "api_version":
        api.admin(disco, args, reporting_dir)

    if args.sysadmin == "audit":
        api.audit(search, args, reporting_dir)

    if args.sysadmin == "baseline":
        api.baseline(disco, args, reporting_dir)

    if args.sysadmin == "cmdbsync":
        api.cmdb_config(search, args, reporting_dir)

    if args.sysadmin == "platforms":
        curl.platform_scripts(args, system_user, system_passwd, reporting_dir+"/platforms")

    if args.sysadmin == "knowledge":
        api.modules(search, args, reporting_dir)

    if args.sysadmin == "licensing":
        api.licensing(search, args, reporting_dir)

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
        builder.ordering(creds, search, args, True)

    if args.a_removal:
        lookup = builder.get_credential(search, creds, args.a_removal, args)
        if lookup:
            go_ahead = input("Are you sure you want to delete this credential? (Y/y) ")
            if go_ahead == "y" or go_ahead == "Y":
                success = api.remove_cred(creds, args)
                if success:
                    msg = "Credential %s deleted from %s." % (args.a_removal, args.target)
                else:
                    msg = "Credential %s was not deleted\n%s" % (args.a_removal, success)
                print(msg)
                logger.info(msg)

    if args.f_remlist:
        exists = os.path.isfile(args.f_remlist)
        if exists:
            with open(args.f_remlist) as f:
                for line in f:
                    success = api.remove_cred(creds, line.strip())
                    if success:
                        msg = "Credential %s deleted from %s." % (line.strip(), args.target)
                    else:
                        msg = "Credential %s was not deleted\n%s" % (line.strip(), success)
                    logger.info(msg)
        
    if args.a_kill_run:
        api.cancel_run(disco, args)

    if args.excavate and args.excavate[0] == "device":
        builder.get_device(search, creds, args)

    if excavate_default or (args.excavate and args.excavate[0] == "devices"):
        reporting.devices(search, creds, args)

    if excavate_default or (args.excavate and args.excavate[0] == "device_ids"):
        identities = builder.unique_identities(search)
        data = []
        for identity in identities:
            data.append([identity['originating_endpoint'],identity['list_of_ips'],identity['list_of_names']])
        output.report(data, [ "Origating Endpoint", "List of IPs", "List of Names" ], args, name="device_ids")

    if args.excavate and args.excavate[0] == "ipaddr":
        reporting.ipaddr(search, creds, args)

    if args.excavate and args.excavate[0] == "devices_with_cred":
        builder.get_credential(search, creds, args)

    if excavate_default or (args.excavate and args.excavate[0] == "suggest_cred_opt"):
        builder.ordering(creds, search, args, False)

    if args.a_query:
        api.query(search, args)

    if excavate_default or (args.excavate and args.excavate[0] == "credential_success"):
        api.success(creds, search, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "schedules"):
        builder.scheduling(creds, search, args)

    if excavate_default or (args.excavate and args.excavate[0] == "excludes"):
        api.excludes(search, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "overlapping_ips"):
        builder.overlapping(search, args)

    if excavate_default or (args.excavate and args.excavate[0] == "discovery_access"):
        reporting.discovery_access(search, creds, args)

    if excavate_default or (args.excavate and args.excavate[0] == "discovery_analysis"):
        reporting.discovery_analysis(search, creds, args)

    if excavate_default or (args.excavate and args.excavate[0] == "active_runs"):
        api.show_runs(disco, args)
        api.discovery_runs(disco, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "sensitive_data"):
        api.sensitive(search, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "export_tpl"):
        api.tpl_export(search, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "eca_errors"):
        api.eca_errors(search, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "open_ports"):
        api.open_ports(search, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "host_utilisation"):
        api.host_util(search, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "orphan_vms"):
        api.orphan_vms(search, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "missing_vms"):
        api.missing_vms(search, args, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "near_removal"):
        api.near_removal(search, args, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "removed"):
        api.removed(search, args, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "os_lifecycle"):
        api.oslc(search, args, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "software_lifecycle"):
        api.slc(search, args, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "db_lifecycle"):
        api.dblc(search, args, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "unrecogised_snmp"):
        api.snmp(search, args, reporting_dir)
        
    if excavate_default or (args.excavate and args.excavate[0] == "installed_agents"):
        api.agents(search, args, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "si_user_accounts"):
        api.software_users(search, args, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "pattern_modules"):
        #TODO: This report has been overlooked
        api.tku(knowledge,args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "tku"):
        api.tku(knowledge, args, reporting_dir)

    if excavate_default or (args.excavate and args.excavate[0] == "vault"):
        api.vault(vault, args, reporting_dir)
    
    if excavate_default or (args.excavate and args.excavate[0] == "hostname"):
        api.hostname(args, reporting_dir)

if cli_target:
    cli_target.close()

print(os.linesep)
