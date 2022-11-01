# DisMAL Maindiscovery
# 
# Author: Wes Moskal-Fitzpatrick
#
# For use with BMC Discovery
#
vers = "0.0.8"

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

# Hidden Options
parser.add_argument('-k', '--keep-awake',   dest='wakey', action='store_true', required=False, help=argparse.SUPPRESS)
parser.add_argument('--debug',              dest='debugging',  action='store_true', required=False, help=argparse.SUPPRESS)

# CLI Appliance Management
cli_management = parser.add_argument_group("CLI Appliance Management")
cli_management.add_argument('--tideway', dest='tideway', type=str, required=False, help= '''
CLI management reports export.
\nOptions:
"all"           - Export all reports
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
"platforms"     - Platform scripts
"knowledge"     - List Knowledge uploads
"licensing"     - License reports
"users"         - List of local UI logins
\n
''',metavar='<report>')
administration.add_argument('--audit',                  dest='r_audit', action='store_true', required=False, help='Export audit report.\n\n')
administration.add_argument('--audit_cli',              dest='r_auditcli', action='store_true', required=False, help='Export audit report (CLI).\n\n')
administration.add_argument('--baseline',               dest='r_baseline', action='store_true', required=False, help='Run the baseline command.\n\n')
administration.add_argument('--baseline_cli',           dest='r_baselinecli', action='store_true', required=False, help='Run the CLI baseline command.\n\n')
administration.add_argument('--cmdbsync',               dest='r_cmdb_config', action='store_true', required=False, help='CMDB sync details.\n\n')
administration.add_argument('--cmdbsync_cli',           dest='r_cmdbsynccli', action='store_true', required=False, help='CMDB sync details (CLI).\n\n')
administration.add_argument('--events',                 dest='tw_events', action='store_true', required=False, help='Export event logs.\n\n')
administration.add_argument('--export_platforms',       dest='export_platforms', action='store_true', required=False, help='Export platform scripts.\n\n')
administration.add_argument('--export_platforms_xml',   dest='export_platforms_xml', action='store_true', required=False, help='Export platform scripts as XML.\n\n')
administration.add_argument('--knowledge_cli',          dest='r_knowledgecli', action='store_true', required=False, help='List Knowledge uploads (CLI).\n\n')
administration.add_argument('--pattern_modules',        dest='r_modules', action='store_true', required=False, help='Summary of Pattern Modules (CLI).\n\n')
administration.add_argument('--license_export',         dest='r_licensing', action='store_true', required=False, help='Export license details.\n\n')
administration.add_argument('--license_export_cli',     dest='r_license_export', action='store_true', required=False, help='Export license details (CLI).\n\n')
administration.add_argument('--license_export_csv',     dest='r_licensing_csv', action='store_true', required=False, help='Export license details - CSV.\n\n')
administration.add_argument('--login_users',            dest='tw_list_users', action='store_true', required=False, help='Export list of UI logins.\n\n')
###
administration.add_argument('--cred_enable',            dest='a_enable', type=str, required=False, help='Enable/Disable a credential.\n\n',metavar='<UUID>')
administration.add_argument('--cred_enable_list',       dest='f_enablelist', type=str, required=False, help='Specify a list of credentials to enable/disable.\n\n',metavar='<filename>')
administration.add_argument('--cred_optimise',          dest='a_opt', action='store_true', required=False, help='Optimise credentials based on restricted ips, excluded ips, success/failure, privilege, type\n\n')
administration.add_argument('--cred_remove',            dest='a_removal', type=str, required=False, help='Delete a credential from the system (with prompt).\n\n',metavar='<UUID>')
administration.add_argument('--cred_remove_list',       dest='f_remlist', type=str, required=False, help='Specify a list of credentials to delete (no prompt).\n\n',metavar='<filename>')
administration.add_argument('--kill_run',               dest='a_kill_run', type=str, required=False, help='Nicely kill a discovery run that is jammed.\n\n',metavar='<argument>')

# Excavation (Boosted Reports)
excavation = parser.add_argument_group("Excavation (Boosted Reports)")
excavation.add_argument('--device',                 dest='r_device', type=str, required=False, help='Run devices report on a device node (Host, NetworkDevice, Printer, SNMPManagedDevice, StorageDevice, ManagementController)\n\n',metavar='<device_name>')
excavation.add_argument('--devices',                dest='r_devices',  action='store_true', required=False, help='Run devices access analysis report - showing credentials used from last session results.\n\n')
excavation.add_argument('--device_ids',             dest='r_device_ids', action='store_true', required=False, help='Export a list of unique device identies.\n\n')
excavation.add_argument('--ipaddr',                 dest='r_ipaddr', type=str, required=False, help='Search specific IP address for DiscoveryAccess results.\n\n',metavar='<ip_address>')
excavation.add_argument('--cred_device',            dest='r_cred_device', type=str, required=False, help='Run devices report for a specific credential\n\n',metavar='<UUID>')
excavation.add_argument('--cred_order',             dest='r_weigh', action='store_true', required=False, help="Display suggested order of credentials based on restricted ips, excluded ips, success/failure, privilege, type\n\n")
excavation.add_argument('--query',                  dest='a_query', type=str, required=False, help='Run a query.\n\n',metavar='<query string>')
excavation.add_argument('--success',                dest='r_success',  action='store_true', required=False, help='Run credential success report.\n\n')
excavation.add_argument('--successful',             dest='r_successful',  action='store_true', required=False, help='Run credential success report.\n\n')
excavation.add_argument('--success_cli',            dest='r_successcli', action='store_true', required=False, help='Run credential success report (CLI).\n\n')
excavation.add_argument('--schedules',              dest='r_schedules', action='store_true', required=False, help='Analysis report on which credentials will be used by with scan/exclude.\n\n')
excavation.add_argument('--schedules_cli',          dest='r_schedulescli', action='store_true', required=False, help='Export of scan schedules (CLI).\n\n')
excavation.add_argument('--excludes',               dest='r_excludes', action='store_true', required=False, help='Export of exclude schedules.\n\n')
excavation.add_argument('--excludes_cli',           dest='r_excludescli', action='store_true', required=False, help='Export of exclude schedules (CLI).\n\n')
excavation.add_argument('--scan_overlaps',          dest='r_overlaps',  action='store_true', required=False, help='Run overlapping range analysis report.\n\n')
excavation.add_argument('--disco_access',           dest='r_disco_access',  action='store_true', required=False, help='Export all DiscoveryAccess including dropped endpoints.\n\n')
excavation.add_argument('--disco_analysis',         dest='r_disco_analysis',  action='store_true', required=False, help='Run analysis report on all DiscoveryAccess including dropped endpoints.\n\n')
excavation.add_argument('--active_runs',            dest='r_activeruns', action='store_true', required=False, help='List active Discovery Runs.\n\n')
excavation.add_argument('--discovery_runs',         dest='r_discoveryruns', action='store_true', required=False, help='Export active Discovery Runs.\n\n')
excavation.add_argument('--sensitive_data',         dest='r_sensitive', action='store_true', required=False, help='Export Sensitive Data report.\n\n')
excavation.add_argument('--sensitive_data_cli',     dest='r_sensitivecli', action='store_true', required=False, help='Export Sensitive Data report (CLI).\n\n')
excavation.add_argument('--export_tpl',             dest='r_tpl_export', action='store_true', required=False, help='Export TPL.\n\n')
excavation.add_argument('--export_tpl_cli',         dest='r_tplexportcli', action='store_true', required=False, help='Export TPL (CLI).\n\n')
excavation.add_argument('--eca_errors',             dest='r_eca_errors', action='store_true', required=False, help='Export ECA Errors.\n\n')
excavation.add_argument('--eca_errors_cli',         dest='r_ecaerrorscli', action='store_true', required=False, help='Export ECA Errors (CLI).\n\n')
excavation.add_argument('--open_ports',             dest='r_open_ports', action='store_true', required=False, help='Export of open ports analysis.\n\n')
excavation.add_argument('--open_ports_cli',         dest='r_portscli', action='store_true', required=False, help='Export of open ports analysis (CLI).\n\n')
excavation.add_argument('--host_utilisation',       dest='r_host_util', action='store_true', required=False, help='Export of Host utilisation.\n\n')
excavation.add_argument('--host_utilisation_cli',   dest='r_utilisationcli', action='store_true', required=False, help='Export of Host utilisation (CLI).\n\n')
excavation.add_argument('--orphan_vms',             dest='r_orphan_vms', action='store_true', required=False, help='Export of orphan VMs.\n\n')
excavation.add_argument('--orphan_vms_cli',         dest='r_orphanvmscli', action='store_true', required=False, help='Export of orphan VMs (CLI).\n\n')
excavation.add_argument('--missing_vms',            dest='r_missing_vms', action='store_true', required=False, help='Export of missing VMs.\n\n')
excavation.add_argument('--missing_vms_cli',        dest='r_missingvmscli', action='store_true', required=False, help='Export of missing VMs (CLI).\n\n')
excavation.add_argument('--near_removal',           dest='r_near_removal', action='store_true', required=False, help='Export of devices near removal.\n\n')
excavation.add_argument('--near_removal_cli',       dest='r_nearremcli', action='store_true', required=False, help='Export of devices near removal (CLI).\n\n')
excavation.add_argument('--removed',                dest='r_removed', action='store_true', required=False, help='Export of devices removed recently.\n\n')
excavation.add_argument('--removed_cli',            dest='r_removedcli', action='store_true', required=False, help='Export of devices removed recently (CLI).\n\n')
excavation.add_argument('--os_lifecycle_cli',       dest='r_oslc', action='store_true', required=False, help='Export of OS lifecycle report (CLI).\n\n')
excavation.add_argument('--software_lifecycle_cli', dest='r_slc', action='store_true', required=False, help='Export of software lifecycle report (CLI).\n\n')
excavation.add_argument('--database_lifecycle_cli', dest='r_dblc', action='store_true', required=False, help='Export of database lifecycle report (CLI).\n\n')
excavation.add_argument('--unrecognised_cli',       dest='r_snmp', action='store_true', required=False, help='Export of unrecognised devices (CLI).\n\n')
excavation.add_argument('--software_agents_cli',    dest='r_agents', action='store_true', required=False, help='Analysis of installed agents (CLI).\n\n')
excavation.add_argument('--software_users',         dest='r_software_users', action='store_true', required=False, help='Software with running process usernames.\n\n')
excavation.add_argument('--software_users_cli',     dest='r_softuser', action='store_true', required=False, help='Software with running process usernames (CLI).\n\n')
excavation.add_argument('--tku',                    dest='r_tku', action='store_true', required=False, help='Export TKU summary.\n\n')
excavation.add_argument('--vault',                  dest='r_vault', action='store_true', required=False, help='Export vault details.\n\n')
excavation.add_argument('--hostname',               dest='r_hostname', action='store_true', required=False, help='Export hostname.\n\n')

global args
args = parser.parse_args()

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

logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w',force=True)
logger = logging.getLogger("_dismal_")
if args.debugging:
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

    ### CLI Appliance Management ###

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

        ######## API Management ########

    if api_target:

        api.admin(disco, args, reporting_dir)
        api.audit(search, args, reporting_dir)

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

    if args.sysadmin == "audit":
        cli.audit(cli_target, args, system_user, system_passwd, reporting_dir)

    ###########################################

    if args.tw_user:
        cli.user_management(args, cli_target)

    if args.servicecctl:
        cli.service_management(args, cli_target)

    if args.clear_queue:
        cli.clear_queue(cli_target)

    if args.r_baselinecli:
        cli.baseline(cli_target, args, reporting_dir)

    if args.tw_list_users:
        cli.tw_list_users(cli_target, reporting_dir)

    if args.r_knowledgecli:
        cli.knowledge(cli_target, system_user, system_passwd, reporting_dir)

    if args.r_cmdbsynccli:
        cli.cmdb_sync(cli_target, system_user, system_passwd, reporting_dir)

    if args.r_successcli:
        reporting.successful_cli(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_license_export:
        cli.licensing(cli_target, system_user, system_passwd, args, reporting_dir)
    
    if args.r_sensitivecli:
        cli.sensitive(cli_target,system_user, system_passwd, args, reporting_dir)

    if args.r_tplexportcli:
        cli.tplexport(cli_target, system_user, system_passwd, reporting_dir)
    
    if args.r_ecaerrorscli:
        cli.eca_errors(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_schedulescli:
        cli.schedules(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_excludescli:
        cli.excludes(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_portscli:
        cli.open_ports(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_utilisationcli:
        cli.host_util(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_orphanvmscli:
        cli.orphan_vms(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_missingvmscli:
        cli.missing_vms(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_nearremcli:
        cli.near_removal(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_removedcli:
        cli.removed(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_oslc:
        cli.os_lifecycle(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_slc:
        cli.software_lifecycle(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_dblc:
        cli.db_lifecycle(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_snmp:
        cli.unrecognised_snmp(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_agents:
        cli.installed_agents(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_softuser:
        cli.software_usernames(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.r_modules:
        cli.module_summary(cli_target, system_user, system_passwd, args, reporting_dir)

    if args.export_platforms:
        curl.platform_scripts(args.target, system_user, system_passwd, reporting_dir+"/platforms")

    if args.export_platforms_xml:
        cli.export_platforms(cli_target, system_user, system_passwd, reporting_dir)

    if args.tw_events:
        cli.tw_events(cli_target, system_user, system_passwd, reporting_dir)

if args.access_method=="api":
    
    ####### API Management #######

    if args.sysadmin == "api_version":
        api.admin(disco.admin(), args, reporting_dir)

    if args.sysadmin == "audit":
        api.audit(search, args, reporting_dir)

    ###########################################

    if args.r_activeruns:
        api.show_runs(disco, args)

    if args.r_discoveryruns:
        api.discovery_runs(disco, args, reporting_dir)

    if args.a_kill_run:
        api.cancel_run(disco, args)

    if args.r_vault:
        api.vault(vault, args, reporting_dir)

    if args.r_successful:
        print("\nCredential Success")
        print("------------------")
        api.success(creds, search, args, reporting_dir)

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
            with open(args.remlist) as f:
                for line in f:
                    success = api.remove_cred(creds, line.strip())
                    if success:
                        msg = "Credential %s deleted from %s." % (line.strip(), args.target)
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

    if args.r_schedules:
        builder.scheduling(creds, search, args)

    if args.r_device_ids:
        identities = builder.unique_identities(disco)
        data = []
        for identity in identities:
            data.append([identity['originating_endpoint'],identity['list_of_ips'],identity['list_of_names']])
        output.report(data, [ "Origating Endpoint", "List of IPs", "List of Names" ], args)

    if args.r_overlaps:
        builder.overlapping(disco, args)

    ####### API Reporting ########
    
    if args.a_query:
        api.query(search, args)

    if args.r_baseline:
        api.baseline(disco.baseline(), args, reporting_dir)

    if args.r_cred_device:
        builder.get_credential(search, creds, args.r_cred_device, args)

    if args.r_device:
        builder.get_device(args.r_device, search, creds, args)

    if args.r_hostname:
        api.hostname(args.appliance,reporting_dir)

    if args.r_tku:
        api.tku(knowledge,reporting_dir)

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

    if args.r_sensitive:
        api.sensitive(search, reporting_dir, args.target)

    if args.r_tpl_export:
        api.tpl_export(search, reporting_dir, args.target)

    if args.r_eca_errors:
        api.eca_errors(search, reporting_dir, args.target)
    
    if args.r_schedules:
        api.schedules(search, reporting_dir, args.target)
    
    if args.r_excludes:
        api.excludes(search, reporting_dir, args.target)

    if args.r_open_ports:
        api.open_ports(search, reporting_dir, args.target)

    if args.r_host_util:
        api.host_util(search, reporting_dir, args.target)

    if args.r_orphan_vms:
        api.orphan_vms(search, reporting_dir, args.target)

    if args.r_missing_vms:
        api.missing_vms(search, reporting_dir, args.target)
    
    if args.r_near_removal:
        api.near_removal(search, reporting_dir, args.target)

    if args.r_removed:
        api.removed(search, reporting_dir, args.target)

    if args.r_oslc:
        api.oslc(search, reporting_dir, args.target)

    if args.r_slc:
        api.slc(search, reporting_dir, args.target)

    if args.r_dblc:
        api.dblc(search, reporting_dir, args.target)

    if args.r_agents:
        api.agents(search, reporting_dir, args.target)

    if args.r_software_users:
        api.software_users(search, reporting_dir, args.target)

    if args.r_cmdb_config:
        api.cmdb_config(search, reporting_dir, args.target)

    if args.r_modules:
        api.modules(search, reporting_dir, args.target)

    if args.r_licensing_csv:
        api.licensing_csv(search, reporting_dir, args.target)

    if args.r_licensing:
        api.licensing(search, reporting_dir, args.target)

if cli_target:
    cli_target.close()

print(os.linesep)
