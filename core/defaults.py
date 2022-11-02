# Default configs for DisMAL

import os

# Config
pwd = os.getcwd()

# Exported files location
#files_path = pwd + "/output_" + args.target.replace(".","_")

# Exported file names
api_filename                = "/versions.txt"
audit_filename              = "/audit.csv"
baseline_filename           = "/baseline.csv"
cluster_filename            = "/cluster.txt"
cmdb_errors_filename        = "/cmdb_errors.txt"
cmdbsync_filename           = "/cmdb_sync.txt"
config_dump_filename        = "/config_dump.xml"
consolidation_filename      = "/consolidation.txt"
core_dumps_filename         = "/core_dumps.txt"
crontab_filename            = "/crontab.txt"
current_opts_filename       = "/tw_options_current.dict"
default_opts_filename       = "/tw_options_default.dict"
disco_status_filename       = "/discovery_status.txt"
disk_filename               = "/disk.csv"
etc_passwd_filename         = "/etc_passwd.csv"
hostname_filename           = "/hostname.txt"
ipaddr_filename             = "/ipaddr.txt"
ldap_filename               = "/ldap.txt"
ntp_filename                = "/ntp_status.txt"
outposts_filename           = "/outposts.txt"
reasoning_filename          = "/waiting.txt"
reports_model_filename      = "/reports_model.txt"
resolv_conf_filename        = "/resolv.conf"
syslog_filename             = "/syslog.txt"
tax_deprecation_filename    = "/tax_deprecation.txt"
timezone_filename           = "/timezone.txt"
tls_certificates_filename   = "/tls_certificates.txt"
tree_filename               = "/tree.csv"
tw_ds_compact_filename      = "/tw_ds_compact.log"
tw_ds_offline_filename      = "/tw_ds_offline_compact.log"
tw_options_filename         = "/tw_options.txt"
ui_errors_filename          = "/ui_errors.txt"
uname_filename              = "/uname.txt"
vmware_tools_filename       = "/vmware_tools.txt"
tw_events_filename          = "/events.txt"
current_platforms_filename  = "/platforms_current.xml"
default_platforms_filename  = "/platforms_default.xml"
tw_knowledge_filename       = "/knowledge.txt"
tw_license_raw_filename     = "/license.txt"
tw_license_csv_filename     = "/license.csv"
tw_license_zip_filename     = "/license.zip"
tw_listusers_filename       = "/users.txt"

# Headers
baseline_header     = [ "Check", "Result", "Description" ]
df_h_header         = [ "fs", "mount", "size", "used", "available", "Used %" ]
etc_passwd_header   = [ "login", "password", "uid", "gid", "gecos", "homedir", "shellcmd" ]
tree_header         = [ "path" ]

# CLI commands
baseline_cmd            = 'tw_baseline --no-highlight'
cluster_cmd             = 'tw_cluster_control --show-members'
cmdb_errors_cmd         = 'cat /usr/tideway/log/tw_svc_cmdbsync_transformer.log | egrep -i "Failed creation|Failed deletion|RPC call failed" || echo "No errors"'
cmdbsync_cmd            = 'tw_sync_control --list'
cons_status_cmd         = 'tw_reasoningstatus --consolidation-status'
core_dumps_cmd          = 'command -v tw_check_cores &> /dev/null && tw_check_cores || ls -l $HOME/cores'
df_h_cmd                = 'df -h | awk \'NR > 1 {OFS=",";print $1,$6,$2,$3,$4,$5}\''
disco_status_cmd        = 'tw_reasoningstatus --discovery-status'
ds_status_off_cmd       = 'cat /usr/tideway/log/tw_ds_offline_compact.log'
ds_status_on_cmd        = 'cat /usr/tideway/log/tw_ds_compact.log'
ect_passwd_cmd          = 'cat /etc/passwd'
get_defaults_cmd        = 'python3 -c "from common.options.defaults import getDefaults; print(getDefaults())"'
get_opts_cmd            = 'python3 -c "from common.options.main import getOptions; print(getOptions())"'
hostname_cmd            = 'hostname'
ipaddr_cmd              = 'hostname -I'
ldap_cmd                = 'tw_secopts | grep LDAP_ENABLED'
ntp_cmd                 = 'command -v timedatectl &> /dev/null && timedatectl status | grep "NTP" || ntpstat'
outposts_cmd            = 'tw_reasoningstatus --discovery-outposts'
reasoning_cmd           = 'tw_reasoningstatus --waiting-full'
reports_model_cmd       = 'tw_check_reports_model'
resolv_conf_cmd         = 'cat /etc/resolv.conf'
rsyslog_cmd             = 'command -v systemctl && systemctl is-active rsyslog'
rsyslog_conf_cmd        = 'cat /etc/rsyslog.conf | sed -e \'1,/#\$ActionResumeRetryCount/d\''
tax_deprecated_cmd      = 'tw_tax_deprecated'
tls_certificates_cmd    = 'openssl s_client -showcerts -connect'
tree_cmd                = 'find /usr/tideway'
tw_config_dump_cmd      = 'tw_config_dump'
tw_crontab_cmd          = 'crontab -l'
tw_options_cmd          = 'tw_options'
tz_cmd                  = 'command -v timedatectl &> /dev/null && timedatectl status | grep "Time zone" || cat /etc/sysconfig/clock && date +%Z'
ui_errors_cmd           = 'ls -l /usr/tideway/python/ui/web/ErrorMsgs/'
uname_cmd               = 'uname -a'
vmware_tools_cmd        = 'command -v systemctl && systemctl is-active vmware-tools'
tw_events_cmd           = 'tw_event_control'
tw_platforms_cmd        = 'tw_disco_export_platforms'
tw_knowledge_cmd        = 'tw_pattern_management --list-uploads'
licensing_cmd           = 'command -v tw_license_report && tw_license_report'
tw_listusers_cmd        = 'tw_listusers'