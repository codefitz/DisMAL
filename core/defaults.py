# Default configs for DisMAL

import os

# Config
pwd      = os.getcwd()

# Exported files location
#files_path = pwd + "/output_" + args.target.replace(".","_")

# Exported file names
audit_filename              = "/audit.csv"
tls_certificates_filename   = "/tls_certificates.txt"
etc_passwd_filename         = "/etc_passwd.csv"
cluster_filename            = "/cluster.txt"
cmdb_errors_filename        = "/cmdb_errors.txt"
core_dumps_filename         = "/core_dumps.txt"
disk_filename               = "/disk.csv"
resolv_conf_filename        = "/resolv.conf"
tw_ds_offline_filename      = "/tw_ds_offline_compact.log"
tw_ds_compact_filename      = "/tw_ds_compact.log"
uname_filename              = "/uname.txt"
hostname_filename           = "/hostname.txt"
ipaddr_filename             = "/ipaddr.txt"
ldap_filename               = "/ldap.txt"
ntp_filename                = "/ntp_status.txt"
timezone_filename           = "/timezone.txt"
consolidation_filename      = "/consolidation.txt"
outposts_filename           = "/outposts.txt"
disco_status_filename       = "/discovery_status.txt"
reasoning_filename          = "/waiting.txt"
reports_model_filename      = "/reports_model.txt"
syslog_filename             = "/syslog.txt"
tax_deprecation_filename    = "/tax_deprecation.txt"
tree_filename               = "/tree.csv"
config_dump_filename        = "/config_dump.xml"
crontab_filename            = "/crontab.txt"
tw_options_filename         = "/tw_options.txt"
current_opts_filename       = "/tw_options_current.dict"
default_opts_filename       = "/tw_options_default.dict"
ui_errors_filename          = "/ui_errors.txt"
vmware_tools_filename       = "/vmware_tools.txt"
api_filename                = "/versions.txt"

# Headers
etc_passwd_header   = [ "login", "password", "uid", "gid", "gecos", "homedir", "shellcmd" ]
df_h_header         = [ "fs", "mount", "size", "used", "available", "Used %" ]
tree_header         = [ "path" ]

# CLI commands
tls_certificates_cmd    = 'openssl s_client -showcerts -connect'
ect_passwd_cmd          = 'cat /etc/passwd'
cluster_cmd             = 'tw_cluster_control --show-members'
cmdb_errors_cmd         = 'cat /usr/tideway/log/tw_svc_cmdbsync_transformer.log | egrep -i "Failed creation|Failed deletion|RPC call failed" || echo "No errors"'
core_dumps_cmd          = 'command -v tw_check_cores &> /dev/null && tw_check_cores || ls -l $HOME/cores'
df_h_cmd                = 'df -h | awk \'NR > 1 {OFS=",";print $1,$6,$2,$3,$4,$5}\''
resolv_conf_cmd         = 'cat /etc/resolv.conf'
ds_status_off_cmd       = 'cat /usr/tideway/log/tw_ds_offline_compact.log'
ds_status_on_cmd        = 'cat /usr/tideway/log/tw_ds_compact.log'
uname_cmd               = 'uname -a'
hostname_cmd            = 'hostname'
ipaddr_cmd              = 'hostname -I'
ldap_cmd                = 'tw_secopts | grep LDAP_ENABLED'
ntp_cmd                 = 'command -v timedatectl &> /dev/null && timedatectl status | grep "NTP" || ntpstat'
tz_cmd                  = 'command -v timedatectl &> /dev/null && timedatectl status | grep "Time zone" || cat /etc/sysconfig/clock && date +%Z'
cons_status_cmd         = 'tw_reasoningstatus --consolidation-status'
outposts_cmd            = 'tw_reasoningstatus --discovery-outposts'
disco_status_cmd        = 'tw_reasoningstatus --discovery-status'
reasoning_cmd           = 'tw_reasoningstatus --waiting-full'
reports_model_cmd       = 'tw_check_reports_model'
rsyslog_cmd             = 'command -v systemctl && systemctl is-active rsyslog'
rsyslog_conf_cmd        = 'cat /etc/rsyslog.conf | sed -e \'1,/#\$ActionResumeRetryCount/d\''
tax_deprecated_cmd      = 'tw_tax_deprecated'
tree_cmd                = 'find /usr/tideway'
tw_config_dump_cmd      = 'tw_config_dump'
tw_crontab_cmd          = 'crontab -l'
tw_options_cmd          = 'tw_options'
get_opts_cmd            = 'python3 -c "from common.options.main import getOptions; print(getOptions())"'
get_defaults_cmd        = 'python3 -c "from common.options.defaults import getDefaults; print(getDefaults())"'
ui_errors_cmd           = 'ls -l /usr/tideway/python/ui/web/ErrorMsgs/'
vmware_tools_cmd        = 'command -v systemctl && systemctl is-active vmware-tools'