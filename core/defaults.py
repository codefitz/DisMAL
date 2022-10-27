# Default configs for DisMAL

import os
#from dismal import args

# Config
pwd      = os.getcwd()

# Exported files location
#files_path = pwd + "/output_" + args.target.replace(".","_")

# Exported file names
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

# Headers
etc_passwd_header   = [ "login", "password", "uid", "gid", "gecos", "homedir", "shellcmd" ]
df_h_header         = [ "fs", "mount", "size", "used", "available", "Used %" ]

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