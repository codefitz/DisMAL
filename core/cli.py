# Discovery CLI commands for DisMAL

import sys
import logging
import getpass
import time
import sys
import ast

# Local modules
from . import access, output, queries

logger = logging.getLogger("_cli_")

def run_query(client,sysuser,passwd,query):
    runQuery = 'tw_query -u %s -p %s --csv "%s"'%(sysuser,passwd,query)
    logger.info("Running query: %s"%query)
    try:
        data = access.remote_cmd(runQuery,client)
        logger.debug("Query Ran:\n%s\n%s"%(query,data))
    except Exception as e:
        msg = "Query failed to run: %s\nException: %s\n%s" %(query,e.__class__,str(e))
        logger.error(msg)
        data = "%s\n>>>Query failed to run, check logs."%query
        print(data)
    return data

def user_management(args, client):
    login = args.a_user_man
    msg = "Checking for user login %s...\n" % login
    logger.info(msg)
    print(msg)
    out = access.remote_cmd('tw_listusers --filter %s' % login, client)
    logger.info(out)
    if not out:
        msg = "User not found: %s\n" % login
        logger.warning(msg)
        print(msg)
        sys.exit(1)

    print(out)

    while True:
        print("Options:\n\n 1. Set User %s Active"%login)
        print(" 2. Change User %s Password"%login)
        print(" 3. Set User %s Password OK"%login)
        print(" 4. Exit\n")
        management = input("Choice: ")
        if management == "1":
            upduser = access.remote_cmd('tw_upduser --active %s' % login, client)
            logger.info("Selected 1: %s"%upduser)
            print(upduser)
        if management == "2":
            passwd = getpass.getpass(prompt='Enter new password: ')
            stdin, stdout, stderr = client.exec_command('tw_passwd %s' % login)
            time.sleep(3)
            # Set password (2x)
            stdin.write('%s\n'%passwd)
            stdin.write('%s\n'%passwd)
            stdin.flush()
            data = []
            errors = []
            passwdset = False
            for line in data.readlines():
                if "at least 8 characters" in line:
                    print("WARNING:",line)
                if "Password set for user" in line:
                    passwdset = True
                    print("INFO:",line)
                data.append(line)
            for line in stderr.readlines():
                if "ERROR:" in line:
                    print(line)
                errors.append(line)
            logger.info("Selected 2: %s,%s"%(data,errors))
            if not passwdset:
                print("Problem with password change, check the logfile for details.\n")
        if management == "3":
            passok = access.remote_cmd('tw_upduser --passwd-ok %s' % login, client)
            logger.info("Selected 3: %s"%passok)
            print(passok)
        if management == "4":
            break
        print(out)

def service_management(args, client):
    cmd = args.a_services
    msg = "Sending Command: tw_service_control --%s\n" % cmd
    logger.info(msg)
    print(msg)
    output = access.remote_cmd('tw_service_control --%s'%cmd, client)
    logger.debug(output)
    print(output)
    return output

def clear_queue(client):
    gonogo = input("Continue with removing persistent reasoning files, no recovery (Y/y)?")
    if gonogo == "Y" or gonogo == "y":
        msg = "Stopping services..."
        logger.info(msg)
        print(msg)
        service_management("stop", client)
        msg = "Deleting persistent data..."
        logger.info(msg)
        cmd = 'rm -rfv /usr/tideway/var/persist/reasoning/engine/queue/*.pq'
        print("Sending:",cmd)
        output = access.remote_cmd(cmd, client)
        logger.info(output)
        print(output)
        cmd = 'rm -rfv /usr/tideway/var/persist/reasoning/engine/queue/*.rc'
        print("Sending:",cmd)
        output = access.remote_cmd(cmd, client)
        logger.info(output)
        print(output)
        msg = "Starting services..."
        logger.info(msg)
        service_management("start", client)
    elif gonogo == "No":
        print("Cancelled. No action taken.")

def baseline(client,args,instance_dir):
    cmd = 'tw_baseline --no-highlight'
    logger.info("Running %s"%cmd)
    data = access.remote_cmd(cmd,client)
    logger.debug("Baseline Ouptut:\n%s"%data)
    header = [ "Check", "Result", "Description" ]
    checked = []
    for line in data.split("\r\n"):
        checklist = line.split("\n",2)[2]
        for checks in checklist.split("\n"):
            check = checks.split(":")
            checked.append([s.strip() for s in check])
    header.insert(0,"Discovery Instance")
    for row in checked:
        row.insert(0, args.discovery)
    output.csv_file(checked, header, instance_dir+"/baseline.csv")

def knowledge(client,sysuser,passwd,instance_dir):
    cmd = 'tw_pattern_management --list-uploads'
    logger.info("Running %s"%cmd)
    data = access.remote_cmd("%s -u %s -p %s"%(cmd,sysuser,passwd),client)
    logger.debug("Knowledge Ouptut:\n%s"%data)
    output.txt_dump(data,instance_dir+"/knowledge.txt")

def cmdb_sync(client,sysuser,passwd,instance_dir):
    cmd = 'tw_sync_control --list'
    logger.info("Running %s"%cmd)
    data = access.remote_cmd('%s -u %s -p %s'%(cmd,sysuser,passwd),client)
    logger.debug("Taxonomy Deprecation:\n%s"%data)
    output.txt_dump(data,instance_dir+"/cmdb_sync.txt")

def licensing(client,sysuser,passwd,args,instance_dir):
    cmd = 'command -v tw_license_report && tw_license_report'
    logger.info("Running %s"%cmd)
    data = access.remote_cmd('%s -u %s -p %s'%(cmd,sysuser,passwd),client)
    logger.debug("Licenses:\n%s"%data)
    if not result:
        result = run_query(client,sysuser,passwd,queries.hc_license)
        output.save2csv(result, instance_dir+"/license.csv",args.discovery)
    else:
        output.txt_dump(result,instance_dir+"/license.txt")

def sensitive(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_sensitive_data)
    output.save2csv(result, instance_dir+"/dq_sensitive_data.csv",args.discovery)

def tplexport(client,sysuser,syspass,instance_dir):
    output.tpl_export(None, queries.hc_tpl_export, instance_dir, "ssh", client, syspass)

def eca_errors(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_eca_error)
    output.save2csv(result, instance_dir+"/dq_eca_errors.csv",args.discovery)

def schedules(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_scan_ranges)
    output.save2csv(result, instance_dir+"/dq_scan_ranges.csv",args.discovery)

def excludes(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_exclude_ranges)
    output.save2csv(result, instance_dir+"/dq_exclude_ranges.csv",args.discovery)

def open_ports(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_open_ports)
    output.save2csv(result, instance_dir+"/dq_open_ports.csv",args.discovery)

def host_util(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_host_utilisation)
    output.save2csv(result, instance_dir+"/dq_host_utilisation.csv",args.discovery)

def orphan_vms(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_orphan_vms)
    output.save2csv(result, instance_dir+"/dq_orphan_vms.csv",args.discovery)

def missing_vms(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_missing_vms)
    output.save2csv(result, instance_dir+"/dq_missing_vms.csv",args.discovery)

def audit(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_audit)
    output.save2csv(result, instance_dir+"/dq_audit.csv",args.discovery)

def near_removal(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_near_removal)
    output.save2csv(result, instance_dir+"/dq_near_removal.csv",args.discovery)

def removed(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_removed)
    output.save2csv(result, instance_dir+"/hc_removed.csv",args.discovery)

def os_lifecycle(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_os_lifecycle)
    output.save2csv(result, instance_dir+"/dq_os_lifecycle.csv",args.discovery)

def software_lifecycle(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_software_lifecycle)
    output.save2csv(result, instance_dir+"/dq_software_lifecycle.csv",args.discovery)

def db_lifecycle(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_db_lifecycle)
    output.save2csv(result, instance_dir+"/dq_db_lifecycle.csv",args.discovery)

def unrecognised_snmp(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_snmp_devices)
    output.save2csv(result, instance_dir+"/dq_snmp_unrecognised.csv",args.discovery)

def installed_agents(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_agents)
    output.save2csv(result, instance_dir+"/dq_installed_agents.csv",args.discovery)

def software_usernames(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_user_accounts)
    output.save2csv(result, instance_dir+"/dq_software_usernames.csv",args.discovery)

def module_summary(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.pm_summary)
    output.save2csv(result, instance_dir+"/dq_pattern_modules.csv",args.discovery)

######

def df_h(client,instance_dir,args):
    cmd = 'df -h | awk \'NR > 1 {OFS=",";print $1,$6,$2,$3,$4,$5}\''
    logger.info("Running %s"%cmd)
    data = access.remote_cmd(cmd,client)
    logger.debug("df -h:\n%s"%data)
    header = [ "fs", "mount", "size", "used", "available", "Used %" ]
    output.cmd2csv(header, data, ",", instance_dir+"/disk.csv",args.discovery)

def timedatectl(client,instance_dir):
    # NTP Check
    cmd = 'command -v timedatectl &> /dev/null && timedatectl status | grep "NTP" || ntpstat'
    logger.info("Running %s"%cmd)
    ntp_status = access.remote_cmd(cmd,client)
    logger.debug("NTP Status:\n%s"%ntp_status)
    cmd = 'command -v timedatectl &> /dev/null && timedatectl status | grep "Time zone" || cat /etc/sysconfig/clock && date +%Z'
    logger.info("Running %s"%cmd)
    time_zone = access.remote_cmd(cmd,client)
    logger.debug("Time Zone:\n%s"%time_zone)
    output.txt_dump(ntp_status,instance_dir+"/ntp_status.txt")
    output.txt_dump(time_zone,instance_dir+"/timezone.txt")

def core_dumps(client,instance_dir):
    # Core Dumps
    cmd = 'command -v tw_check_cores &> /dev/null && tw_check_cores || ls -l $HOME/cores'
    logger.info("Running %s"%cmd)
    data = access.remote_cmd(cmd,client)
    logger.debug("Core Dumps:\n%s"%data)
    output.txt_dump(data,instance_dir+"/core_dumps.txt")

def cmdb_errors(client,instance_dir):
    # CMDB Errors
    cmd = 'cat /usr/tideway/log/tw_svc_cmdbsync_transformer.log | egrep -i "Failed creation|Failed deletion|RPC call failed" || echo "No errors"'
    logger.info("Running %s"%cmd)
    data = access.remote_cmd(cmd,client)
    logger.debug("CMDB Errors:\n%s"%data)
    output.txt_dump(data,instance_dir+"/cmdb_errors.txt")

def ldap(client,instance_dir):
    # LDAP
    cmd = 'tw_secopts | grep LDAP_ENABLED'
    logger.info("Running %s"%cmd)
    data = access.remote_cmd(cmd,client)
    logger.debug("LDAP:\n%s"%data)
    output.txt_dump(data,instance_dir+"/ldap.txt")

def ect_passwd(client,instance_dir,args):
    # Users
    cmd = 'cat /etc/passwd'
    logger.info("Running %s"%cmd)
    data = access.remote_cmd(cmd,client)
    logger.debug("/etc/passwd:\n%s"%data)
    header = [ "login", "password", "uid", "gid", "gecos", "homedir", "shellcmd" ]
    output.cmd2csv(header, data, ":", instance_dir+"/etc_passwd.csv",args.discovery)

def syslog(client,twpasswd,instance_dir):
    # Syslog
    cmd = 'command -v systemctl && systemctl is-active rsyslog'
    logger.info("Running %s"%cmd)
    syslog = access.remote_cmd('%s || echo %s | sudo -S /sbin/service rsyslog status'%(cmd,twpasswd),client)
    logger.debug("systemctl status rsyslog:\n%s"%syslog)
    cmd = 'cat /etc/rsyslog.conf | sed -e \'1,/#\$ActionResumeRetryCount/d\''
    logger.info("Running %s"%cmd)
    config = access.remote_cmd(cmd,client)
    logger.debug("Config:\n%s"%config)
    status = syslog+"\n"+config
    output.txt_dump(status,instance_dir+"/syslog.txt")

def cluster_info(client,instance_dir):
    # Cluster Info
    cmd = 'tw_cluster_control --show-members'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("Cluster Info:\n%s"%result)
    output.txt_dump(result,instance_dir+"/cluster.txt")

def ui_errors(client,instance_dir):
    # UI Errors
    cmd = 'ls -l /usr/tideway/python/ui/web/ErrorMsgs/'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("UI Errors:\n%s"%result)
    output.txt_dump(result,instance_dir+"/ui_errors.txt")

def tax_deprecated(client,sysuser,passwd,instance_dir):
    # Deprecation
    cmd = 'tw_tax_deprecated'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd('%s -u %s -p %s'%(cmd,sysuser,passwd),client)
    logger.debug("Taxonomy Deprecation:\n%s"%result)
    output.txt_dump(result,instance_dir+"/tax_deprecation.txt")

def vmware_tools(client,twpasswd,instance_dir):
    cmd = 'command -v systemctl && systemctl is-active vmware-tools'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd('%s || echo %s | sudo -S /sbin/service vmware-tools status'%(cmd,twpasswd),client)
    logger.debug("VMware Tools:\n%s"%result)
    output.txt_dump(result,instance_dir+"/vmware_tools.txt")

def tw_options(client,sysuser,passwd,instance_dir):
    opt_cmd = 'tw_options'
    logger.info("Running %s"%opt_cmd)
    options = access.remote_cmd('%s -u %s -p %s'%(opt_cmd,sysuser,passwd),client)
    logger.debug("tw_options:\n%s"%current)
    output.txt_dump(options,instance_dir+"/tw_options.txt")
    get_opts = 'python3 -c "from common.options.main import getOptions; print(getOptions())"'
    logger.info("Running %s"%get_opts)
    current = access.remote_cmd(get_opts,client)
    logger.debug("Current tw_options:\n%s"%current)
    currents = ast.literal_eval(current)
    output.txt_dump(str(currents),instance_dir+"/tw_options_current.dict")
    get_defaults = 'python3 -c "from common.options.defaults import getDefaults; print(getDefaults())"'
    logger.info("Running %s"%get_defaults)
    default = access.remote_cmd(get_defaults,client)
    logger.debug("Default tw_options:\n%s"%default)
    defaults = ast.literal_eval(default)
    output.txt_dump(str(defaults),instance_dir+"/tw_options_default.dict")

def tw_config_dump(client,instance_dir):
    cmd = 'tw_config_dump'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("tw_config_dump:\n%s"%result)
    output.txt_dump(result,instance_dir+"/config_dump.xml")

def tw_crontab(client,instance_dir):
    cmd = 'crontab -l'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("crontab:\n%s"%result)
    output.txt_dump(result,instance_dir+"/crontab.txt")

def tw_list_users(client,instance_dir):
    cmd = 'tw_listusers'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("tw_listusers:\n%s"%result)
    output.txt_dump(result,instance_dir+"/users.txt")

def export_platforms(client,sysuser,passwd,instance_dir):
    # Exports platform scripts, probably overkill unless customer is dedicated, heavily customised
    cmd = 'tw_disco_export_platforms'
    logger.info("Running %s"%cmd)
    current = access.remote_cmd('%s -u %s -p %s -o /usr/tideway/data/customer/platforms.xml && cat /usr/tideway/data/customer/platforms.xml'%(cmd,sysuser,passwd),client)
    default = access.remote_cmd('%s --default -u %s -p %s -o /usr/tideway/data/customer/platforms_default.xml && cat /usr/tideway/data/customer/platforms_default.xml'%(cmd,sysuser,passwd),client)
    logger.debug("Platforms:\n%s"%current)
    output.txt_dump(current,instance_dir+"/platforms.xml")
    output.txt_dump(default,instance_dir+"/platforms_default.xml")

def tw_events(client,sysuser,passwd,instance_dir):
    cmd = 'tw_event_control'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd('%s -u %s -p %s --list'%(cmd,sysuser,passwd),client)
    logger.debug("tw_event_control:\n%s"%result)
    output.txt_dump(result,instance_dir+"/events.txt")

def reports_model(client,sysuser,passwd,instance_dir):
    # no idea what this does, never got it to run on demo appliance
    cmd = 'tw_check_reports_model'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd('%s -u %s -p %s'%(cmd,sysuser,passwd),client)
    if not result:
        result = "No output."
    logger.debug("tw_check_reports_model:\n%s"%result)
    output.txt_dump(result,instance_dir+"/reports_model.txt")

def reasoning(client,sysuser,passwd,instance_dir):
    # Get reasoning info
    cmd = 'tw_reasoningstatus --consolidation-status'
    logger.info("Running %s"%cmd)
    consolidation = access.remote_cmd('%s -u %s -p %s'%(cmd,sysuser,passwd),client)
    logger.debug("Consolidation Status:\n%s"%consolidation)
    cmd = 'tw_reasoningstatus --discovery-outposts'
    logger.info("Running %s"%cmd)
    outposts = access.remote_cmd('%s -u %s -p %s'%(cmd,sysuser,passwd),client)
    logger.debug("Outposts:\n%s"%outposts)
    cmd = 'tw_reasoningstatus --discovery-status'
    logger.info("Running %s"%cmd)
    disco_status = access.remote_cmd('%s -u %s -p %s'%(cmd,sysuser,passwd),client)
    logger.debug("Discovery Status:\n%s"%disco_status)
    cmd = 'tw_reasoningstatus --waiting-full'
    logger.info("Running %s"%cmd)
    waiting = access.remote_cmd('%s -u %s -p %s'%(cmd,sysuser,passwd),client)
    if not waiting:
        waiting = "No output."
    logger.debug("Waiting:\n%s"%waiting)
    output.txt_dump(consolidation,instance_dir+"/consolidation.txt")
    output.txt_dump(outposts,instance_dir+"/outposts.txt")
    output.txt_dump(disco_status,instance_dir+"/discovery_status.txt")
    output.txt_dump(waiting,instance_dir+"/waiting.txt")

def certificates(client,appliance,instance_dir):
    cmd = 'openssl s_client -showcerts -connect %s:443'%appliance
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("certificates:\n%s"%result)
    output.txt_dump(result,instance_dir+"/ssl.txt")

def resolv_conf(client,instance_dir):
    cmd = 'cat /etc/resolv.conf'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("resolv.conf:\n%s"%result)
    output.txt_dump(result,instance_dir+"/resolv.conf")

def ds_compact(client,instance_dir):
    offcmd = 'cat /usr/tideway/log/tw_ds_offline_compact.log'
    oncmd = 'cat /usr/tideway/log/tw_ds_compact.log'
    logger.info("Running %s"%offcmd)
    offline = access.remote_cmd(offcmd,client)
    logger.debug("tw_ds_offline_compact.log:\n%s"%offline)
    logger.info("Running %s"%oncmd)
    online = access.remote_cmd(oncmd,client)
    logger.debug("tw_ds_offline_compact.log:\n%s"%online)
    output.txt_dump(offline,instance_dir+"/tw_ds_offline_compact.log")
    output.txt_dump(online,instance_dir+"/tw_ds_compact.log")

def tree(client,instance_dir,args):
    cmd = 'find /usr/tideway'
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("tree:\n%s"%result)
    header = [ "path" ]
    output.cmd2csv(header, result, ",", instance_dir+"/tree.csv",args.discovery)

def host_info(client,instance_dir):
    uname = 'uname -a'
    logger.info("Running %s"%uname)
    uname_out = access.remote_cmd(uname,client)
    logger.debug("uname -a:\n%s"%uname_out)
    hostname = 'hostname'
    logger.info("Running %s"%hostname)
    hostname_out = access.remote_cmd(hostname,client)
    logger.debug("hostname:\n%s"%hostname_out)
    ipaddr = 'hostname -I'
    logger.info("Running %s"%ipaddr)
    ipaddr_out = access.remote_cmd(ipaddr,client)
    logger.debug("ip addr:\n%s"%ipaddr_out)
    output.txt_dump(uname,instance_dir+"/uname.txt")
    output.txt_dump(hostname,instance_dir+"/hostname.txt")
    output.txt_dump(ipaddr,instance_dir+"/ipaddr.txt")