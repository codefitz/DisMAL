# Discovery CLI commands for DisMAL

import sys
import logging
import getpass
import time
import sys
import ast

# Local modules
from . import access, output, queries, defaults

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

def certificates(client,args,dir):
    cmd = "%s %s:443"%(defaults.tls_certificates_cmd,args.target)
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("Certificates:\n%s"%result)
    output.define_txt(args,result,dir+defaults.tls_certificates_filename,None)

def etc_passwd(client,args,dir):
    cmd = defaults.ect_passwd_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("/etc/passwd:\n%s"%result)
    output.define_csv(args,defaults.etc_passwd_header,result,dir+defaults.etc_passwd_filename,args.output_file,args.target,"cmd")

def cluster_info(client,args,dir):
    cmd = defaults.cluster_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("Cluster Info:\n%s"%result)
    output.define_txt(args,result,dir+defaults.cluster_filename,None)

def cmdb_errors(client,args,dir):
    cmd = defaults.cmdb_errors_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("CMDB Errors:\n%s"%result)
    output.define_txt(args,result,dir+defaults.cmdb_errors_filename,None)

def core_dumps(client,args,dir):
    cmd = defaults.core_dumps_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("Core Dumps:\n%s"%result)
    output.define_txt(args,result,dir+defaults.core_dumps_filename,None)

def df_h(client,args,dir):
    cmd = defaults.df_h_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("df -h:\n%s"%result)
    output.define_csv(args,defaults.df_h_header,result,dir+defaults.disk_filename,args.output_file,args.target,"cmd")

def resolv_conf(client,args,dir):
    cmd = defaults.resolv_conf_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("resolv.conf:\n%s"%result)
    output.define_txt(args,result,dir+defaults.resolv_conf_filename,None)

def ds_compact(client,args,dir):
    offcmd = defaults.ds_status_off_cmd
    oncmd = defaults.ds_status_on_cmd
    logger.info("Running %s"%offcmd)
    logger.info("Running %s"%oncmd)
    offline = access.remote_cmd(offcmd,client)
    logger.debug("tw_ds_offline_compact.log:\n%s"%offline)
    logger.info("Running %s"%oncmd)
    online = access.remote_cmd(oncmd,client)
    logger.debug("tw_ds_online_compact.log:\n%s"%online)
    output.define_txt(args,offline,dir+defaults.tw_ds_offline_filename,"offline")
    output.define_txt(args,online,dir+defaults.tw_ds_compact_filename,"online")

def host_info(client,args,dir):
    uname = defaults.uname_cmd
    logger.info("Running %s"%uname)
    uname_out = access.remote_cmd(uname,client)
    logger.debug("uname -a:\n%s"%uname_out)
    hostname = defaults.hostname_cmd
    logger.info("Running %s"%hostname)
    hostname_out = access.remote_cmd(hostname,client)
    logger.debug("hostname:\n%s"%hostname_out)
    ipaddr = defaults.ipaddr_cmd
    logger.info("Running %s"%ipaddr)
    ipaddr_out = access.remote_cmd(ipaddr,client)
    logger.debug("ip addr:\n%s"%ipaddr_out)
    output.define_txt(args,uname_out,dir+defaults.uname_filename,"uname")
    output.define_txt(args,uname_out,dir+defaults.hostname_filename,"hostname")
    output.define_txt(args,uname_out,dir+defaults.ipaddr_filename,"ipaddr")

def ldap(client,args,dir):
    cmd = defaults.ldap_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("LDAP:\n%s"%result)
    output.define_txt(args,result,dir+defaults.ldap_filename,None)

def timedatectl(client,args,dir):
    cmd = defaults.ntp_cmd
    logger.info("Running %s"%cmd)
    ntp_status = access.remote_cmd(cmd,client)
    logger.debug("NTP Status:\n%s"%ntp_status)
    cmd = defaults.tz_cmd
    logger.info("Running %s"%cmd)
    time_zone = access.remote_cmd(cmd,client)
    logger.debug("Time Zone:\n%s"%time_zone)
    output.define_txt(args,ntp_status,dir+defaults.ntp_filename,"ntp")
    output.define_txt(args,time_zone,dir+defaults.timezone_filename,"tz")

def reasoning(client,args,user,passwd,dir):
    cmd = defaults.cons_status_cmd
    logger.info("Running %s"%cmd)
    consolidation = access.remote_cmd('%s -u %s -p %s'%(cmd,user,passwd),client)
    logger.debug("Consolidation Status:\n%s"%consolidation)
    cmd = defaults.outposts_cmd
    logger.info("Running %s"%cmd)
    outposts = access.remote_cmd('%s -u %s -p %s'%(cmd,user,passwd),client)
    logger.debug("Outposts:\n%s"%outposts)
    cmd = defaults.disco_status_cmd
    logger.info("Running %s"%cmd)
    disco_status = access.remote_cmd('%s -u %s -p %s'%(cmd,user,passwd),client)
    logger.debug("Discovery Status:\n%s"%disco_status)
    cmd = defaults.reasoning_cmd
    logger.info("Running %s"%cmd)
    waiting = access.remote_cmd('%s -u %s -p %s'%(cmd,user,passwd),client)
    if not waiting:
        waiting = "No output."
    logger.debug("Waiting:\n%s"%waiting)
    output.define_txt(args,consolidation,dir+defaults.consolidation_filename,"consolidation")
    output.define_txt(args,outposts,dir+defaults.outposts_filename,"outposts")
    output.define_txt(args,disco_status,dir+defaults.disco_status_filename,"disco_status")
    output.define_txt(args,waiting,dir+defaults.reasoning_filename,"waiting")

def reports_model(client,args,user,passwd,dir):
    # no idea what this does, never got it to run on demo appliance
    cmd = defaults.reports_model_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd('%s -u %s -p %s'%(cmd,user,passwd),client)
    if not result:
        result = "No output."
    logger.debug("tw_check_reports_model:\n%s"%result)
    output.define_txt(args,result,dir+defaults.reports_model_filename,None)

def syslog(client,args,passwd,dir):
    cmd = '%s || echo %s | sudo -S /sbin/service rsyslog status'%(defaults.rsyslog_cmd,passwd)
    logger.info("Running %s"%cmd)
    syslog = access.remote_cmd(cmd,client)
    logger.debug("systemctl status rsyslog:\n%s"%syslog)
    cmd = defaults.rsyslog_conf_cmd
    logger.info("Running %s"%cmd)
    config = access.remote_cmd(cmd,client)
    logger.debug("Config:\n%s"%config)
    status = syslog+"\n"+config
    output.define_txt(args,status,dir+defaults.syslog_filename,None)

def tax_deprecated(client,args,user,passwd,dir):
    # Deprecation
    cmd = '%s -u %s -p %s'%(defaults.tax_deprecated_cmd,user,passwd)
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("Taxonomy Deprecation:\n%s"%result)
    output.define_txt(args,result,dir+defaults.tax_deprecation_filename,None)

def tree(client,args,dir):
    cmd = defaults.tree_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("tree:\n%s"%result)
    output.define_csv(args,defaults.tree_header,result,dir+defaults.tree_filename,args.output_file,args.target,"cmd")

def tw_config_dump(client,args,dir):
    cmd = defaults.tw_config_dump_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("tw_config_dump:\n%s"%result)
    output.define_txt(args,result,dir+defaults.config_dump_filename,None)

def tw_crontab(client,args,dir):
    cmd = defaults.tw_crontab_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("crontab:\n%s"%result)
    output.define_txt(args,result,dir+defaults.crontab_filename,None)

def tw_options(client,args,user,passwd,dir):
    opt_cmd = '%s -u %s -p %s'%(defaults.tw_options_cmd,user,passwd)
    logger.info("Running %s"%opt_cmd)
    options = access.remote_cmd(opt_cmd,client)
    logger.debug("tw_options:\n%s"%options)
    get_opts = defaults.get_opts_cmd
    logger.info("Running %s"%get_opts)
    current = access.remote_cmd(get_opts,client)
    logger.debug("Current tw_options:\n%s"%current)
    current_opts = ast.literal_eval(current)
    get_defaults = defaults.get_defaults_cmd
    logger.info("Running %s"%get_defaults)
    default = access.remote_cmd(get_defaults,client)
    logger.debug("Default tw_options:\n%s"%default)
    default_opts = ast.literal_eval(default)
    output.define_txt(args,options,dir+defaults.tw_options_filename,"twoptions")
    output.define_txt(args,current_opts,dir+defaults.current_opts_filename,"twoptions_current")
    output.define_txt(args,default_opts,dir+defaults.default_opts_filename,"twoptions_default")

def ui_errors(client,args,dir):
    cmd = defaults.ui_errors_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("UI Errors:\n%s"%result)
    output.define_txt(args,result,dir+defaults.ui_errors_filename,None)

def vmware_tools(client,args,passwd,dir):
    cmd = '%s || echo %s | sudo -S /sbin/service vmware-tools status'%(defaults.vmware_tools_cmd,passwd)
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("VMware Tools:\n%s"%result)
    output.define_txt(args,result,dir+defaults.vmware_tools_filename,None)

def syslog(client,args,passwd,dir):
    # Syslog
    cmd = '%s || echo %s | sudo -S /sbin/service rsyslog status'%(defaults.rsyslog_cmd,passwd)
    logger.info("Running %s"%cmd)
    syslog = access.remote_cmd(cmd,client)
    logger.debug("systemctl status rsyslog:\n%s"%syslog)
    cmd = defaults.rsyslog_conf_cmd
    logger.info("Running %s"%cmd)
    config = access.remote_cmd(cmd,client)
    logger.debug("Config:\n%s"%config)
    status = syslog+"\n"+config
    output.define_txt(args,status,dir+defaults.syslog_filename,None)

def audit(client,args,user,passwd,dir):
    result = run_query(client,user,passwd,queries.hc_audit)
    output.define_csv(args,None,result,dir+defaults.audit_filename,args.output_file,args.target,"csv")

def baseline(client,args,dir):
    cmd = defaults.baseline_cmd
    logger.info("Running %s"%cmd)
    data = access.remote_cmd(cmd,client)
    logger.debug("Baseline Ouptut:\n%s"%data)
    header = defaults.baseline_header
    checked = []
    for line in data.split("\r\n"):
        checklist = line.split("\n",2)[2]
        for checks in checklist.split("\n"):
            check = checks.split(":")
            checked.append([s.strip() for s in check])
    header.insert(0,"Discovery Instance")
    for row in checked:
        row.insert(0, args.target)
    output.define_csv(args,header,checked,dir+defaults.baseline_filename,args.output_file,args.target,"csv_file")

def cmdb_sync(client,args,user,passwd,dir):
    cmd = '%s -u %s -p %s'%(defaults.cmdbsync_cmd,user,passwd)
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("CMDB Sync:\n%s"%result)
    output.define_txt(args,result,dir+defaults.cmdbsync_filename,None)

def tw_events(client,args,user,passwd,instance_dir):
    cmd = '%s -u %s -p %s --list'%(defaults.tw_events_cmd,user,passwd)
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("tw_event_control:\n%s"%result)
    output.define_txt(args,result,dir+defaults.tw_events_filename,None)

def export_platforms(client,args,user,passwd,dir):
    cmd = defaults.tw_platforms_cmd
    logger.info("Running %s"%cmd)
    current = access.remote_cmd('%s -u %s -p %s -o /usr/tideway/data/customer/platforms.xml && cat /usr/tideway/data/customer/platforms.xml'%(cmd,user,passwd),client)
    default = access.remote_cmd('%s --default -u %s -p %s -o /usr/tideway/data/customer/platforms_default.xml && cat /usr/tideway/data/customer/platforms_default.xml'%(cmd,user,passwd),client)
    logger.debug("Platforms:\n%s"%current)
    output.define_txt(args,current,dir+defaults.current_platforms_filename,None)
    output.define_txt(args,default,dir+defaults.default_platforms_filename,None)

def knowledge(client,args,user,passwd,dir):
    cmd = defaults.tw_knowledge_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd("%s -u %s -p %s"%(cmd,user,passwd),client)
    logger.debug("Knowledge Ouptut:\n%s"%result)
    output.define_txt(args,result,dir+defaults.tw_knowledge_filename,None)

def licensing(client,args,user,passwd,dir):
    cmd = defaults.licensing_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd('%s -u %s -p %s'%(cmd,user,passwd),client)
    logger.debug("Licenses:\n%s"%result)
    if not result:
        result = run_query(client,user,passwd,queries.hc_license)
        output.define_csv(args,None,result,dir+defaults.tw_license_csv_filename,args.output_file,args.target,"csv")
    else:
        output.define_txt(args,result,dir+defaults.tw_license_raw_filename,None)

def tw_list_users(client,args,dir):
    cmd = defaults.tw_listusers_cmd
    logger.info("Running %s"%cmd)
    result = access.remote_cmd(cmd,client)
    logger.debug("tw_listusers:\n%s"%result)
    output.define_txt(args,result,dir+defaults.tw_listusers_filename,None)

def user_management(args, client):
    login = args.tw_user
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
    cmd = args.servicecctl
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

def sensitive(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_sensitive_data)
    output.save2csv(result, instance_dir+"/dq_sensitive_data.csv",args.target)

def tplexport(client,sysuser,syspass,instance_dir):
    output.tpl_export(None, queries.hc_tpl_export, instance_dir, "ssh", client, syspass)

def eca_errors(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_eca_error)
    output.save2csv(result, instance_dir+"/dq_eca_errors.csv",args.target)

def schedules(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_scan_ranges)
    output.save2csv(result, instance_dir+"/dq_scan_ranges.csv",args.target)

def excludes(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_exclude_ranges)
    output.save2csv(result, instance_dir+"/dq_exclude_ranges.csv",args.target)

def open_ports(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_open_ports)
    output.save2csv(result, instance_dir+"/dq_open_ports.csv",args.target)

def host_util(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_host_utilisation)
    output.save2csv(result, instance_dir+"/dq_host_utilisation.csv",args.target)

def orphan_vms(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_orphan_vms)
    output.save2csv(result, instance_dir+"/dq_orphan_vms.csv",args.target)

def missing_vms(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_missing_vms)
    output.save2csv(result, instance_dir+"/dq_missing_vms.csv",args.target)

def near_removal(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_near_removal)
    output.save2csv(result, instance_dir+"/dq_near_removal.csv",args.target)

def removed(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_removed)
    output.save2csv(result, instance_dir+"/hc_removed.csv",args.target)

def os_lifecycle(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_os_lifecycle)
    output.save2csv(result, instance_dir+"/dq_os_lifecycle.csv",args.target)

def software_lifecycle(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_software_lifecycle)
    output.save2csv(result, instance_dir+"/dq_software_lifecycle.csv",args.target)

def db_lifecycle(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_db_lifecycle)
    output.save2csv(result, instance_dir+"/dq_db_lifecycle.csv",args.target)

def unrecognised_snmp(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_snmp_devices)
    output.save2csv(result, instance_dir+"/dq_snmp_unrecognised.csv",args.target)

def installed_agents(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_agents)
    output.save2csv(result, instance_dir+"/dq_installed_agents.csv",args.target)

def software_usernames(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.hc_user_accounts)
    output.save2csv(result, instance_dir+"/dq_software_usernames.csv",args.target)

def module_summary(client,sysuser,syspass,args,instance_dir):
    result = run_query(client,sysuser,syspass,queries.pm_summary)
    output.save2csv(result, instance_dir+"/dq_pattern_modules.csv",args.target)