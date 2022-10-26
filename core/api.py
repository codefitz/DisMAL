# Discovery API commands for DisMAL

import sys
import logging
import csv
import json
import os

# PIP Modules
from pprint import pprint
import pandas

# Local
from . import tools, output, builder, queries

logger = logging.getLogger("_api_")

def get_json(api_endpoint):
    status_code = api_endpoint.status_code
    api_json = {}
    if status_code == 200:
        msg = "Called API endpoint: %s\nStatus: %s - %s\n" % (api_endpoint.url,status_code,api_endpoint.ok)
        logger.info(msg)
        api_json = api_endpoint.json()
    elif status_code == 404:
        msg = "Failed to get API endpoint: %s\nReason: %s - %s\n" % (api_endpoint.url,status_code,api_endpoint.reason)
        logger.warning(msg)
        api_json = api_endpoint.json()
    else:
        msg = "Failed to get API endpoint: %s\nReason: %s - %s\n" % (api_endpoint.url,status_code,api_endpoint.reason)
        print(msg)
        logger.error(msg)
        return False
    return api_json

def query(disco, args):
    results = []
    try:
        results = disco.search_bulk(args.a_query,limit=500)
    except Exception as e:
        msg = "Not able to make api call.\nQuery: %s\nException: %s" %(args.a_query,e.__class__)
        print(msg)
        logger.error(msg)
    if len(results) > 0:
        if args.csv_export:
            w = csv.writer(sys.stdout)
            w.writerows(results)
        elif args.f_name:
            with open(args.f_name, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerows(results)
                msg = "Results written to %s" % args.f_name
                print(msg)
                logger.info(msg)
        else:
            pprint(results)
    else:
        msg = "No results found!\n"
        print(msg)
        logger.warning(msg)

def admin(data,instance_dir):
    result = get_json(data)
    os_version = result['versions']['os_updates']
    logger.info('OS Version:\n%s'%os_version)
    disco_version = result['versions']['product']
    logger.info('Discovery Version:\n%s'%os_version)
    output.txt_dump(json.dumps(result['versions']),instance_dir+"/versions.txt")

def baseline(data, args, instance_dir):
    logger.info("Checking Baseline...")
    bl = get_json(data)
    if bl:
        baseline = json.loads(json.dumps(bl))
        logger.debug('Baseline Status:\n%s'%bl)
        # Last Message
        try:
            if 'summary' in baseline:
                # Helix does not share the baseline
                last_message = baseline['summary']['last_message']
                # Failures
                header = []
                data = []
                if "FAILED" in baseline['results']:
                    failures = baseline['results']['FAILED']
                    header, data = tools.json2csv(failures)
                header.insert(0,"Discovery Instance")
                for row in data:
                    row.insert(0, args.target)
                output.csv_file(data, header, instance_dir+"/baseline.csv")
        except Exception as e:
            logger.error("Problem with baseline:\n%s\n%s"%(e.__class__,str(e)))
            # Try dumping it
            output.txt_dump(bl,instance_dir+"/baseline_status.txt")
    else:
        last_message = bl
        output.txt_dump(last_message,instance_dir+"/baseline_status.txt")

def hostname(appliance,instance_dir):
    output.txt_dump(appliance,instance_dir+"/hostname.txt")

def tku(twknowledge,instance_dir):
    logger.info("Checking Knowledge...")
    k = get_json(twknowledge.get_knowledge)
    if k:
        knowledge = json.loads(json.dumps(k))
        logger.debug('Knowledge:\n%s'%k)
        if 'latest_edp' in knowledge:
            latest_edp = knowledge['latest_edp']['name']
        else:
            latest_edp = "Not installed"
        if 'latest_storage' in knowledge:
            latest_storage = knowledge['latest_storage']['name']
        else:
            latest_storage = "Not installed"
        latest_tku = knowledge['latest_tku']['name']
        tkus = (latest_tku, latest_edp, latest_storage)
        tku_level = "\n".join(map(str, tkus))
        output.txt_dump(tku_level,instance_dir+"/knowledge.txt")

def discovery_runs(twdisco, args, instance_dir):
# Current Scans
    logger.info("Checking Scan ranges...")
    r = get_json(twdisco.get_discovery_runs)
    if r:
        runs = json.loads(json.dumps(r))
        logger.debug('Runs:\s%s'%r)
        header, data = tools.json2csv(runs)
        header.insert(0,"Discovery Instance")
        for row in data:
            row.insert(0, args.target)
        output.csv_file(data, header, instance_dir+"/current_scans.csv")

def cancel_run(disco, args):
    run_id = args.a_kill_run
    cancel = disco.patch_discovery_run(run_id, {"cancelled": True})
    if cancel.ok:
        msg = "Cancelled Run %s.\n" % run_id
        print(msg)
        logger.info(msg)
        return cancel.ok
    elif 'message' in cancel.json():
        msg = cancel.json()['message'] + "\n"
        print(msg)
        logger.warning("Run not cancelled\n%s" % msg)
        return False
    else:
        msg = cancel.text + "\n"
        print(msg)
        logger.warning("Run not cancelled\n%s" % msg)
        return False

def vault(twvault, args, instance_dir):
    logger.info("Checking Vault...")
    v = get_json(twvault.get_vault)
    if v:
        vault = json.loads(json.dumps(v))
        logger.debug('Vault Status:\n%s'%v)
        vopen = vault.get('open')
        vsaved = vault.get('passphrase_saved')
        vset = vault.get('passphrase_set')
        vault_status = "OK"
        if not vopen:
            if not vsaved:
                vault_status = "Vault closed - Passphrase not saved"
        if not vset:
            vault_status = "Vault open - no passphrase set"
        output.txt_dump(vault_status,instance_dir+"/vault.txt")

    # Credential Success
def success(twcreds,twsearch,args,instance_dir):
    builder.successful(twcreds, twsearch, False, args)
    df = pandas.read_csv(args.file)
    df.insert(0, "Discovery Instance", args.target)
    df.to_csv(instance_dir+"/credentials.csv", index=False)
    os.remove(args.file)

def remove_cred(appliance, cred):
    delete = appliance.delete_vault_credential(cred)
    if delete.ok:
        msg = "Credential UUID %s deleted.\n" % cred
        print(msg)
        logger.info(msg)
        return delete.ok
    elif 'message' in delete.json():
        msg = delete.json()['message'] + "\n"
        print(msg)
        logger.warning("Credential not deleted\n%s" % msg)
        return False
    else:
        msg = delete.text + "\n"
        print(msg)
        logger.warning("Credential not deleted\n%s" % msg)
        return False

def update_cred(appliance, uuid):
    lookup = appliance.get_vault_credential(uuid)
    lookupjson = get_json(lookup)
    if 'message' in lookupjson:
        enabled = None
        msg = lookupjson.get('message')
        print(msg)
        logger.warning("Credential not updated\n%s" % msg)
    else:
        enabled = lookupjson.get('enabled')
    active = None
    if enabled is not None:
        if enabled:
            appliance.patch_vault_credential(uuid,{"enabled":False})
            active = False
        else:
            appliance.patch_vault_credential(uuid,{"enabled":True})
            active = True
    return active

def search_results(api_endpoint,query):
    try:
        return api_endpoint.search_bulk(query, format="object",limit=500)
    except Exception as e:
        msg = "Not able to make api call.\nQuery: %s\nException: %s\n%s" %(query,e.__class__,str(e))
        print(msg)
        logger.error(msg)
        return []

def show_runs(disco, args):
    results = []
    try:
        results = disco.get_discovery_runs
    except Exception as e:
        msg = "Not able to make api call.\nException: %s" %(e.__class__)
        print(msg)
        logger.error(msg)
    if len(results.json()) > 0:
        runs = []
        headers =[]
        for run in results.json():
            disco_run = {}
            for key in run:
                disco_run.update({key:run[key]})
                headers.append(key)
            runs.append(disco_run)
        headers = tools.sortlist(headers)
        run_csvs = []
        for run in runs:
            run_csv = []
            for header in headers:
                value = run.get(header)
                run_csv.append(value)
            run_csvs.append(run_csv)
        run_csvs.insert(0, headers)
        if args.export:
            w = csv.writer(sys.stdout)
            w.writerows(run_csvs)
        elif args.file:
            with open(args.file, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerows(run_csvs)
                msg = "Results written to %s" % args.file
                print(msg)
                logger.info(msg)
        else:
            pprint(results.json())
    else:
        msg = "No runs in progress."
        print(msg)
        logger.error(msg)

# Sensitive Data Report
def sensitive(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_sensitive_data, instance_dir+"/dq_sensitive_data.csv",discovery)

# TPL Export
def tpl_export(twsearch, instance_dir):
    output.tpl_export(twsearch, queries.hc_tpl_export, instance_dir, "api", None, None)

# ECA Errors
def eca_errors(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_eca_error, instance_dir+"/dq_eca_errors.csv",discovery)

# Scan Ranges
def schedules(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_scan_ranges, instance_dir+"/dq_scan_ranges.csv",discovery)

# Exclude Ranges
def excludes(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_exclude_ranges, instance_dir+"/dq_exclude_ranges.csv",discovery)

# Open Service Ports
def open_ports(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_open_ports, instance_dir+"/dq_open_ports.csv",discovery)

# Host Utilisation
def host_util(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_host_utilisation, instance_dir+"/dq_host_utilisation.csv",discovery)
    
# Orphan VMs
def orphan_vms(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_orphan_vms, instance_dir+"/dq_orphan_vms.csv",discovery)

# Missing VM Children
def missing_vms(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_missing_vms, instance_dir+"/dq_missing_vms.csv",discovery)
    
# Audit Report
def audit(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_audit, instance_dir+"/dq_audit.csv",discovery)

# Devices Near Removal
def near_removal(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_near_removal, instance_dir+"/dq_near_removal.csv",discovery)

# Last 7 Days Removed
def removed(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_removed, instance_dir+"/dq_removed.csv",discovery)

# OS Lifecycle
def oslc(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_os_lifecycle, instance_dir+"/dq_os_lifecycle.csv",discovery)

# Software Lifecycle
def slc(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_software_lifecycle, instance_dir+"/dq_software_lifecycle.csv",discovery)

# DB Lifecycle
def dblc(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_db_lifecycle, instance_dir+"/dq_db_lifecycle.csv",discovery)

# Unrecognised SNMP Devices
def snmp(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_snmp_devices, instance_dir+"/dq_snmp_unrecognised.csv",discovery)

# Installed Agents
def agents(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_agents, instance_dir+"/dq_installed_agents.csv",discovery)

# Software and User Accounts
def software_users(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.hc_user_accounts, instance_dir+"/dq_software_usernames.csv",discovery)

# CMDB Sync config
def cmdb_config(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.cmdb_sync_config, instance_dir+"/dq_cmdb_sync_config.csv",discovery)

# Pattern Module Summary
def modules(twsearch, instance_dir, discovery):
    output.query2csv(twsearch, queries.pm_summary, instance_dir+"/dq_pattern_modules.csv",discovery)

# License Report
def licensing_csv(twdisco, instance_dir):
    # CSV
    r = twdisco.licensing(content_type="csv")
    handle = open("%s/license_export.zip"%instance_dir, "wb")
    for chunk in r.iter_content(chunk_size=512):
        if chunk:  # filter out keep-alive new chunks
            handle.write(chunk)

def licensing(twdisco, instance_dir):
    # Plaintext
    r = twdisco.licensing()
    handle = open("%s/license_report.txt"%instance_dir, "wb")
    for chunk in r.iter_content(chunk_size=512):
        if chunk:  # filter out keep-alive new chunks
            handle.write(chunk)