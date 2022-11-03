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
from . import tools, output, builder, queries, defaults, reporting

logger = logging.getLogger("_api_")

def init_endpoints(api_target, args):
    try:
        disco = api_target.discovery()
    except:
        msg = "Error getting Discovery endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        search = api_target.data()
    except:
        msg = "Error getting Data endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        creds = api_target.credentials()
    except:
        msg = "Error getting Credentials endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        vault = api_target.vault()
    except:
        msg = "Error getting Vault endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        knowledge = api_target.knowledge()
    except:
        msg = "Error getting Knowledge endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    return disco, search, creds, vault, knowledge

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

def admin(disco,args,dir):
    data = disco.admin()
    result = get_json(data)
    os_version = result['versions']['os_updates']
    logger.info('OS Version:\n%s'%os_version)
    logger.info('Discovery Version:\n%s'%os_version)
    output.define_txt(args,json.dumps(result['versions']),dir+defaults.api_filename,None)

def audit(search,args,dir):
    output.define_csv(args,search,queries.hc_audit,dir+defaults.audit_filename,args.output_file,args.target,"query")

def baseline(disco, args, dir):
    data = disco.baseline()
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
                rows = []
                if "FAILED" in baseline['results']:
                    failures = baseline['results']['FAILED']
                    header, rows = tools.json2csv(failures)
                header.insert(0,"Discovery Instance")
                for row in rows:
                    row.insert(0, args.target)
                output.define_csv(args,header,rows,dir+defaults.baseline_filename,args.output_file,args.target,"csv_file")
        except Exception as e:
            logger.error("Problem with baseline:\n%s\n%s"%(e.__class__,str(e)))
            # Try dumping it
            output.txt_dump(bl,dir+"/baseline_status.txt")
    else:
        last_message = bl
        output.txt_dump(last_message,dir+"/baseline_status.txt")

def cmdb_config(search, args, dir):
    output.define_csv(args,search,queries.cmdb_sync_config,dir+defaults.cmdbsync_filename,args.output_file,args.target,"query")

def modules(search, args, dir):
    output.define_csv(args,search,queries.pm_summary,dir+defaults.tw_knowledge_filename,args.output_file,args.target,"query")

def licensing(disco, args, dir):
    try:
        # CSV
        r = disco.licensing(content_type="csv")
        handle = open("%s%s"%(dir,defaults.tw_license_zip_filename), "wb")
        for chunk in r.iter_content(chunk_size=512):
            if chunk:  # filter out keep-alive new chunks
                handle.write(chunk)
    except:
        # Plaintext
        r = disco.licensing()
        handle = open("%s%s"%(dir,defaults.tw_license_raw_filename), "wb")
        for chunk in r.iter_content(chunk_size=512):
            if chunk:  # filter out keep-alive new chunks
                handle.write(chunk)

def query(disco, args):
    results = []
    try:
        results = disco.search_bulk(args.a_query,limit=500)
    except Exception as e:
        msg = "Not able to make api call.\nQuery: %s\nException: %s" %(args.a_query,e.__class__)
        print(msg)
        logger.error(msg)
    if len(results) > 0:
        if args.output_csv:
            w = csv.writer(sys.stdout)
            w.writerows(results)
        elif args.output_file:
            with open(args.output_file, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerows(results)
                msg = "Results written to %s" % args.output_file
                print(msg)
                logger.info(msg)
        else:
            pprint(results)
    else:
        msg = "No results found!\n"
        print(msg)
        logger.warning(msg)

def success(twcreds,twsearch,args,instance_dir):
    reporting.successful(twcreds, twsearch, args)
    df = pandas.read_csv(args.file)
    df.insert(0, "Discovery Instance", args.target)
    df.to_csv(instance_dir+"/credentials.csv", index=False)
    os.remove(args.file)

def schedules(search, args, dir):
    output.define_csv(args,search,queries.hc_scan_ranges,dir+defaults.scan_ranges_filename,args.output_file,args.target,"query")

def excludes(search, args, dir):
    output.define_csv(args,search,queries.hc_exclude_ranges,dir+defaults.exclude_ranges_filename,args.output_file,args.target,"query")

def discovery_runs(disco, args, dir):
    logger.info("Checking Scan ranges...")
    r = get_json(disco.get_discovery_runs)
    if r:
        runs = json.loads(json.dumps(r))
        logger.debug('Runs:\s%s'%r)
        header, rows = tools.json2csv(runs)
        header.insert(0,"Discovery Instance")
        for row in rows:
            row.insert(0, args.target)
        output.define_csv(args,None,rows,dir+defaults.current_scans_filename,args.output_file,args.target,"csv_file")

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

def sensitive(search, args, dir):
    output.define_csv(args,search,queries.hc_sensitive_data,dir+defaults.sensitive_data_filename,args.output_file,args.target,"query")

def tpl_export(search, args, dir):
    reporting.tpl_export(search, queries.hc_tpl_export, dir, "api", None, None)

def eca_errors(search, args, dir):
    output.define_csv(args,search,queries.hc_eca_error,dir+defaults.eca_errors_filename,args.output_file,args.target,"query")

def open_ports(search, args, dir):
    output.define_csv(args,search,queries.hc_open_ports,dir+defaults.open_ports_filename,args.output_file,args.target,"query")

def host_util(search, args, dir):
    output.define_csv(args,search,queries.hc_host_utilisation,dir+defaults.host_util_filename,args.output_file,args.target,"query")

def orphan_vms(search, args, dir):
    output.define_csv(args,search,queries.hc_orphan_vms,dir+defaults.orphan_vms_filename,args.output_file,args.target,"query")

def missing_vms(search, args, dir):
    output.define_csv(args,search,queries.hc_missing_vms,dir+defaults.mssing_vms_filename,args.output_file,args.target,"query")

def near_removal(search, args, dir):
    output.define_csv(args,search,queries.hc_near_removal,dir+defaults.near_removal_filename,args.output_file,args.target,"query")

def removed(search, args, dir):
    output.define_csv(args,search,queries.hc_removed,dir+defaults.removed_filename,args.output_file,args.target,"query")

def oslc(search, args, dir):
    output.define_csv(args,search,queries.hc_os_lifecycle,dir+defaults.os_lifecycle_filename,args.output_file,args.target,"query")

def slc(search, args, dir):
    output.define_csv(args,search,queries.hc_software_lifecycle,dir+defaults.si_lifecycle_filename,args.output_file,args.target,"query")

def dblc(search, args, dir):
    output.define_csv(args,search,queries.hc_db_lifecycle,dir+defaults.db_lifecycle_filename,args.output_file,args.target,"query")

def snmp(search, args, dir):
    output.define_csv(args,search,queries.hc_snmp_devices,dir+defaults.snmp_unrecognised_filename,args.output_file,args.target,"query")

def agents(search, args, dir):
    output.define_csv(args,search,queries.hc_agents,dir+defaults.installed_agents_filename,args.output_file,args.target,"query")

def software_users(search, args, dir):
    output.define_csv(args,search,queries.hc_user_accounts,dir+defaults.si_user_accounts_filename,args.output_file,args.target,"query")

def tku(knowledge, args, dir):
    logger.info("Checking Knowledge...")
    k = get_json(knowledge.get_knowledge)
    if k:
        result = json.loads(json.dumps(k))
        logger.debug('Knowledge:\n%s'%k)
        if 'latest_edp' in result:
            latest_edp = result['latest_edp']['name']
        else:
            latest_edp = "Not installed"
        if 'latest_storage' in result:
            latest_storage = result['latest_storage']['name']
        else:
            latest_storage = "Not installed"
        latest_tku = result['latest_tku']['name']
        tkus = (latest_tku, latest_edp, latest_storage)
        tku_level = "\n".join(map(str, tkus))
        output.define_txt(args,tku_level,dir+defaults.pattern_modules_filename,None)

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

def vault(vault, args, dir):
    logger.info("Checking Vault...")
    v = get_json(vault.get_vault)
    if v:
        result = json.loads(json.dumps(v))
        logger.debug('Vault Status:\n%s'%v)
        vopen = result.get('open')
        vsaved = result.get('passphrase_saved')
        vset = result.get('passphrase_set')
        vault_status = "OK"
        if not vopen:
            if not vsaved:
                vault_status = "Vault closed - Passphrase not saved"
        if not vset:
            vault_status = "Vault open - no passphrase set"
        output.define_txt(args,vault_status,dir+defaults.vault_filename,None)

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

def hostname(args,dir):
    output.define_txt(args,args.target,dir+defaults.hostname_filename,None)