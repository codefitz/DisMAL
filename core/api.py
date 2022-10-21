# Discovery API commands for DisMAL

import sys
import logging
import csv

# PIP Modules
from pprint import pprint

# Local

from . import tools

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