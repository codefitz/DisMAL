# Discovery API commands for DisMAL

import sys
import logging
import csv
import json
import os
from urllib.parse import urlparse

# PIP Modules
from pprint import pprint
import pandas
import tideway

# Local
from . import tools, output, builder, queries, defaults, reporting, access
import socket

logger = logging.getLogger("_api_")

def init_endpoints(api_target, args):
    try:
        logger.debug("Requesting discovery endpoint from %s", args.target)
        disco = api_target.discovery()
        logger.debug("Discovery endpoint obtained: %s", disco)
    except:
        msg = "Error getting Discovery endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        logger.debug("Requesting data endpoint from %s", args.target)
        search = api_target.data()
        logger.debug("Data endpoint obtained: %s", search)
    except:
        msg = "Error getting Data endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        logger.debug("Requesting credentials endpoint from %s", args.target)
        creds = api_target.credentials()
        logger.debug("Credentials endpoint obtained: %s", creds)
    except:
        msg = "Error getting Credentials endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        logger.debug("Requesting vault endpoint from %s", args.target)
        vault = api_target.vault()
        logger.debug("Vault endpoint obtained: %s", vault)
    except:
        msg = "Error getting Vault endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        logger.debug("Requesting knowledge endpoint from %s", args.target)
        knowledge = api_target.knowledge()
        logger.debug("Knowledge endpoint obtained: %s", knowledge)
    except:
        msg = "Error getting Knowledge endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    return disco, search, creds, vault, knowledge

def get_json(api_endpoint):
    """Return JSON data from a request object.

    The ``tideway`` library lazily performs the HTTP request when an attribute
    such as ``status_code`` is accessed.  Because of this we must be prepared
    for network related exceptions to be raised here.  Any errors result in an
    empty dictionary being returned so callers can handle the failure
    gracefully.
    """

    # If the endpoint is callable (for example a property), call it first
    if callable(api_endpoint):
        try:
            api_endpoint = api_endpoint()
        except Exception as e:  # pragma: no cover - network errors
            if logger.isEnabledFor(logging.DEBUG):
                msg = (
                    "Not able to make api call.\nException: %s\n%s"
                    % (e.__class__, str(e))
                )
                print(msg)
                logger.error(msg)
            else:
                msg = (
                    "Not able to make api call. Rerun in debug mode for more "
                    "information."
                )
                print(msg)
                logger.error("Not able to make api call", exc_info=e)
            return {}

    if not hasattr(api_endpoint, "status_code"):
        if isinstance(api_endpoint, (list, dict)):
            return api_endpoint
        logger.error("Invalid API endpoint provided to get_json")
        return {}

    status_code = api_endpoint.status_code
    url = getattr(api_endpoint, "url", "unknown")

    if status_code == 200:
        msg = "Called API endpoint: %s\nStatus: %s - %s\n" % (
            url,
            status_code,
            api_endpoint.ok,
        )
        logger.info(msg)
    else:
        msg = "Failed to get API endpoint: %s\nReason: %s - %s\n" % (
            url,
            status_code,
            api_endpoint.reason,
        )
        if status_code == 404:
            logger.warning(msg)
        else:
            print(msg)
            logger.error(msg)

    if logger.isEnabledFor(logging.DEBUG):
        try:
            logger.debug("API response text from %s:\n%s", url, api_endpoint.text)
        except Exception:
            pass

    try:
        data = api_endpoint.json()
    except Exception as e:  # pragma: no cover - unexpected JSON issues
        msg = "Error decoding JSON from %s: %s" % (url, str(e))
        print(msg)
        logger.error(msg)
        return {}
    else:
        if logger.isEnabledFor(logging.DEBUG):
            try:
                logger.debug("Decoded JSON from %s:\n%s", url, json.dumps(data, indent=2))
            except Exception:
                pass
        return data

def admin(disco,args,dir):
    logger.debug("Calling disco.admin() with no parameters")
    data = disco.admin()
    logger.debug(
        "disco.admin() response ok=%s status=%s text=%s",
        getattr(data, "ok", "N/A"),
        getattr(data, "status_code", "N/A"),
        getattr(data, "text", "N/A"),
    )
    result = get_json(data)
    os_version = result['versions']['os_updates']
    logger.info('OS Version:\n%s'%os_version)
    logger.info('Discovery Version:\n%s'%os_version)
    output.define_txt(args,json.dumps(result['versions']),dir+defaults.api_filename,None)

def audit(search,args,dir):
    output.define_csv(args,search,queries.audit,dir+defaults.audit_filename,args.output_file,args.target,"query")

def baseline(disco, args, dir):
    logger.debug("Calling disco.baseline() with no parameters")
    data = disco.baseline()
    logger.debug(
        "disco.baseline() response ok=%s status=%s text=%s",
        getattr(data, "ok", "N/A"),
        getattr(data, "status_code", "N/A"),
        getattr(data, "text", "N/A"),
    )
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
    output.define_csv(args,search,queries.patterns,dir+defaults.tw_knowledge_filename,args.output_file,args.target,"query")

def licensing(disco, args, dir):
    try:
        # CSV
        logger.debug("Calling disco.licensing(content_type='csv')")
        r = disco.licensing(content_type="csv")
        logger.debug(
            "disco.licensing() response ok=%s status=%s text=%s",
            getattr(r, "ok", "N/A"),
            getattr(r, "status_code", "N/A"),
            getattr(r, "text", "N/A"),
        )
        handle = open("%s%s"%(dir,defaults.tw_license_zip_filename), "wb")
        for chunk in r.iter_content(chunk_size=512):
            if chunk:  # filter out keep-alive new chunks
                handle.write(chunk)
    except:
        # Plaintext
        logger.debug("Calling disco.licensing() with no parameters")
        r = disco.licensing()
        logger.debug(
            "disco.licensing() response ok=%s status=%s text=%s",
            getattr(r, "ok", "N/A"),
            getattr(r, "status_code", "N/A"),
            getattr(r, "text", "N/A"),
        )
        handle = open("%s%s"%(dir,defaults.tw_license_raw_filename), "wb")
        for chunk in r.iter_content(chunk_size=512):
            if chunk:  # filter out keep-alive new chunks
                handle.write(chunk)

def query(search, args):
    """Run an ad-hoc query against the search endpoint."""
    results = []
    try:
        if hasattr(search, "search_bulk"):
            results = search.search_bulk(args.a_query, limit=500)
        else:
            results = search.search(args.a_query, format="object", limit=500)
    except Exception as e:
        if logger.isEnabledFor(logging.DEBUG):
            msg = (
                "Not able to make api call.\nQuery: %s\nException: %s\n%s"
                % (args.a_query, e.__class__, str(e))
            )
            print(msg)
            logger.error(msg)
        else:
            msg = "Not able to make api call. Rerun in debug mode for more information."
            print(msg)
            logger.error(
                "Not able to make api call for query %s", args.a_query, exc_info=e
            )
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

def get_outposts(appliance):
    """Return list of Discovery Outposts from the appliance."""
    logger.debug("Calling appliance.get('/discovery/outposts?deleted=false')")
    resp = appliance.get("/discovery/outposts?deleted=false")
    logger.debug(
        "outposts response ok=%s status=%s text=%s",
        getattr(resp, "ok", "N/A"),
        getattr(resp, "status_code", "N/A"),
        getattr(resp, "text", "N/A"),
    )
    return get_json(resp)


def map_outpost_credentials(appliance):
    """Return mapping of credential UUIDs to outpost URLs."""
    mapping = {}
    outposts = get_outposts(appliance)
    if not isinstance(outposts, list):
        return mapping
    token = getattr(appliance, "token", None)
    api_version = getattr(appliance, "api_version", None)
    for outpost in outposts:
        url = outpost.get("url")
        if not url:
            continue
        parsed = urlparse(url)
        target = (parsed.netloc or parsed.path).rstrip("/")
        try:
            op_app = tideway.outpost(target, token, api_version=api_version)
            creds_ep = op_app.credentials()
            cred_list = get_json(creds_ep.get_vault_credentials)
            for cred in cred_list or []:
                uuid = cred.get("uuid")
                if not uuid:
                    continue
                get_json(creds_ep.get_vault_credential(uuid))
                mapping[uuid] = url
        except Exception as e:  # pragma: no cover - network errors
            logger.error("Error processing outpost %s: %s", url, e)
    return mapping

def success(twcreds, twsearch, args, dir):
    reporting.successful(twcreds, twsearch, args)
    #if args.output_file:
    #    df = pandas.read_csv(args.output_file)
    #    df.insert(0, "Discovery Instance", args.target)
    #    df.to_csv(dir+defaults.success_filename, index=False)
    #    os.remove(args.output_file)

def schedules(search, args, dir):
    output.define_csv(args,search,queries.scan_ranges,dir+defaults.scan_ranges_filename,args.output_file,args.target,"query")

def excludes(search, args, dir):
    output.define_csv(args,search,queries.exclude_ranges,dir+defaults.exclude_ranges_filename,args.output_file,args.target,"query")

def discovery_runs(disco, args, dir):
    logger.info("Checking Scan ranges...")
    logger.debug("Calling disco.get_discovery_runs")
    api_response = disco.get_discovery_runs
    logger.debug(
        "disco.get_discovery_runs response ok=%s status=%s text=%s",
        getattr(api_response, "ok", "N/A"),
        getattr(api_response, "status_code", "N/A"),
        getattr(api_response, "text", "N/A"),
    )
    r = get_json(api_response)
    if r:
        runs = json.loads(json.dumps(r))
        logger.debug('Runs:\n%s' % r)
        header, rows = tools.json2csv(runs)
        header.insert(0,"Discovery Instance")
        for row in rows:
            row.insert(0, args.target)
        output.define_csv(args,None,rows,dir+defaults.current_scans_filename,args.output_file,args.target,"csv_file")

def show_runs(disco, args):
    logger.debug("Calling disco.get_discovery_runs")
    api_response = disco.get_discovery_runs
    logger.debug(
        "disco.get_discovery_runs response ok=%s status=%s text=%s",
        getattr(api_response, "ok", "N/A"),
        getattr(api_response, "status_code", "N/A"),
        getattr(api_response, "text", "N/A"),
    )
    runs = get_json(api_response)
    if not runs:
        msg = "No runs in progress."
        print(msg)
        logger.error(msg)
        return
    parsed_runs = []
    headers = []
    for run in runs:
        disco_run = {}
        for key in run:
            disco_run.update({key: run[key]})
            headers.append(key)
        parsed_runs.append(disco_run)
    headers = tools.sortlist(headers)
    run_csvs = []
    for run in parsed_runs:
        run_csv = []
        for header in headers:
            value = run.get(header)
            run_csv.append(value)
        run_csvs.append(run_csv)

    export = getattr(args, "export", False)
    outfile = getattr(args, "file", getattr(args, "output_file", None))
    if export:
        w = csv.writer(sys.stdout)
        w.writerow(headers)
        w.writerows(run_csvs)
    elif outfile:
        with open(outfile, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(run_csvs)
            msg = "Results written to %s" % outfile
            print(msg)
            logger.info(msg)
    else:
        if getattr(args, "excavate", None):
            out_dir = getattr(args, "reporting_dir", "")
            output.define_csv(
                args,
                headers,
                run_csvs,
                os.path.join(out_dir, defaults.current_scans_filename),
                getattr(args, "output_file", None),
                getattr(args, "target", None),
                "csv_file",
            )
        elif getattr(args, "debugging", False):
            pprint(runs)
        else:
            print(f"Active discovery runs: {len(runs)}")
            for r in runs:
                rid = r.get("run_id") or r.get("id") or r.get("label") or "N/A"
                status = r.get("status", "unknown")
                print(f" - {rid}: {status}")

def sensitive(search, args, dir):
    output.define_csv(args,search,queries.sensitive_data,dir+defaults.sensitive_data_filename,args.output_file,args.target,"query")

def tpl_export(search, args, dir):
    reporting.tpl_export(search, queries.tpl_export, dir, "api", None, None, None)

def eca_errors(search, args, dir):
    output.define_csv(args,search,queries.eca_error,dir+defaults.eca_errors_filename,args.output_file,args.target,"query")

def open_ports(search, args, dir):
    output.define_csv(args,search,queries.open_ports,dir+defaults.open_ports_filename,args.output_file,args.target,"query")

def host_util(search, args, dir):
    output.define_csv(args,search,queries.host_utilisation,dir+defaults.host_util_filename,args.output_file,args.target,"query")

def orphan_vms(search, args, dir):
    output.define_csv(args,search,queries.orphan_vms,dir+defaults.orphan_vms_filename,args.output_file,args.target,"query")

def missing_vms(search, args, dir):
    if getattr(args, "resolve_hostnames", False):
        response = search_results(search, queries.missing_vms)
        if isinstance(response, list) and len(response) > 0:
            header, data = tools.json2csv(response)
            header.insert(0, "Discovery Instance")
            for row in data:
                row.insert(0, args.target)

            gf_index = header.index("Guest_Full_Name") if "Guest_Full_Name" in header else None
            header.append("Pingable")

            devices = devices_lookup(search)
            header.extend(["last_identity", "last_scanned", "last_result"])

            timer_count = 0
            for row in data:
                timer_count = tools.completage(
                    "Resolving hostnames...",
                    len(data),
                    timer_count,
                )
                ip = "N/A"
                if gf_index is not None:
                    host = row[gf_index]
                    if host and host != "N/A" and access.ping(host) == 0:
                        try:
                            ip = socket.gethostbyname(host)
                        except Exception:
                            ip = "N/A"
                row.append(ip)
                info = devices.get(ip)
                if info:
                    row.extend([
                        info.get("last_identity", "N/A"),
                        info.get("last_start_time", "N/A"),
                        info.get("last_result", "N/A"),
                    ])
                else:
                    row.extend(["N/A", "N/A", "N/A"])
            print(os.linesep, end="\r")

            output.define_csv(
                args,
                header,
                data,
                dir + defaults.missing_vms_filename,
                args.output_file,
                args.target,
                "csv_file",
            )
        else:
            output.define_csv(
                args,
                search,
                queries.missing_vms,
                dir + defaults.missing_vms_filename,
                args.output_file,
                args.target,
                "query",
            )
    else:
        output.define_csv(
            args,
            search,
            queries.missing_vms,
            dir + defaults.missing_vms_filename,
            args.output_file,
            args.target,
            "query",
        )

def near_removal(search, args, dir):
    output.define_csv(args,search,queries.near_removal,dir+defaults.near_removal_filename,args.output_file,args.target,"query")

def removed(search, args, dir):
    output.define_csv(args,search,queries.removed,dir+defaults.removed_filename,args.output_file,args.target,"query")

def oslc(search, args, dir):
    output.define_csv(args,search,queries.os_lifecycle,dir+defaults.os_lifecycle_filename,args.output_file,args.target,"query")

def slc(search, args, dir):
    output.define_csv(args,search,queries.software_lifecycle,dir+defaults.si_lifecycle_filename,args.output_file,args.target,"query")

def dblc(search, args, dir):
    output.define_csv(args,search,queries.db_lifecycle,dir+defaults.db_lifecycle_filename,args.output_file,args.target,"query")

def snmp(search, args, dir):
    output.define_csv(args,search,queries.snmp_devices,dir+defaults.snmp_unrecognised_filename,args.output_file,args.target,"query")

def agents(search, args, dir):
    output.define_csv(args,search,queries.agents,dir+defaults.installed_agents_filename,args.output_file,args.target,"query")

def software_users(search, args, dir):
    output.define_csv(args,search,queries.user_accounts,dir+defaults.si_user_accounts_filename,args.output_file,args.target,"query")

def devices_lookup(search):
    """Return a mapping of IPs to their last discovery information."""
    results = search_results(search, queries.deviceInfo)
    mapping = {}
    for result in results:
        ip = tools.getr(result, "DA_Endpoint", None)
        if ip:
            mapping[ip] = {
                "last_identity": tools.getr(result, "Device_Hostname", "N/A"),
                "last_start_time": tools.getr(result, "DA_Start", "N/A"),
                "last_result": tools.getr(result, "DA_Result", "N/A"),
            }
    return mapping

def tku(knowledge, args, dir):
    logger.info("Checking Knowledge...")
    logger.debug("Calling knowledge.get_knowledge")
    api_response = knowledge.get_knowledge
    logger.debug(
        "knowledge.get_knowledge response ok=%s status=%s text=%s",
        getattr(api_response, "ok", "N/A"),
        getattr(api_response, "status_code", "N/A"),
        getattr(api_response, "text", "N/A"),
    )
    k = get_json(api_response)
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
    logger.debug(
        "Calling disco.patch_discovery_run(%s, {cancelled: True})", run_id
    )
    cancel = disco.patch_discovery_run(run_id, {"cancelled": True})
    logger.debug(
        "disco.patch_discovery_run response ok=%s status=%s text=%s",
        getattr(cancel, "ok", "N/A"),
        getattr(cancel, "status_code", "N/A"),
        getattr(cancel, "text", "N/A"),
    )
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

def update_schedule_timezone(disco, args):
    """Adjust discovery run start times for the given timezone."""
    tz = args.schedule_timezone
    reset = getattr(args, "reset_schedule_timezone", False)

    if not tz:
        logger.error("No timezone provided for schedule update")
        return

    from datetime import datetime
    from zoneinfo import ZoneInfo

    # Allow a few common short names
    common = {
        "UTC": 0,
        "CST": -6,
        "CDT": -5,
        "EST": -5,
        "EDT": -4,
        "PST": -8,
        "PDT": -7,
        "MST": -7,
        "MDT": -6,
    }

    try:
        if tz.upper() in common:
            offset = common[tz.upper()]
        else:
            offset = int(
                (datetime.now(ZoneInfo(tz)).utcoffset() or datetime.timedelta())
                .total_seconds()
                // 3600
            )
    except Exception as e:
        msg = f"Invalid timezone {tz}: {e}"
        print(msg)
        logger.error(msg)
        return

    if reset:
        offset = -offset

    logger.debug("Calling disco.get_discovery_runs")
    api_response = disco.get_discovery_runs
    logger.debug(
        "disco.get_discovery_runs response ok=%s status=%s text=%s",
        getattr(api_response, "ok", "N/A"),
        getattr(api_response, "status_code", "N/A"),
        getattr(api_response, "text", "N/A"),
    )

    runs = get_json(api_response)
    if not runs:
        logger.error("No discovery runs returned")
        return

    for run in runs:
        run_id = run.get("range_id") or run.get("id") or run.get("run_id")
        schedule = run.get("schedule", {})
        start_times = schedule.get("start_times", [])
        if not run_id or not isinstance(start_times, list):
            continue
        new_times = [int((t + offset) % 24) for t in start_times]
        patch = {"schedule": {"start_times": new_times}}
        logger.debug("Calling disco.patch_discovery_run(%s, %s)", run_id, patch)
        resp = disco.patch_discovery_run(run_id, patch)
        logger.debug(
            "disco.patch_discovery_run response ok=%s status=%s text=%s",
            getattr(resp, "ok", "N/A"),
            getattr(resp, "status_code", "N/A"),
            getattr(resp, "text", "N/A"),
        )

def vault(vault, args, dir):
    logger.info("Checking Vault...")
    logger.debug("Calling vault.get_vault")
    api_response = vault.get_vault
    logger.debug(
        "vault.get_vault response ok=%s status=%s text=%s",
        getattr(api_response, "ok", "N/A"),
        getattr(api_response, "status_code", "N/A"),
        getattr(api_response, "text", "N/A"),
    )
    v = get_json(api_response)
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
    logger.debug("Calling appliance.delete_vault_credential(%s)", cred)
    delete = appliance.delete_vault_credential(cred)
    logger.debug(
        "delete_vault_credential response ok=%s status=%s text=%s",
        getattr(delete, "ok", "N/A"),
        getattr(delete, "status_code", "N/A"),
        getattr(delete, "text", "N/A"),
    )
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
    logger.debug("Calling appliance.get_vault_credential(%s)", uuid)
    lookup = appliance.get_vault_credential(uuid)
    logger.debug(
        "get_vault_credential response ok=%s status=%s text=%s",
        getattr(lookup, "ok", "N/A"),
        getattr(lookup, "status_code", "N/A"),
        getattr(lookup, "text", "N/A"),
    )
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
            logger.debug(
                "Calling appliance.patch_vault_credential(%s, {enabled: False})",
                uuid,
            )
            resp = appliance.patch_vault_credential(uuid,{"enabled":False})
            logger.debug(
                "patch_vault_credential response ok=%s status=%s text=%s",
                getattr(resp, "ok", "N/A"),
                getattr(resp, "status_code", "N/A"),
                getattr(resp, "text", "N/A"),
            )
            active = False
        else:
            logger.debug(
                "Calling appliance.patch_vault_credential(%s, {enabled: True})",
                uuid,
            )
            resp = appliance.patch_vault_credential(uuid,{"enabled":True})
            logger.debug(
                "patch_vault_credential response ok=%s status=%s text=%s",
                getattr(resp, "ok", "N/A"),
                getattr(resp, "status_code", "N/A"),
                getattr(resp, "text", "N/A"),
            )
            active = True
    return active

def search_results(api_endpoint, query):
    try:
        if isinstance(query, dict) and isinstance(query.get("query"), str):
            query = dict(query)
            query["query"] = query["query"].replace("\n", " ").replace("\r", " ")
        if logger.isEnabledFor(logging.DEBUG):
            try:
                logger.debug("Search query: %s" % query)
            except Exception:
                pass

        if hasattr(api_endpoint, "search_bulk"):
            results = api_endpoint.search_bulk(query, format="object", limit=500)
        else:
            results = api_endpoint.search(query, format="object", limit=500)
        # Depending on the version of the `tideway` library the call above may
        # return either a `requests.Response` object or the decoded JSON
        # directly.  Normalise the output so callers always get Python data
        # structures.
        if hasattr(results, "json"):
            if logger.isEnabledFor(logging.DEBUG):
                try:
                    logger.debug("Raw search response: %s" % results.text)
                except Exception:
                    pass
            status_code = getattr(results, "status_code", 200)
            if status_code >= 400:
                logger.error(
                    "Search API returned %s - %s",
                    status_code,
                    getattr(results, "reason", ""),
                )
                try:
                    data = json.loads(results.text)
                except Exception:
                    data = {"error": getattr(results, "text", "")}
                if logger.isEnabledFor(logging.DEBUG):
                    try:
                        logger.debug("Parsed error payload: %s", json.dumps(data))
                    except Exception:
                        pass
                logger.error("Search failed: %s - %s", status_code, getattr(results, "reason", ""))
                return data
            try:
                data = results.json()
            except Exception as e:
                msg = "Error decoding JSON from search results: %s" % str(e)
                print(msg)
                logger.error(msg)
                return []
            else:
                if logger.isEnabledFor(logging.DEBUG):
                    try:
                        logger.debug("Parsed results length: %s" % len(data))
                    except Exception:
                        pass
                return tools.list_table_to_json(data)
        else:
            if logger.isEnabledFor(logging.DEBUG):
                try:
                    logger.debug("Parsed results length: %s" % len(results))
                except Exception:
                    pass
            return tools.list_table_to_json(results)
    except Exception as e:
        if logger.isEnabledFor(logging.DEBUG):
            msg = (
                "Not able to make api call.\nQuery: %s\nException: %s\n%s"
                % (query, e.__class__, str(e))
            )
            print(msg)
            logger.error(msg)
        else:
            msg = "Not able to make api call. Rerun in debug mode for more information."
            print(msg)
            logger.error(
                "Not able to make api call for query %s", query, exc_info=e
            )
        return []

def hostname(args,dir):
    output.define_txt(args,args.target,dir+defaults.hostname_filename,None)
