# DisMAL Reporting Functions

import datetime
import logging
from platform import uname
import os
from collections import Counter
import json
import re

# PIP Packages
import pandas as pd

# Local
from . import api, queries, tools, builder, output, access, cli

logger = logging.getLogger("_reporting_")

def successful(creds, search, args):
    msg = "Running: Success Report )"
    logger.info(msg)

    vaultcreds = api.get_json(creds.get_vault_credentials)
    logger.debug('List Credentials:'+json.dumps(vaultcreds))

    credsux_results = {}
    devinfosux = {}
    credfail_results = {}

    credsux_results = api.search_results(search,queries.credential_success)
    devinfosux = api.search_results(search,queries.deviceinfo_success)
    credfail_results = api.search_results(search,queries.credential_failure)

    data = []
    headers = []

    logger.info('Successful SessionResults:' + json.dumps(credsux_results))
    logger.info('Successful DeviceInfos:' + json.dumps(devinfosux))
    logger.info('Failures:' + json.dumps(credfail_results))

    suxCreds = tools.session_get(credsux_results)
    suxDev = tools.session_get(devinfosux)
    failCreds = tools.session_get(credfail_results)

    # Include Scan Ranges and Excludes
    scan_resp = search.search(queries.scanrange,format="object",limit=500)
    scan_ranges = api.get_json(scan_resp)
    excludes_resp = search.search(queries.excludes,format="object",limit=500)
    excludes = api.get_json(excludes_resp)
    if not scan_ranges or not isinstance(scan_ranges, list):
        logger.error("Failed to retrieve scan ranges")
        return
    if not excludes or not isinstance(excludes, list):
        logger.error("Failed to retrieve excludes")
        return
    if len(scan_ranges) == 0 or len(excludes) == 0:
        logger.error("No scan or exclude data returned")
        return

    timer_count = 0
    for cred in vaultcreds:
        timer_count = tools.completage("Gathering Credentials", len(vaultcreds), timer_count)

        msg = "Analysing Credential:%s\n"%cred.get('uuid')
        logger.debug(msg)

        detail = builder.get_credentials(cred)

        uuid = detail.get('uuid')
        index = tools.getr(detail,'index',0)
        
        ip_range = tools.getr(detail,'iprange',None)
        list_of_ranges = tools.range_to_ips(ip_range)
        ip_exclude = tools.getr(detail,'exclusions',None)
        enabled = tools.getr(detail,'enabled')
        if enabled:
            status = "Enabled"
        else:
            status = "Disabled"

        active = False
        success = 0
        fails = 0
        session = None
        percent = None
        failure = [ None, 0 ]
        sessions = [ None, 0 ]
        devinfos = [ None, 0 ]
        try:
            sessions = suxCreds[uuid]
            active = True
            msg = "Sessions found, Active: %s" % sessions
            logger.debug(msg)
        except KeyError:
            pass
        try:
            devinfos = suxDev[uuid]
            active = True
            msg = "DeviceInfos found, Active: %s" % devinfos
            logger.debug(msg)
        except KeyError:
            pass
        try:
            failure = failCreds[uuid]
            active = True
            msg = "Failures found, Active: %s" % failure
            logger.debug(msg)
        except KeyError:
            pass

        if sessions[0] and devinfos[0]:
            seshcount = int(sessions[1])
            devcount = int(devinfos[1])
            success = seshcount + devcount
            session = sessions[0] or devinfos[0]
            msg = "Sessions and DevInfos: %s" % success
            logger.debug(msg)
        elif sessions[0]:
            #print (sessions)
            success = sessions[1]
            session = sessions[0]
            msg = "Sessions only: %s" % success
            logger.debug(msg)
        elif devinfos[0]:
            #print (devinfos)
            success = devinfos[1]
            session = devinfos[0]
            msg = "DevInfos only: %s" % success
            logger.debug(msg)

        scan_ranges_res = scan_ranges[0]
        excludes_res = excludes[0]

        scheduled_scans = builder.get_scans(scan_ranges_res.get('results'), list_of_ranges)
        msg = "Scheduled Scans List" % scheduled_scans
        logger.debug(msg)

        excluded_scans = builder.get_scans(excludes_res.get('results'), list_of_ranges)
        msg = "Excluded Scans List" % excluded_scans
        logger.debug(msg)

        if failure[1]:
            fails = failure[1]
            logger.debug("Failures:%s"%fails)
            
        total = success + fails
        if total > 0:
            logger.debug("Success:%s\nTotal:%s"%(success,total))
            percent = "{0:.0%}".format(success/(total))

        msg = None
        if args.output_file or args.output_csv:
            if active:
                data.append([ detail.get('label'), index, uuid, detail.get('username'), session or failure[0], success, failure[1], percent, status, ip_range, ip_exclude, scheduled_scans if scheduled_scans else None, excluded_scans if excluded_scans else None ])
            else:
                data.append([ detail.get('label'), index, uuid, detail.get('username'), detail.get('types'), None, None, "0%", "Credential appears to not be in use (%s)" % status, ip_range, ip_exclude, scheduled_scans if scheduled_scans else None, excluded_scans if excluded_scans else None ])
            headers = [ "Credential", "Index", "UUID", "Login ID", "Protocol", "Successes", "Failures", "Success %", "State", "Ranges", "Excludes", "Scheduled Scans", "Exclusion Lists" ]
        else:
            if active:
                data.append([ detail.get('label'), index, uuid, detail.get('username'), session or failure[0], success, failure[1], percent, status ])
            else:
                data.append([ detail.get('label'), index, uuid, detail.get('username'), detail.get('types'), None, None, "0%", "Credential appears to not be in use (%s)" % status ])
            headers = [ "Credential", "Index", "UUID", "Login ID", "Protocol", "Successes", "Failures", "Success %", "State" ]
    print(os.linesep,end="\r")

    if msg:
        print(msg)
    output.report(data, headers, args)

def successful_cli(client, args, sysuser, passwd, reporting_dir):
    credentials = access.remote_cmd('tw_vault_control --show --json -u %s -p %s'%(sysuser,passwd),client)
    credjson = []
    for cred in credentials.split("\n"):
        try:
            credjson.append(json.loads(cred))
        except:
            pass

    data = []
    headers = []

    for cred_detail in credjson:
        msg = "Analysing Credential: %s\n"%cred_detail.get('uuid')
        logger.debug(msg)

        detail = tools.extract_credential(cred_detail)
        uuid = detail.get('uuid')
        
        list_of_ranges = detail.get('iprange')
        ip_exclude = detail.get('exclusions')
        enabled = tools.getr(detail,'enabled')
        types = tools.getr(detail,'types')
        if enabled:
            status = "Enabled"
        else:
            status = "Disabled"

        active = False
        success = 0
        failure = 0
        sessions = 0
        devinfos = 0
        credsux = access.remote_cmd('tw_query -u %s -p %s --csv %s'%(sysuser,passwd,queries.credential_success),client)
        devinfosux = access.remote_cmd('tw_query -u %s -p %s --csv %s'%(sysuser,passwd,queries.deviceinfo_success),client)
        credfail = access.remote_cmd('tw_query -u %s -p %s --csv %s'%(sysuser,passwd,queries.credential_failure),client)
        for line in devinfosux.split("\n"):
            if uuid in line:
                msg = "Successful UUID found in line: %s\n"%line
                logger.debug(msg)
                active = True
                success += int(line.split(",")[2])
        for line in credsux.split("\n"):
            if uuid in line:
                msg = "DevInfo UUID found in line: %s\n"%line
                logger.debug(msg)
                active = True
                success += int(line.split(",")[2])
        for line in credfail.split("\n"):
            if uuid in line:
                msg = "Failed UUID found in line: %s\n"%line
                logger.debug(msg)
                active = True
                failure = int(line.split(",")[2])
        
        msg = "Sessions found, Active: %s" % devinfos
        logger.debug(msg)
        msg = "DeviceInfos found, Active: %s" % sessions
        logger.debug(msg)
        msg = "Failures found, Active: %s" % failure
        logger.debug(msg)
            
        total = success + failure
        if total > 0:
            logger.debug("Successes: %s\nOut of Total: %s"%(success,total))
            percent = "{0:.0%}".format(success/(total))

        if active:
            logger.debug("UUID %s found Active"%uuid)
            data.append([ detail.get('label'), uuid, detail.get('username'), types, success, failure, percent, status, list_of_ranges, ip_exclude ])
        else:
            logger.debug("UUID %s found Inactive"%uuid)
            data.append([ detail.get('label'), uuid, detail.get('username'), types, None, None, "0%", "Credential appears to not be in use (%s)" % status, detail.get('usage'), detail.get('internal_store'), list_of_ranges, ip_exclude ])
        headers = [ "Credential", "UUID", "Login ID", "Protocol", "Successes", "Failures", "Success %", "State", "Usage", "Store", "Scan Ranges", "Exclude Ranges" ]

    headers.insert(0,"Discovery Instance")
    for row in data:
        row.insert(0, args.target)
    output.csv_file(data, headers, reporting_dir+"/credentials.csv")

def devices(twsearch, twcreds, args):

    print("\nDevice Access Analyis")
    print("---------------------")
    logger.info("Running Data Analysis Report...")

    vaultcreds = api.get_json(twcreds.get_vault_credentials)

    ### list of unique identities
    identities = builder.unique_identities(twsearch)
    results = api.search_results(twsearch,queries.deviceInfo)

    devices = []
    msg = None
    headers = []

    # Build the results

    timer_count = 0
    for identity in identities:
        timer_count = tools.completage("Gathering Device Results...", len(identities), timer_count)
        logger.debug("Processing identity %s"%identity)
        latest_timestamp = None
        all_credentials_used = []
        all_discovery_runs = []
        all_kinds = []
        device = {}
        last_identity = None
        last_scanned_ip = None
        last_kind = None
        for result in results:

            da_endpoint = tools.getr(result,'DA_Endpoint',None)
            logger.debug("Checking endpoint %s in identity %s"%(da_endpoint,identity))

            # If this deviceinfo record relates to this device identity
            if da_endpoint in identity.get('list_of_ips'):

                # Collect ALL Data

                device_name = tools.getr(result,'Device_Hostname',"None")
                logger.debug("%s Device Name: %s"%(da_endpoint,device_name))
                all_device_names = [ device_name ]
                all_device_names = tools.list_of_lists(result,'Inferred_Name',all_device_names)
                all_device_names = tools.list_of_lists(result,'Inferred_Hostname',all_device_names)
                all_device_names = tools.list_of_lists(result,'Inferred_FQDN',all_device_names)
                all_endpoints = [ da_endpoint ]
                all_endpoints = tools.list_of_lists(result,'Chosen_Endpoint',all_endpoints)
                all_endpoints = tools.list_of_lists(result,'Discovered_IP_Addrs',all_endpoints)
                all_endpoints = tools.list_of_lists(result,'Inferred_All_IP_Addrs',all_endpoints)
                logger.debug("%s All endpoints: %s"%(da_endpoint,all_endpoints))
                    
                scan_run = tools.getr(result,'Discovery_Run',"None")
                all_discovery_runs.append(scan_run)
                all_discovery_runs = tools.sortlist(all_discovery_runs)
                logger.debug("%s All Runs: %s"%(da_endpoint,all_discovery_runs))

                uuid = tools.getr(result,'Last_Credential',None)

                all_credentials_used = []
                cred_label = None
                cred_username = None
                if uuid:
                    credential_details = tools.get_credential(vaultcreds,uuid)
                    cred_label = tools.getr(credential_details,'label',"Not Found")
                    cred_username = tools.getr(credential_details,'username',"Not Found")
                    all_credentials_used.append("%s (%s)" % (cred_label,uuid))
                all_credentials_used = tools.sortlist(all_credentials_used)
                logger.debug("%s All Runs: %s"%(da_endpoint,all_credentials_used))
                
                da_result = tools.getr(result,'DA_Result',"None")
                end_state = tools.getr(result,'DA_End_State',"None")
                last_marker = tools.getr(result,'Last_Marker',None)
                had_inference = tools.getr(result,'Had_Inference',None)
                logger.debug("%s Last Marker: %s"%(da_endpoint,last_marker))
                logger.debug("%s Had Inference: %s"%(da_endpoint,had_inference))

                # Other Attributes

                first_marker = tools.getr(result,'First_Marker',"None")
                last_interesting = tools.getr(result,'Last_Interesting',"None")
                os_type = tools.getr(result,'OS_Type',"None")
                device_type = tools.getr(result,'Device_Type',"None")
                method_success = tools.getr(result,'M_Success',"None")
                method_failure = tools.getr(result,'M_Failure',"None")
                endtime = tools.getr(result,'DA_End',"None")
                kind = tools.getr(result,'Kind',"None")
                last_access_method = tools.getr(result,'Last_Access_Method',"None")
                logger.debug("%s Last Access Method: %s"%(da_endpoint,last_access_method))

                all_kinds.append(kind)

                start_time = tools.getr(result,'DA_Start',"None")

                device.update({
                                "all_device_names":identity.get('list_of_names'),
                                "all_endpoints":identity.get('list_of_ips'),
                                "all_credentials_used":all_credentials_used,
                                "all_discovery_runs":all_discovery_runs
                                })

                start_time_str = start_time.split(" ")
                start_time_str = start_time_str[:2]
                start_time_str = " ".join(start_time_str)
                start_timestamp = datetime.datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
                logger.debug("%s Start Timestamp: %s latest Timestamp: %s"%(da_endpoint,start_timestamp,latest_timestamp))
                if not latest_timestamp:
                    logger.debug("%s No Latest Timestamp, setting to Start Timestamp: %s"%(da_endpoint,latest_timestamp))
                    latest_timestamp = start_timestamp
                if start_timestamp > latest_timestamp:
                    logger.debug("%s Start Timestamp %s is fresher than latest_timestamp: %s"%(da_endpoint,start_timestamp,latest_timestamp))
                    latest_timestamp = start_timestamp

                    if last_marker: # The last scan
                        logger.debug("%s, %s Last Marker is set."%(da_endpoint,latest_timestamp))

                        # Collect the very LAST Data

                        last_kind = kind
                        last_identity = device_name
                        last_scanned_ip = da_endpoint
                        last_credential = uuid
                        last_credential_label = cred_label
                        last_credential_username = cred_username
                        last_start_time = start_time
                        last_run = scan_run
                        last_endstate = end_state
                        last_result = da_result
                        last_access_method = last_access_method

                        device.update({
                                    "last_identity":last_identity,
                                    "last_kind":last_kind,
                                    "last_scanned_ip":last_scanned_ip,
                                    "last_credential":last_credential,
                                    "last_credential_label":last_credential_label,
                                    "last_credential_username":last_credential_username,
                                    "last_start_time":last_start_time,
                                    "last_run":last_run,
                                    "last_endstate":last_endstate,
                                    "last_result":last_result,
                                    "last_access_method":last_access_method
                                    })
                    
                    if had_inference: # The last successful
                        logger.debug("%s, %s Had Inference."%(da_endpoint,latest_timestamp))

                        last_successful_identity = device_name
                        last_successful_ip = da_endpoint
                        last_successful_credential = uuid
                        last_successful_credential_label = cred_label
                        last_successful_credential_username = cred_username
                        last_successful_start_time = start_time
                        last_successful_run = scan_run
                        last_successful_endstate = end_state
                        last_successful_result = da_result

                        device.update({
                                        "last_successful_identity":last_successful_identity,
                                        "last_successful_ip":last_successful_ip,
                                        "last_successful_credential":last_successful_credential,
                                        "last_successful_credential_label":last_successful_credential_label,
                                        "last_successful_credential_username":last_successful_credential_username,
                                        "last_successful_start_time":last_successful_start_time,
                                        "last_successful_run":last_successful_run,
                                        "last_successful_endstate":last_successful_endstate,
                                        "last_successful_result":last_successful_result,
                                        "last_access_method":last_access_method
                                        })
                
                if not last_identity:
                    last_identity = all_device_names[0]
                    device.update({"last_identity":last_identity})
                    logger.debug("%s, %s Last Identity missing, set to %s"%(da_endpoint,latest_timestamp,last_identity))
                if not last_kind:
                    last_kind = kind
                    device.update({"last_kind":last_kind})
                    logger.debug("%s, %s Last Kind missing, set to %s"%(da_endpoint,latest_timestamp,last_kind))
                if not last_scanned_ip:
                    last_scanned_ip = da_endpoint
                    device.update({"last_scanned_ip":last_scanned_ip})
                    logger.debug("%s, %s Last Scanned IP missing, set to %s"%(da_endpoint,latest_timestamp,last_scanned_ip))

                devices.append(device)
                logger.debug("Device added to list of devices:%s"%(device))
    
    # Make sure we only report each device once - there is probably a more efficient way to do this in the loop.
    devices = list({v['last_identity']:v for v in devices}.values())
    logger.debug("Unique List of devices:%s"%(devices))

    # Build the report

    data = []

    for device in devices:
        last_scanned_ip = device.get("last_scanned_ip")
        last_identity = device.get('last_identity')
        last_kind = device.get('last_kind')
        all_device_names = device.get("all_device_names")
        all_endpoints = device.get("all_endpoints")
        all_credentials_used = device.get("all_credentials_used")
        all_discovery_runs = device.get("all_discovery_runs")
        last_credential = device.get("last_credential")
        last_credential_label = device.get("last_credential_label")
        last_credential_username = device.get("last_credential_username")
        last_start_time = device.get("last_start_time")
        last_run = device.get("last_run")
        last_endstate = device.get("last_endstate")
        last_result = device.get("last_result")
        last_successful_identity = device.get('last_successful_identity')
        last_successful_ip = device.get('last_successful_ip')
        last_successful_credential = device.get("last_successful_credential")
        last_successful_credential_label = device.get("last_successful_credential_label")
        last_successful_credential_username = device.get("last_successful_credential_username")
        last_successful_start_time = device.get("last_successful_start_time")
        last_successful_run = device.get("last_successful_run")
        last_successful_endstate = device.get("last_successful_endstate")
        last_access_method = device.get('last_access_method')

        msg = os.linesep
        if args.output_csv or args.output_file:    
            data.append([
                        last_scanned_ip,
                        last_identity,
                        last_kind,
                        all_device_names,
                        all_endpoints,
                        all_credentials_used,
                        all_discovery_runs,
                        last_credential,
                        last_credential_label,
                        last_credential_username,
                        last_start_time,
                        last_run,
                        last_endstate,
                        last_result,
                        last_access_method,
                        last_successful_identity,
                        last_successful_ip,
                        last_successful_credential,
                        last_successful_credential_label,
                        last_successful_credential_username,
                        last_successful_start_time,
                        last_successful_run,
                        last_successful_endstate,
                        ])
            headers = [
                    "last_scanned_ip",
                    "last_identity",
                    "last_kind",
                    "all_device_names",
                    "all_endpoints",
                    "all_credentials_used",
                    "all_discovery_runs",
                    "last_credential",
                    "last_credential_label",
                    "last_credential_username",
                    "last_start_time",
                    "last_run",
                    "last_endstate",
                    "last_result",
                    "last_access_method",
                    "last_successful_identity",
                    "last_successful_ip",
                    "last_successful_credential",
                    "last_successful_credential_label",
                    "last_successful_credential_username",
                    "last_successful_start_time",
                    "last_successful_run",
                    "last_successful_endstate"
                    ]
        else:
            msg = "\nOnly showing limited details for table output. Output to CSV for full results.\n"
            data.append([
                        last_scanned_ip,
                        last_identity,
                        last_kind,
                        last_credential_label,
                        last_start_time,
                        last_run,
                        last_endstate,
                        last_result,
                        last_access_method
                        ])

            headers = [
                    "last_scanned_ip",
                    "last_identity",
                    "last_kind",
                    "last_credential_label",
                    "last_start_time",
                    "last_run",
                    "last_endstate",
                    "last_result",
                    "last_access_method"
                    ]

    if msg:
        print(msg)
    output.report(data, headers, args)

def ipaddr(search, credentials, args):
    ipaddr = args.excavate[1]
    msg = "\nIP Address Lookup: %s" % ipaddr
    logger.info(msg)
    print(msg)

    devices = {
                "query":
                """
                    search flags(no_segment) Host, NetworkDevice, Printer, SNMPManagedDevice, StorageDevice, ManagementController
                    where '%s' in __all_ip_addrs
                    show
                    name as 'Name',
                    os as 'OS',
                    kind(#) as 'Nodekind'
                    processwith unique()
                """ % ipaddr
               }
    accesses = {
                "query":
                """
                    search DiscoveryAccess where endpoint = '%s'
                    show
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.hostname as 'Name',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.device_type as 'Device_Type',
                    inferred_kind as 'nodekind',
                    (#DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_credential
                        or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_slave) as 'credential',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_access_method as 'session_type',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.method_success as 'success',
                    'Credential ID Retrieved from DeviceInfo' as 'message'
                    process with unique()
                """ % ipaddr
               }

    devResults = api.search_results(search,devices)
    accessResults = api.search_results(search,accesses)
    dropped = api.search_results(search,queries.dropped_endpoints)

    devices_found = []
    if len(devResults) == 1:
        msg = "\nDevices Found:"
        devices_found.append(devResults[0]['Name'])
        logger.debug("1 Dev Result: %s,%s"%(msg,devices_found))
    elif len(devResults) > 1:
        msg = "\nDevices Found:"
        for dev in devResults:
            devices_found.append(dev.get('Name'))
            logger.debug("Added Dev Result: %s"%(devices_found))
    if len(accessResults) == 1:
        msg = "\nDevices Found:"
        devices_found.append(accessResults[0]['Name'])
        logger.debug("1 DA result: %s,%s"%(msg,devices_found))
    elif len(accessResults) > 1:
        msg = "\nDevices Found:"
        for dev in accessResults:
            devices_found.append(dev.get('Name'))
            logger.debug("Added DA result: %s"%(devices_found))

    if len(devices_found) == 0:
        msg = "\nDevice not found or data may have aged out!"
    
        for drop in dropped:
            if drop.get('Endpoint') == ipaddr:
                msg = "Dropped IP Address"
                logger.debug("Endpoint %s is dropped IP"%(ipaddr))
    else:
        devices_found = tools.sortlist(devices_found)

    print(msg,devices_found,"\n")
    logger.debug("Unique List: %s,%s"%(msg,devices_found))

    id_list = []
    unique_ids = builder.unique_identities(search)
    for identity in unique_ids:
        logger.debug("Checking IP address %s in Identity %s"%(ipaddr,identity))
        if ipaddr in identity.get('list_of_ips'):
            msg = "Identities Matched:"
            id_list.append(identity)
            logger.debug("Appending identity to list %s"%(identity))
    
    if len(id_list) > 0:
        print(msg)
        logger.info(msg)
        for id in id_list:
            print(id)
            logger.info(id)
        print(os.linesep)

    # Build the results
    
    data = []

    uuid = None

    sessionQry = {
                "query":
                """
                    search DiscoveryAccess where endpoint = '%s'
                    traverse DiscoveryAccess:Metadata:Detail:SessionResult
                    show
                    session_type as 'session_type',
                    credential as 'credential',
                    success as 'success',
                    message as 'message',
                    kind(#) as 'nodekind'
                    processwith unique()
                """ % ipaddr
               }
    sessionResults = api.search_results(search,sessionQry)
    total = len(sessionResults)
    logger.debug("%s Session results"%total)
    if total == 0:
        # Alternate lookup
        sessionResults = accessResults
        total = len(sessionResults)
        logger.debug("%s Alternate Session results"%total)

    # Build the results
    
    data = []

    uuid = None

    for result in sessionResults:
        uuid = result.get('credential')
        logger.debug("UUID from SessionResult %s"%uuid)
        label = None
        username = None
        status = None
        if uuid:
            vaultcreds = api.get_json(credentials.get_vault_credential(uuid))
            logger.debug("Pulled Vault Credential %s"%vaultcreds)
            detail = builder.get_credentials(vaultcreds)
            label = tools.getr(detail,'label')
            username = tools.getr(detail,'username')
            enabled = tools.getr(detail,'enabled')
            if enabled:
                status = "Enabled"
            else:
                status = "Disabled"
        st = result.get('session_type')
        m = result.get('message')
        s = result.get('success')
        data.append([ st, label, uuid, username, status, m, s ])

    output.report(data, [ "Session Type", "Credential", "Credential ID", "Credential Login", "Status", "Message", "Successful" ], args)

def discovery_access(twsearch, twcreds, args):
    print("\nDiscovery Access Export")
    print("-----------------------")
    logger.info("Running DA Report")

    vaultcreds = api.get_json(twcreds.get_vault_credentials)

    ### list of unique identities
    identities = builder.unique_identities(twsearch)
    discos = api.search_results(twsearch,queries.last_disco)
    dropped = api.search_results(twsearch,queries.dropped_endpoints)

    disco_data = []
    unique_endpoints = []

    # Get a list of Unique IPs
    for result in discos:
        logger.debug("Getting unique IPs from result: %s"%result)
        endpoint = result.get('Endpoint')
        unique_endpoints.append(endpoint)
    for result in dropped:
        logger.debug("Getting unique IPs from dropped: %s"%result)
        endpoint = result.get('Endpoint')
        unique_endpoints.append(endpoint)
    unique_endpoints = tools.sortlist(unique_endpoints)
    logger.debug("List of Unique Endpoints: %s"%unique_endpoints)

    # Build the results
    timer_count = 0
    for endpoint in unique_endpoints:
        timer_count = tools.completage("Gathering Discovery Access Results...", len(unique_endpoints), timer_count)
        logger.debug("Building Record for: %s"%endpoint)

        ep_timestamp = None

        list_of_end_states = []
    
        for result in discos:
            r_endpoint = tools.getr(result,'Endpoint')
            if r_endpoint == endpoint:
                ep_record = {"endpoint":endpoint}
                logger.debug("Building Results, result: %s"%result)
                hostname = tools.getr(result,'Hostname',None)
                os_type = tools.getr(result,'OS_Type',None)
                os_class = tools.getr(result,'OS_Class',None)
                disco_run = tools.getr(result,'Discovery_Run',None)
                run_start = tools.getr(result,'Run_Starttime',None)
                run_end = tools.getr(result,'Run_Endtime',None)
                scan_start = tools.getr(result,'Scan_Starttime',None)
                scan_end = tools.getr(result,'Scan_Endtime')
                when = result.get('When_Last_Scan')
                scan_end_str = scan_end.split(" ")
                scan_end_str = scan_end_str[:2]
                scan_end_str = " ".join(scan_end_str)
                ep_timestamp = datetime.datetime.strptime(scan_end_str, "%Y-%m-%d %H:%M:%S")
                time_now = datetime.datetime.now()
                delta = time_now - ep_timestamp
                days = delta.days
                days_to_hours = days * 24
                days_to_mins = days_to_hours * 60
                secs_to_mins = (delta.seconds) / 60
                overall_mins = days_to_mins + secs_to_mins
                whenData = pd.DataFrame({'in_minutes':[overall_mins]})
                # 0, 60 Mins, 24 Hours, 7 Days, 4 Weeks, 3 Months, 6 Months, 12 Months
                bins = [0,59,1440,10080,43830,131487,262974,525949,525950]
                labels = ['Less than 60 minutes ago','Less than 24 hours ago','Less than 7 days ago','Less than 1 month ago','Less than 3 months ago','Less than 6 months ago','Less than 12 months ago','Over a year ago']
                whenData['when'] = pd.cut(whenData['in_minutes'], bins=bins, labels=labels, right=False)
                whenDict = whenData.to_dict()
                when = whenDict.get('when')
                whenWasThat = when.get(0)
                current_access = tools.getr(result,'Current_Access',None)
                os_version = tools.getr(result,'OS_Version',None)
                node_updated = tools.getr(result,'Host_Node_Updated',None)
                end_state = tools.getr(result,'End_State',None)
                prev_end_state = tools.getr(result,'Previous_End_State',None)
                list_of_end_states.append(end_state)
                reason_not_updated = tools.getr(result,'Reason_Not_Updated',None)
                session_results_logged = tools.getr(result,'Session_Results_Logged',None)
                node_kind = result.get('Node_Kind')
                if type(node_kind) is list:
                    node_kind = tools.sortlist(node_kind)
                last_credential = tools.getr(result,'Last_Credential',None)
                credential_name = None
                credential_login = None
                list_of_names = None
                list_of_endpoints = None
                node_id = result.get("DA_ID")
                prev_node_id = result.get("Previous_DA_ID")
                next_node_id = result.get("Next_DA_ID")
                for identity in identities:
                    if endpoint in identity.get('list_of_ips'):
                        list_of_endpoints = identity.get('list_of_ips')
                        list_of_names = identity.get('list_of_names')
                        logger.debug("Endpoint %s Identity: %s"%(endpoint,identity))
            
                if last_credential:
                    credential_details = tools.get_credential(vaultcreds,last_credential)
                    credential_name = tools.getr(credential_details,'label',"Not Found")
                    credential_login = tools.getr(credential_details,'username',"Not Found")
                    logger.debug("Last Credential: %s"%(last_credential))

                # Count endstates and determine consistency
                end_states_total = len(list_of_end_states)
                end_states_counter = dict(Counter(list_of_end_states))
                largest = max(end_states_counter, key=end_states_counter.get)
                if end_states_counter[largest] == end_states_total:
                    consistency = "Always %s"%largest
                elif end_states_counter[largest] >= end_states_total - 2:
                    consistency = "Usually %s"%largest
                else:
                    consistency = "Most Often %s"%largest

                last_marker = result.get("Last_Marker")

                ep_record.update({
                                "hostname":hostname,
                                "list_of_names":list_of_names,
                                "list_of_endpoints":list_of_endpoints,
                                "node_kind":node_kind,
                                "os_type":os_type,
                                "os_version":os_version,
                                "os_class":os_class,
                                "disco_run":disco_run,
                                "run_start":run_start,
                                "run_end":run_end,
                                "scan_start":scan_start,
                                "scan_end":scan_end,
                                "when_was_that":whenWasThat,
                                "consistency":consistency,
                                "current_access":current_access,
                                "node_updated":node_updated,
                                "reason_not_updated":reason_not_updated,
                                "end_state":end_state,
                                "previous_end_state":prev_end_state,
                                "session_results_logged":session_results_logged,
                                "last_credential":last_credential,
                                "credential_name":credential_name,
                                "credential_login":credential_login,
                                "timestamp":ep_timestamp,
                                "da_id":node_id,
                                "prev_da_id":prev_node_id,
                                "next_node_id":next_node_id,
                                "last_marker":last_marker
                    })
                # Add to DA list
                disco_data.append(ep_record)

        for result in dropped:
            dropped_ep = result.get('Endpoint')
            dropped_times = 0
            if dropped_ep == endpoint:
                ep_record = {"endpoint":endpoint}
                dropped_times += 1
                run_end = tools.getr(result,'End')
                run_end_str = run_end.split(" ")
                run_end_str = run_end_str[:2]
                run_end_str = " ".join(run_end_str)
                run_end_timestamp = datetime.datetime.strptime(run_end_str, "%Y-%m-%d %H:%M:%S")
                time_now = datetime.datetime.now()
                delta = time_now - run_end_timestamp
                days = delta.days
                days_to_hours = days * 24
                days_to_mins = days_to_hours * 60
                secs_to_mins = (delta.seconds) / 60
                overall_mins = days_to_mins + secs_to_mins
                whenData = pd.DataFrame({'in_minutes':[overall_mins]})
                # 0, 60 Mins, 24 Hours, 7 Days, 4 Weeks, 3 Months, 6 Months, 12 Months
                bins = [0,59,1440,10080,43830,131487,262974,525949,525950]
                labels = ['Less than 60 minutes ago','Less than 24 hours ago','Less than 7 days ago','Less than 1 month ago','Less than 3 months ago','Less than 6 months ago','Less than 12 months ago','Over a year ago']
                whenData['when'] = pd.cut(whenData['in_minutes'], bins=bins, labels=labels, right=False)
                whenDict = whenData.to_dict()
                when = whenDict.get('when')
                whenWasThat = when.get(0)
                disco_run = tools.getr(result,'Run',None)
                run_start = tools.getr(result,'Start',None)
                run_end = tools.getr(result,'End',None)
                when = result.get('When_Last_Scan')
                end_state = tools.getr(result,'End_State',None)
                list_of_end_states.append(end_state)
                # Count end states and determine consistency
                end_states_total = len(list_of_end_states)
                end_states_counter = dict(Counter(list_of_end_states))
                largest = max(end_states_counter, key=end_states_counter.get)
                if end_states_counter[largest] == end_states_total:
                    consistency = "Always %s"%largest
                elif end_states_counter[largest] >= end_states_total - 2:
                    consistency = "Usually %s"%largest
                else:
                    consistency = "Most Often %s"%largest
                reason_not_updated = tools.getr(result,'Reason_Not_Updated',None)
                list_of_names = None
                list_of_endpoints = None
                for identity in identities:
                    if endpoint in identity.get('list_of_ips'):
                        list_of_endpoints = identity.get('list_of_ips')
                        list_of_names = identity.get('list_of_names')

                logger.debug("Updating Dropped Record %s"%(ep_timestamp))
                ep_record.update({
                                "list_of_names":list_of_names,
                                "list_of_endpoints":list_of_endpoints,
                                "disco_run":disco_run,
                                "run_start":run_start,
                                "run_end":run_end,
                                "when_was_that":whenWasThat,
                                "consistency":consistency,
                                "reason_not_updated":reason_not_updated,
                                "end_state":end_state,
                                "timestamp":ep_timestamp,
                                "dropped":dropped_times
                            })

                # Change Analysis
                current_dq_state = ep_record.get("end_state")
                prev_dq_state = ep_record.get("previous_end_state")
                was_dropped = tools.getr(ep_record,"dropped",0)
                if prev_dq_state is None:
                    if was_dropped > 1 and current_dq_state in [ "DarkSpace", "AlreadyProcessing", "Excluded" ]:
                        prev_dq_state = current_dq_state
                    else:
                        prev_dq_state = "First Scan"
                change = "%s -> %s"%(prev_dq_state,current_dq_state)
                ep_record.update({"change":change})

                # Add to DA list
                disco_data.append(ep_record)

    # Build the report

    msg = os.linesep
    data = []

    for ddata in disco_data:

        if args.output_csv or args.output_file:

            data.append([
                        ddata.get("endpoint"),
                        ddata.get("hostname"),
                        ddata.get("list_of_names"),
                        ddata.get("list_of_endpoints"),
                        ddata.get("node_kind"),
                        ddata.get("os_type"),
                        ddata.get("os_version"),
                        ddata.get("os_class"),
                        ddata.get("disco_run"),
                        ddata.get("run_start"),
                        ddata.get("run_end"),
                        ddata.get("scan_start"),
                        ddata.get("scan_end"),
                        ddata.get("when_was_that"),
                        ddata.get("consistency"),
                        ddata.get("current_access"),
                        ddata.get("node_updated"),
                        ddata.get("reason_not_updated"),
                        ddata.get("end_state"),
                        ddata.get("previous_end_state"),
                        ddata.get("change"),
                        ddata.get("session_results_logged"),
                        ddata.get("last_credential"),
                        ddata.get("credential_name"),
                        ddata.get("credential_login"),
                        ddata.get("timestamp"),
                        ddata.get("last_marker"),
                        ddata.get("da_id"),
                        ddata.get("prev_da_id"),
                        ddata.get("next_node_id"),
                        ddata.get("dropped")
                        ])
            headers = [
                        "endpoint",
                        "device_name",
                        "list_of_device_names",
                        "list_of_endpoints",
                        "node_kind",
                        "os_type",
                        "os_version",
                        "os_class",
                        "discovery_run",
                        "discovery_run_start",
                        "discovery_run_end",
                        "scan_start",
                        "scan_end",
                        "when_was_that",
                        "consistency",
                        "current_access",
                        "inferred_node_updated",
                        "reason_not_updated",
                        "end_state",
                        "previous_end_state",
                        "end_state_change",
                        "session_results_logged",
                        "last_credential",
                        "credential_name",
                        "credential_login",
                        "timestamp",
                        "last_marker",
                        "da_id",
                        "prev_da_id",
                        "next_node_id",
                        "dropped"
                        
                    ]
        else:
            msg = "\nOnly showing limited details for table output. Output to CSV for full results.\n"
            data.append([
                        ddata.get("endpoint"),
                        ddata.get("hostname"),
                        ddata.get("when_was_that"),
                        ddata.get("node_updated"),
                        ddata.get("consistency"),
                        ddata.get("change"),
                        ddata.get("credential_name")
                        ])

            headers = [
                        "endpoint",
                        "device_name",
                        "when_was_that",
                        "inferred_node_updated",
                        "consistency",
                        "end_state_change",
                        "credential_name"
                    ]

    print(msg)

    try:
        # Try sorting all records by IP Endpoint
        data.sort( key = lambda k: (isinstance(tools.ip_or_string(k[0]), str), tools.ip_or_string(k[0])) )
    except TypeError as e:
        msg = "TypeError: Data output can't be hashed (cannot be sorted)\nError: %s" % str(e)
        print(msg)
        logger.error(msg)

    output.report(data, headers, args)

def discovery_analysis(twsearch, twcreds, args):
    print("\nDiscovery Access Analysis")
    print("-------------------------")
    logger.info("Running DA Analysis Report")

    vaultcreds = api.get_json(twcreds.get_vault_credentials)

    ### list of unique identities
    identities = builder.unique_identities(twsearch)
    discos = api.search_results(twsearch,queries.last_disco)
    dropped = api.search_results(twsearch,queries.dropped_endpoints)

    disco_data = []
    unique_endpoints = []

    # Get a list of Unique IPs
    for result in discos:
        logger.debug("Getting unique IPs from result: %s"%result)
        endpoint = result.get('Endpoint')
        unique_endpoints.append(endpoint)
    for result in dropped:
        logger.debug("Getting unique IPs from dropped: %s"%result)
        endpoint = result.get('Endpoint')
        unique_endpoints.append(endpoint)
    unique_endpoints = tools.sortlist(unique_endpoints)
    logger.debug("List of Unique Endpoints: %s"%unique_endpoints)

    # Build the results
    timer_count = 0
    for endpoint in unique_endpoints:
        timer_count = tools.completage("Gathering Analysis Results...", len(unique_endpoints), timer_count)
        logger.debug("Building Record for: %s"%endpoint)

        ep_timestamp = None
        ep_record = {"endpoint":endpoint}

        list_of_end_states = []
    
        for result in discos:
            # Results _should_ be unique so there is no need to to a timestamp check
            r_endpoint = tools.getr(result,'Endpoint')
            if r_endpoint == endpoint:
                logger.debug("Building Results, result: %s"%result)
                hostname = tools.getr(result,'Hostname',None)
                os_type = tools.getr(result,'OS_Type',None)
                os_class = tools.getr(result,'OS_Class',None)
                disco_run = tools.getr(result,'Discovery_Run',None)
                run_start = tools.getr(result,'Run_Starttime',None)
                run_end = tools.getr(result,'Run_Endtime',None)
                scan_start = tools.getr(result,'Scan_Starttime',None)
                scan_end = tools.getr(result,'Scan_Endtime')
                when = result.get('When_Last_Scan')
                scan_end_str = scan_end.split(" ")
                scan_end_str = scan_end_str[:2]
                scan_end_str = " ".join(scan_end_str)
                ep_timestamp = datetime.datetime.strptime(scan_end_str, "%Y-%m-%d %H:%M:%S")
                time_now = datetime.datetime.now()
                delta = time_now - ep_timestamp
                days = delta.days
                days_to_hours = days * 24
                days_to_mins = days_to_hours * 60
                secs_to_mins = (delta.seconds) / 60
                overall_mins = days_to_mins + secs_to_mins
                whenData = pd.DataFrame({'in_minutes':[overall_mins]})
                # 0, 60 Mins, 24 Hours, 7 Days, 4 Weeks, 3 Months, 6 Months, 12 Months
                bins = [0,59,1440,10080,43830,131487,262974,525949,525950]
                labels = ['Less than 60 minutes ago','Less than 24 hours ago','Less than 7 days ago','Less than 1 month ago','Less than 3 months ago','Less than 6 months ago','Less than 12 months ago','Over a year ago']
                whenData['when'] = pd.cut(whenData['in_minutes'], bins=bins, labels=labels, right=False)
                whenDict = whenData.to_dict()
                when = whenDict.get('when')
                whenWasThat = when.get(0)
                current_access = tools.getr(result,'Current_Access',None)
                access_method = tools.getr(result,'Access_Method',None)
                os_version = tools.getr(result,'OS_Version',None)
                node_updated = tools.getr(result,'Host_Node_Updated',None)
                end_state = tools.getr(result,'End_State',None)
                prev_end_state = tools.getr(result,'Previous_End_State',None)
                list_of_end_states.append(end_state)
                reason_not_updated = tools.getr(result,'Reason_Not_Updated',None)
                session_results_logged = tools.getr(result,'Session_Results_Logged',None)
                node_kind = result.get('Node_Kind')
                if type(node_kind) is list:
                    node_kind = tools.sortlist(node_kind)
                last_credential = tools.getr(result,'Last_Credential',None)
                credential_name = None
                credential_login = None
                list_of_names = None
                list_of_endpoints = None
                node_id = result.get("DA_ID")
                prev_node_id = result.get("Previous_DA_ID")
                next_node_id = result.get("Next_DA_ID")
                for identity in identities:
                    if endpoint in identity.get('list_of_ips'):
                        list_of_endpoints = identity.get('list_of_ips')
                        list_of_names = identity.get('list_of_names')
                        logger.debug("Endpoint %s Identity: %s"%(endpoint,identity))
            
                if last_credential:
                    credential_details = tools.get_credential(vaultcreds,last_credential)
                    credential_name = tools.getr(credential_details,'label',"Not Found")
                    credential_login = tools.getr(credential_details,'username',"Not Found")
                    logger.debug("Last Credential: %s"%(last_credential))

                # Count endstates and determine consistency
                end_states_total = len(list_of_end_states)
                end_states_counter = dict(Counter(list_of_end_states))
                largest = max(end_states_counter, key=end_states_counter.get)
                if end_states_counter[largest] == end_states_total:
                    consistency = "Always %s"%largest
                elif end_states_counter[largest] >= end_states_total - 2:
                    consistency = "Usually %s"%largest
                else:
                    consistency = "Most Often %s"%largest

                last_marker = result.get("Last_Marker")

                if last_marker:
                    ep_record.update({
                                        "hostname":hostname,
                                        "list_of_names":list_of_names,
                                        "list_of_endpoints":list_of_endpoints,
                                        "node_kind":node_kind,
                                        "os_type":os_type,
                                        "os_version":os_version,
                                        "os_class":os_class,
                                        "disco_run":disco_run,
                                        "run_start":run_start,
                                        "run_end":run_end,
                                        "scan_start":scan_start,
                                        "scan_end":scan_end,
                                        "when_was_that":whenWasThat,
                                        "consistency":consistency,
                                        "current_access":current_access,
                                        "access_method":access_method,
                                        "node_updated":node_updated,
                                        "reason_not_updated":reason_not_updated,
                                        "end_state":end_state,
                                        "previous_end_state":prev_end_state,
                                        "session_results_logged":session_results_logged,
                                        "last_credential":last_credential,
                                        "credential_name":credential_name,
                                        "credential_login":credential_login,
                                        "timestamp":ep_timestamp,
                                        "da_id":node_id,
                                        "prev_da_id":prev_node_id,
                                        "next_node_id":next_node_id
                    })

        for result in dropped:
            dropped_ep = result.get('Endpoint')
            dropped_times = 0
            if dropped_ep == endpoint:
                dropped_times += 1
                run_end = tools.getr(result,'End')
                run_end_str = run_end.split(" ")
                run_end_str = run_end_str[:2]
                run_end_str = " ".join(run_end_str)
                run_end_timestamp = datetime.datetime.strptime(run_end_str, "%Y-%m-%d %H:%M:%S")
                time_now = datetime.datetime.now()
                delta = time_now - run_end_timestamp
                days = delta.days
                days_to_hours = days * 24
                days_to_mins = days_to_hours * 60
                secs_to_mins = (delta.seconds) / 60
                overall_mins = days_to_mins + secs_to_mins
                whenData = pd.DataFrame({'in_minutes':[overall_mins]})
                # 0, 60 Mins, 24 Hours, 7 Days, 4 Weeks, 3 Months, 6 Months, 12 Months
                bins = [0,59,1440,10080,43830,131487,262974,525949,525950]
                labels = ['Less than 60 minutes ago','Less than 24 hours ago','Less than 7 days ago','Less than 1 month ago','Less than 3 months ago','Less than 6 months ago','Less than 12 months ago','Over a year ago']
                whenData['when'] = pd.cut(whenData['in_minutes'], bins=bins, labels=labels, right=False)
                whenDict = whenData.to_dict()
                when = whenDict.get('when')
                whenWasThat = when.get(0)
                disco_run = tools.getr(result,'Run',None)
                run_start = tools.getr(result,'Start',None)
                run_end = tools.getr(result,'End',None)
                when = result.get('When_Last_Scan')
                end_state = tools.getr(result,'End_State',None)
                list_of_end_states.append(end_state)
                # Count end states and determine consistency
                end_states_total = len(list_of_end_states)
                end_states_counter = dict(Counter(list_of_end_states))
                largest = max(end_states_counter, key=end_states_counter.get)
                if end_states_counter[largest] == end_states_total:
                    consistency = "Always %s"%largest
                elif end_states_counter[largest] >= end_states_total - 2:
                    consistency = "Usually %s"%largest
                else:
                    consistency = "Most Often %s"%largest
                reason_not_updated = tools.getr(result,'Reason_Not_Updated',None)
                list_of_names = None
                list_of_endpoints = None
                for identity in identities:
                    if endpoint in identity.get('list_of_ips'):
                        list_of_endpoints = identity.get('list_of_ips')
                        list_of_names = identity.get('list_of_names')

                logger.debug("ep_timestamp: %s, run_end timestamp: %s"%(ep_timestamp,run_end_timestamp))
                if not ep_timestamp:
                    ep_timestamp = run_end_timestamp
                    logger.debug("IP has no DA, endpoint timestamp set to: %s"%(ep_timestamp))

                    # New DA Record
                    # Only update if we have the freshest timestamp
                    logger.debug("Updating Dropped Record %s"%(ep_timestamp))
                    ep_record.update({
                                    "list_of_names":list_of_names,
                                    "list_of_endpoints":list_of_endpoints,
                                    "disco_run":disco_run,
                                    "run_start":run_start,
                                    "run_end":run_end,
                                    "when_was_that":whenWasThat,
                                    "consistency":consistency,
                                    "reason_not_updated":reason_not_updated,
                                    "end_state":end_state,
                                    "timestamp":ep_timestamp,
                                    "dropped":dropped_times
                                })

                elif run_end_timestamp > ep_timestamp:
                    ep_timestamp = run_end_timestamp
                    logger.debug("endpoint timestamp update to: %s"%(ep_timestamp))

                    prev_end_state = ep_record.get("end_state")
                    dropped_times += tools.getr(ep_record,"dropped",0)

                    # Update DA record
                    ep_record.update({
                                        "list_of_names":list_of_names,
                                        "list_of_endpoints":list_of_endpoints,
                                        "disco_run":disco_run,
                                        "run_start":run_start,
                                        "run_end":run_end,
                                        "scan_start":None,
                                        "scan_end":None,
                                        "when_was_that":whenWasThat,
                                        "consistency":consistency,
                                        "current_access":None,
                                        "access_method":None,
                                        "node_updated":None,
                                        "reason_not_updated":reason_not_updated,
                                        "end_state":end_state,
                                        "previous_end_state":prev_end_state,
                                        "session_results_logged":None,
                                        "timestamp":ep_timestamp,
                                        "dropped":dropped_times
                                    })

        # Change Analysis
        current_dq_state = ep_record.get("end_state")
        prev_dq_state = ep_record.get("previous_end_state")
        was_dropped = tools.getr(ep_record,"dropped",0)
        if prev_dq_state is None:
            if was_dropped > 1 and current_dq_state in [ "DarkSpace", "AlreadyProcessing", "Excluded" ]:
                prev_dq_state = current_dq_state
            else:
                prev_dq_state = "First Scan"
        change = "%s -> %s"%(prev_dq_state,current_dq_state)
        ep_record.update({"change":change})

        # Add to DA list
        disco_data.append(ep_record)

    print(os.linesep,end="\r")
    # Build the report

    msg = os.linesep
    data = []

    for ddata in disco_data:

        if args.output_csv or args.output_file:

            data.append([
                        ddata.get("endpoint"),
                        ddata.get("hostname"),
                        ddata.get("list_of_names"),
                        ddata.get("list_of_endpoints"),
                        ddata.get("node_kind"),
                        ddata.get("os_type"),
                        ddata.get("os_version"),
                        ddata.get("os_class"),
                        ddata.get("disco_run"),
                        ddata.get("run_start"),
                        ddata.get("run_end"),
                        ddata.get("scan_start"),
                        ddata.get("scan_end"),
                        ddata.get("when_was_that"),
                        ddata.get("consistency"),
                        ddata.get("current_access"),
                        ddata.get("access_method"),
                        ddata.get("node_updated"),
                        ddata.get("reason_not_updated"),
                        ddata.get("end_state"),
                        ddata.get("previous_end_state"),
                        ddata.get("change"),
                        ddata.get("session_results_logged"),
                        ddata.get("last_credential"),
                        ddata.get("credential_name"),
                        ddata.get("credential_login"),
                        ddata.get("timestamp"),
                        ddata.get("da_id"),
                        ddata.get("prev_da_id"),
                        ddata.get("next_node_id"),
                        ddata.get("dropped")
                        ])
            headers = [
                        "endpoint",
                        "device_name",
                        "list_of_device_names",
                        "list_of_endpoints",
                        "node_kind",
                        "os_type",
                        "os_version",
                        "os_class",
                        "discovery_run",
                        "discovery_run_start",
                        "discovery_run_end",
                        "scan_start",
                        "scan_end",
                        "when_was_that",
                        "consistency",
                        "current_access",
                        "access_method",
                        "inferred_node_updated",
                        "reason_not_updated",
                        "end_state",
                        "previous_end_state",
                        "end_state_change",
                        "session_results_logged",
                        "last_credential",
                        "credential_name",
                        "credential_login",
                        "timestamp",
                        "da_id",
                        "prev_da_id",
                        "next_node_id",
                        "dropped"
                        
                    ]
        else:
            msg = "\nOnly showing limited details for table output. Output to CSV for full results.\n"
            data.append([
                        ddata.get("endpoint"),
                        ddata.get("hostname"),
                        ddata.get("when_was_that"),
                        ddata.get("node_updated"),
                        ddata.get("consistency"),
                        ddata.get("change"),
                        ddata.get("credential_name")
                        ])

            headers = [
                        "endpoint",
                        "device_name",
                        "when_was_that",
                        "inferred_node_updated",
                        "consistency",
                        "end_state_change",
                        "credential_name"
                    ]

    print(msg)

    try:
        # Try sorting all records by IP Endpoint
        data.sort( key = lambda k: (isinstance(tools.ip_or_string(k[0]), str), tools.ip_or_string(k[0])) )
    except TypeError as e:
        msg = "TypeError: Data output can't be hashed (cannot be sorted)\nError: %s" % str(e)
        print(msg)
        logger.error(msg)

    output.report(data, headers, args)

def tpl_export(search, query, dir, method, client, sysuser, syspass):
    tpldir = dir + "/tpl"
    if not os.path.exists(tpldir):
        os.makedirs(tpldir)
    files=0
    if method == "api":
        response = api.search_results(search, query)
        if type(response) == list and len(response) > 0:
            header, data = tools.json2csv(response)
            for row in data:
                filename = "%s/%s.tpl"%(tpldir,row[1])
                files+=1
                try:
                    f=open(filename, 'w', encoding="utf-8")
                    f.write(row[0])
                    f.close()
                except Exception as e:
                    logger.error("Problem with TPL: %s\n%s\n%s\nRow Data:\n%s"%(filename,e.__class__,str(e),row))
                    output.txt_dump(str(row),"%s/module_%s.tpl"%(tpldir,files))
        else:
            output.txt_dump("No results.","%s/tpl_export.txt"%tpldir)
    else:
        results = cli.run_query(client,sysuser,syspass,query)
        try:
            body = results.split("\n",1)[1]
            for line in body.split("\r\n"):
                files+=1
                if line:
                    try:
                        columns = [c.strip() for c in line.split(',')]
                        filename = "%s/%s.tpl"%(tpldir,columns[0])
                        columns.pop(0)
                        row = [ tools.dequote(columns) ]
                        logger.debug("Parsing row:\n%s"%row)
                        row2 = ''.join(row[0])
                        row3 = tools.dequote(row2)
                        newrow = row3.replace('""""','","')
                        logger.debug("NEW row:\n%s"%newrow)
                        try:
                            f=open(filename, 'w', encoding="utf-8")
                            f.write(newrow)
                            f.close()
                        except Exception as e:
                            logger.error("Problem with TPL: %s\n%s\n%s\nRow Data:\n%s"%(filename,e.__class__,str(e),row))
                            output.txt_dump(str(row),"%s/module_%s.tpl"%(tpldir,files))
                    except Exception as e:
                        logger.error("Problem with TPL:\n%s\n%s\nRow Data:\n%s"%(e.__class__,str(e),line))
                        # Dump
                        output.txt_dump(str(line),"%s/module_%s.tpl"%(tpldir,files))
        except Exception as e:
            logger.error("Problem parsing data:\n%s\n%s"%(e.__class__,str(e)))
            # Try dumping it instead
            output.txt_dump(results,"%s/tpl_export.txt"%tpldir)