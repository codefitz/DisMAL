# Discovery API report builder for DisMAL

import logging
import os

from . import api, tools, output, queries

logger = logging.getLogger("_builder_")

def get_credentials(entry):
    details = {}
    uuid = entry.get('uuid')
    index = entry.get('index')
    label = entry.get('label')
    enabled = entry.get('enabled')
    types = entry.get('types')
    usage = entry.get('usage')
    username = None
    if 'username' in entry:
        username = entry.get('username')
    elif 'snmp.v3.securityname' in entry:
        username = entry.get('snmp.v3.securityname')
    elif 'aws.access_key_id' in entry:
        username = entry.get('aws.access_key_id')
    elif 'azure.application_id' in entry:
        username = entry.get('azure.application_id')
    iprange = None
    exclusions = None
    if 'ip_range' in entry:
        iprange = entry.get('ip_range')
    if 'ip_exclusion' in entry:
        exclusions = entry.get('ip_exclusion')
    details = {"index":index,"uuid":uuid,"label":label,"username":username,"enabled":enabled,"iprange":iprange,"exclusions":exclusions,"types":types,"usage":usage}
    return details

def get_credential(twsearch, twcreds, args):
    uuid = args.excavate[1]
    msg = "\nCredential Lookup: %s" % uuid
    logger.info(msg)
    print(msg)
    print("---------------------------------------------------")

    vaultcreds = twcreds.get_vault_credential(uuid)
    print(vaultcreds.text)
    vaultcredJSON = api.get_json(vaultcreds)
    if 'code' in vaultcredJSON and vaultcredJSON['code'] == 404:
        label = vaultcredJSON['message']
        i = None
        found = False
        logger.debug("Vault lookup failed: %s"%(label))
    else:
        label = vaultcredJSON['label']
        i = vaultcredJSON['index']
        found = True
        logger.debug("Vault lookup succeeded: %s"%(label))

    qryJSON = {
                "query":
                """search SessionResult
                    where credential = '%s' show
                    (#Detail:Metadata:DiscoveryAccess:DiscoveryAccess.#Associate:Inference:InferredElement:.name or #Detail:Metadata:DiscoveryAccess:DiscoveryAccess.#DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.hostname) as 'device_name',
                    (kind(#Detail:Metadata:DiscoveryAccess:DiscoveryAccess.#Associate:Inference:InferredElement:) or #Detail:Metadata:DiscoveryAccess:DiscoveryAccess.inferred_kind or #Detail:Metadata:DiscoveryAccess:DiscoveryAccess.#DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.kind) as 'inferred_node',
                    #Detail:Metadata:DiscoveryAccess:DiscoveryAccess.endpoint as 'scanned_endpoint',
                    credential as 'credential',
                    success as 'success',
                    message as 'message',
                    friendlyTime(time_index) as 'date_time',
                    #Detail:Metadata:DiscoveryAccess:DiscoveryAccess.#id as 'node_id'""" % uuid
               }
    sessionResults = api.search_results(twsearch,qryJSON)

    diJSON = {
                "query":
                """search DeviceInfo where last_credential = '%s' or last_slave = '%s' or __preserved_last_credential = '%s'
                            ORDER BY hostname
                            show
                            (hostname or sysname) as 'device_name',
                            kind as 'inferred_node',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.endpoint as 'scanned_endpoint',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#id as 'da_node_id',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.reason as 'message',
                            method_success as 'success',
                            method_failure as 'failure',
                            friendlyTime(request_time) as 'date_time'""" % (uuid, uuid, uuid)
               }
    diResults = api.search_results(twsearch,diJSON)

    # Build the results
    
    data = []
    da_ids = []
    for result in sessionResults:
        logger.debug("Adding session result: %s"%(result))
        dn = tools.getr(result,'device_name',None)
        ifn = tools.getr(result,'inferred_node',None)
        se = tools.getr(result,'scanned_endpoint',None)
        m = tools.getr(result,'message',None)
        s = tools.getr(result,'success',None)
        dt = tools.getr(result,'date_time',None)
        id = tools.getr(result,'node_id',None)
        if id:
            da_ids.append(id)
            logger.debug("Adding DA ID to list: %s"%(id))
        data.append([ label, i, uuid, dn, ifn, se, m, s, dt ])

    for result in diResults:
        logger.debug("Checking DevicInfo result: %s"%(result))
        dn = tools.getr(result,'device_name',None)
        ifn = tools.getr(result,'inferred_node',None)
        se = tools.getr(result,'scanned_endpoint',None)
        m = tools.getr(result,'message',None)
        sx = tools.getr(result,'success',None)
        f = tools.getr(result,'failure',None)
        if sx:
            s = True
        elif f:
            s = False
        dt = tools.getr(result,'date_time',None)
        da_id = tools.getr(result,'da_node_id',None)
        if da_id and da_id in da_ids:
            logger.debug("DeviceInfo already logged in Session Result list: %s"%(da_id))
            continue # Do not log this result
        else:
            logger.debug("Adding DeviceInfo result: %s"%(da_id))
            data.append([ label, i, uuid, dn, ifn, se, m, s, dt ])

    output.report(data, [
                            "Credential",
                            "Index",
                            "UUID",
                            "Device Name",
                            "Inferred Node",
                            "Scanned Endpoint",
                            "Result/Reason",
                            "Successful",
                            "Access Time"
                        ], args, name="devices_with_cred")

    return found

def ordering(creds, search, args, apply):

    credlist = api.get_json(creds.get_vault_credentials)
    msg = "Analysing current credential order...\n"
    print(msg)
    logger.info(msg)

    if not credlist:
        msg = "Credential list could not be retrieved."
        print(msg)
        logger.error(msg)
        return

    cred_weighting = []
    
    for cred in credlist:
        weighting = 100
        label = cred.get('label')
        index = cred.get('index')
        #if not args.weigh:
        #    msg = '%s) %s' % (index, label)
        #    print(msg)
        #    logger.info(msg)
        
        # Weightings

        if "ip_range" in cred:
            ip_list = tools.range_to_ips(cred.get('ip_range'))
            for ip in ip_list:
                if ip == "0.0.0.0/0,::/0":
                    weighting = 4294967296 # Go to the bottom, (total no. IPs in the world)
                else:
                    weighting += 1
            logger.debug("Credential %s, IP Range: %s, Weighting Updated: %s"%(label,ip_list,weighting))

        if "ip_exclusion" in cred:
            exclude_list = tools.range_to_ips(cred.get('ip_exclusion'))
            for ip in exclude_list:
                if ip == "0.0.0.0/0,::/0":
                    weighting = -4294967296 # Will scan nothing - who would set this? No doubt there will be a customer out there!
                else:
                    weighting -= 1
            logger.debug("Credential %s, Exclude List: %s, Weighting Updated: %s"%(label,exclude_list,weighting))

        for type in cred['types']:
            if type == "aws" or type == "openstack" or type == "azure" or type == "web_basic" or type == "google":
                weighting += 1
                logger.debug("Credential %s, Type: %s, Weighting Updated: %s"%(label,type,weighting))
            elif type == "ssh" or type == "powershell":
                weighting += 2
                logger.debug("Credential %s, Type: %s, Weighting Updated: %s"%(label,type,weighting))
            elif type == "windows":
                weighting += 3
                logger.debug("Credential %s, Type: %s, Weighting Updated: %s"%(label,type,weighting))
            elif type == "vsphere" or type == "vcenter":
                weighting += 4
                logger.debug("Credential %s, Type: %s, Weighting Updated: %s"%(label,type,weighting))
            elif type == "snmp":
                weighting += 5
                logger.debug("Credential %s, Type: %s, Weighting Updated: %s"%(label,type,weighting))
            else:
                weighting += 6
                logger.debug("Credential %s, No Type, Weighting Updated: %s"%(label,weighting))

        if "ssh.key.set" in cred:
            ssh_key_set = cred.get('ssh.key.set')
            if ssh_key_set:
                weighting -= 1
                logger.debug("Credential %s, SSH Key Set, Weighting Updated: %s"%(label,weighting))

        if "snmp.version" in cred:
            snmp_version = cred.get('snmp.version')
            if snmp_version == "v3":
                weighting -= 1
                logger.debug("Credential %s, SNMPv3, Weighting Updated: %s"%(label,weighting))

        if "scopes" in cred:
            scopes = cred.get('scopes')
            if len(scopes) > 0:
                weighting -= 1
                logger.debug("Credential %s, in Scope, Weighting Updated: %s"%(label,weighting))

        ## Successes and Failures

        seshsux = api.search_results(search,"""
                                        search SessionResult where success
                                        and (slave = "%s" or credential = "%s")
                                        show (slave or credential) as cred_uuid, session_type process with countUnique(0)
                                        """ % (cred['uuid'],cred['uuid']))
        devinfosux = api.search_results(search,"""
                                        search DeviceInfo where method_success and __had_inference
                                        and (slave = "%s" or credential = "%s")
                                        and nodecount(traverse DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess traverse DiscoveryAccess:Metadata:Detail:SessionResult) = 0
                                        show (last_credential or last_slave) as cred_uuid,
                                        access_method as 'session_type'
                                        process with countUnique(0)
                                    """ % (cred['uuid'],cred['uuid']))
        credfails = api.search_results(search,"""
                                        search SessionResult where not success
                                        and (slave = "%s" or credential = "%s")
                                        show (slave or credential) as cred_uuid, session_type process with countUnique(0)
                                    """ % (cred['uuid'],cred['uuid']))
        
        for credsux in seshsux:
            weighting -= 1
            logger.debug("Credential %s, Counted Successful Session record, Weighting Updated: %s"%(label,weighting))
        for devsux in devinfosux:
            weighting -= 1
            logger.debug("Credential %s, Counted Successful DeviceInfo record, Weighting Updated: %s"%(label,weighting))
        for credfail in credfails:
            weighting += 1
            logger.debug("Credential %s, Counted Failed record, Weighting Updated: %s"%(label,weighting))

        cred_weighting.append({"uuid":cred.get('uuid'),"weighting":weighting})
        logger.debug("Credential %s, Final Weighting: %s"%(label,weighting))

    weighted = sorted(cred_weighting, key=lambda k: k['weighting'])
    logger.debug("Sorted weights: %s"%(weighted))
    index = 0

    for weighted_cred in weighted:
        weighted_cred.update({"index":index})
        index += 1
        logger.debug("Indexing: %s"%(weighted_cred))
    
    print("\nOrdering credentials...\n")

    data = []

    if apply:
        for weighted_cred in weighted:
            logger.debug("Updating: %s"%(weighted_cred))
            headers =  [ "New Index", "Credential" ]
            creds.update_cred(weighted_cred.get('uuid'),{"index":weighted_cred.get('index')})
    else:
        headers = [ "Credential", "Current Index", "Weighting", "New Index" ]
        for cred in credlist:
            for weighted_cred in weighted:
                logger.debug("Evaluating: %s ... %s"%(cred.get('uuid'),weighted_cred.get('uuid')))
                if cred.get('uuid') == weighted_cred.get('uuid'):
                    index = cred.get('index')
                    label = cred.get('label')
                    weight = weighted_cred.get('weighting')
                    new_index = weighted_cred.get('index')
                    msg = '%s: Index: %s, Weight: %s, New Index: %s' % (label, index, weight, new_index)
                    logger.info(msg)
                    data.append([label, index, weight, new_index])

    # Refresh
    credlist = api.get_json(creds.get_vault_credentials)
    msg = "New Credential Order:\n"
    print(msg)
    logger.info(msg)
    for cred in credlist:
        label = cred.get('label')
        index = cred.get('index')
        msg = '%s) %s' % (index, label)
        logger.info(msg)
        data.append([index, label])

    output.report(data, headers, args, name="suggested_cred_opt")

def get_device(search, credentials, args):
    dev = args.excavate[1]
    msg = "\nDevice Lookup: %s" % dev
    logger.info(msg)
    print(msg)

    devJSON = {
                "query":
                "search flags(no_segment) Host, NetworkDevice, Printer, SNMPManagedDevice, StorageDevice, ManagementController where name = '%s' show name, os, kind(#) as 'nodekind'" % dev
               }
    logger.debug("Executing device search query for %s: %s", dev, devJSON.get("query"))
    dev_resp = search.search(devJSON,format="object")
    logger.debug("Device search HTTP status: %s", getattr(dev_resp, "status_code", "n/a"))
    devResults = api.get_json(dev_resp)
    devTotal = 0
    if not devResults or not isinstance(devResults, list):
        logger.error("Failed to retrieve device lookup results")
    elif len(devResults) > 0 and isinstance(devResults[0], dict):
        devTotal = devResults[0].get('count', 0)
    logger.debug("Devices Total: %s"%(devTotal))

    if devTotal > 0:
        first = devResults[0]
        if isinstance(first, dict) and first.get('results'):
            os = first['results'][0].get('os')
            kind = first['results'][0].get('nodekind')
            msg = "\nNodekind: %s\nOperating System: %s\n" % (kind, os)
            logger.info(msg)
            print(msg)
    else:
        msg = "\nDevice not found!\n"
        logger.warning(msg)
        print(msg)

    qryJSON = {
                "query":
                """search flags(no_segment) Host, NetworkDevice, Printer, SNMPManagedDevice, StorageDevice, ManagementController where name = '%s'
                   traverse InferredElement:Inference:Associate:DiscoveryAccess
                   traverse DiscoveryAccess:Metadata:Detail:SessionResult
                   show
                   session_type as 'session_type',
                   credential as 'credential',
                   success as 'success',
                   message as 'message',
                   kind(#) as 'nodekind'""" % dev
               }
    sessionResults = api.search_results(search,qryJSON)
    total = len(sessionResults)
    failed = False
    logger.debug("Session Results Total: %s"%(total))
    if total == 0:
        # Alternate lookup
        qryJSON = {
                    "query":
                    """search flags(no_segment) Host, NetworkDevice, Printer, SNMPManagedDevice, StorageDevice, ManagementController where name = '%s'
                       traverse InferredElement:Inference:Associate:DiscoveryAccess
                       traverse DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo
                       show
                       last_access_method as 'session_type',
                       (last_credential or last_slave) as 'credential',
                       method_success as 'success',
                       'Credential ID Retrieved from DeviceInfo' as 'message',
                       kind(#) as 'nodekind'""" % dev
                   }
        sessionResults = api.search_results(search,qryJSON)
        total = len(sessionResults)
        logger.debug("Alternate Session Results Total: %s"%(total))
        if total == 0:
            failed = True
            if devTotal > 0:
                missing = "DiscoveryAccess may have aged out or no session results.\n"
            else:
                missing = "Device not found or DiscoveryAccess may have aged out.\n"

    # Build the results
    
    data = []
    if failed:
        logger.warning(missing)
        print(missing)

    uuid = None

    for result in sessionResults:
        logger.debug("Processing Result: %s"%(result))
        uuid = result['credential']
        status = None
        label = None
        username = None
        if uuid:
            vaultcreds = api.get_json(credentials.listCredentials(uuid))
            cred_detail = get_credentials(vaultcreds)
            logger.debug("Credential retrieved: %s"%(cred_detail))
            label = cred_detail.get('label')
            enabled = cred_detail.get('enabled')
            username = cred_detail.get('username')
            if enabled:
                status = "Enabled"
            else:
                status = "Disabled"
        st = result['session_type']
        c = label
        ci = uuid
        m = result['message']
        s = result['success']
        data.append([ st, c, ci, username, status, m, s ])

    output.report(data,
                        [
                            "Session Type",
                            "Credential",
                            "Credential ID",
                            "Credential Login",
                            "Status",
                            "Message",
                            "Successful"
                            ], args, name="device")

def scheduling(vault, search, args):
    ## Schedules compared to runs
    print("\nScheduled Runs with Credentials")
    print("-------------------------------")
    logger.info("Running Schedules Report...")
    msg = None

    vaultcreds = api.get_json(vault.get_vault_credentials)
    if not vaultcreds or not isinstance(vaultcreds, list):
        logger.error("Vault credentials could not be retrieved")
        return

    credential_ips = []
    timer_count = 0
    for cred in vaultcreds:
        timer_count = tools.completage("Getting credentials...", len(vaultcreds), timer_count)
        logger.debug("Getting detail for credential %s"%cred)
        detail = get_credentials(cred)
        list_of_ips = []
        uuid = detail.get('uuid')
        label = detail.get('label')
        if detail.get("iprange"):
            list_of_ips = tools.range_to_ips(detail.get('iprange'))
            logger.debug("%s IP Range: %s"%(cred,list_of_ips))
        credential_ips.append([uuid,list_of_ips,label])
    print(os.linesep,end="\r")

    logger.debug("Executing excludes query: %s", queries.excludes)
    excludes_resp = search.search(queries.excludes,format="object")
    logger.debug("Excludes search HTTP status: %s", getattr(excludes_resp, "status_code", "n/a"))
    excludes = api.get_json(excludes_resp)
    if not excludes or not isinstance(excludes, list):
        logger.error("Failed to retrieve excludes")
        return
    if len(excludes) == 0:
        logger.error("No excludes returned")
        return

    # Build the results

    results = excludes[0]
    if not isinstance(results, dict) or 'results' not in results:
        logger.error("Invalid excludes result structure")
        return
    data = []
    exclude_ips = []

    timer_count = 0
    for result in results.get('results'):
        timer_count = tools.completage("Processing excludes...", len(results.get('results')), timer_count)
        logger.debug("Processing Exclude result %s"%(result))
        r = result['Scan_Range'][0]
        fr = result.get('Scan_Range')
        i = result.get('ID')
        sc = result.get('Label')
        dr = result.get('Date_Rules')
        list_of_ips = tools.range_to_ips(r)
        exclude_ips.append([i,list_of_ips])

        in_exclude = []

        for run in exclude_ips:
            logger.debug("Processing Exclude Run %s"%(run))
            run_ips = run[1]
            for credential in credential_ips:
                cred_ips = credential[1]
                for cred_ip in cred_ips:
                    if cred_ip in run_ips:
                        logger.debug("Credential IP %s found in Exclude run"%(cred_ip))
                        in_exclude.append("%s (%s)" % (credential[2],credential[0]))
        #in_exclude = list(dict.fromkeys(in_exclude)) # sort and unique
        in_exclude = tools.sortlist(in_exclude)
        logger.debug("Excludes:%s"%(in_exclude))

        if args.output_csv or args.output_file:
            msg = os.linesep
            data.append([ sc, "Exclude Range", i, fr, None, dr, in_exclude ])
        else:
            msg = "\nOnly showing ranges, credential counts for tables output. Output to CSV for credential list.\n"
            data.append([ sc, "Exclude Range", i, len(fr), None, dr, len(in_exclude) ])
    if timer_count > 0:
        print(os.linesep,end="\r")
    
    logger.debug("Executing scan range query: %s", queries.scanrange.get("query", queries.scanrange))
    scan_resp = search.search(queries.scanrange,format="object")
    logger.debug("Scan range search HTTP status: %s", getattr(scan_resp, "status_code", "n/a"))
    scan_ranges = api.get_json(scan_resp)
    if not scan_ranges or not isinstance(scan_ranges, list):
        logger.error("Failed to retrieve scan ranges")
        return
    if len(scan_ranges) == 0:
        logger.error("No scan ranges returned")
        return

    # Build the results

    results = scan_ranges[0]
    if not isinstance(results, dict) or 'results' not in results:
        logger.error("Invalid scan range result structure")
        return

    range_ips = []
    timer_count = 0
    for result in results['results']:
        timer_count = tools.completage("Processing runs...", len(results['results']), timer_count)
        logger.debug("Processing Scan range:%s"%(result))
        r = result['Scan_Range'][0]
        fr = result.get('Scan_Range')
        i = result.get('ID')
        sc = result.get('Label')
        sl = result.get('Level')
        dr = result.get('Date_Rules')
        list_of_ips = tools.range_to_ips(r)
        range_ips.append([i,list_of_ips])

        in_run = []

        for run in range_ips:
            logger.debug("Processing Run %s"%(run))
            run_ips = run[1]
            for credential in credential_ips:
                cred_ips = credential[1]
                for cred_ip in cred_ips:
                    if cred_ip in run_ips:
                        in_run.append("%s (%s)" % (credential[2],credential[0]))
                        logger.debug("Credential IP %s found in run"%(cred_ip))
                    elif cred_ip == "0.0.0.0/0,::/0":
                        in_run.append("%s (%s)" % (credential[2],credential[0]))
                        logger.debug("No range specified - scan all - %s"%(cred_ip))
        in_run = tools.sortlist(in_run)
        logger.debug("Runs:%s"%(in_run))
        
        if args.output_csv or args.output_file:
            msg = os.linesep
            data.append([ sc, "Scan Range", i, fr, sl, dr, in_run ])
        else:
            msg = "\nOnly showing ranges, credential counts for tables output. Output to CSV for credential list.\n"
            data.append([ sc, "Scan Range", i, len(fr), sl, dr, len(in_run) ])
    print(os.linesep,end="\r")

    # sort data by index field
    data.sort(key=lambda x: x[2])

    if msg:
        print(msg)

    output.report(data, [ "Name", "Type", "Range ID", "Ranges", "Scan Level", "When", "Credentials" ], args, name="schedules")

def unique_identities(search):

    logger.info("Running: Unique Identities report...")

    # Use a larger page size for these potentially large queries to reduce
    # the number of round trips to the Discovery API.
    devices = api.search_results(search, queries.deviceInfo, page_size=1000)
    da_results = api.search_results(search, queries.da_ip_lookup, page_size=1000)

    # list of unique endpoints
    unique_endpoints = {da.get('ip') for da in da_results if da.get('ip')}
    for endpoint in unique_endpoints:
        logger.debug("Unique Endpoint: %s" % endpoint)

    # map of endpoint to sets of ips and names
    endpoint_map = {ep: {"ips": set(), "names": set()} for ep in unique_endpoints}

    print(os.linesep, end="\r")
    timer_count = 0
    for device in devices:
        timer_count = tools.completage("Processing", len(devices), timer_count)
        endpoint = device.get('DA_Endpoint')
        if endpoint not in unique_endpoints:
            continue

        list_of_ips = [endpoint]
        list_of_ips = tools.list_of_lists(device, 'Chosen_Endpoint', list_of_ips)
        list_of_ips = tools.list_of_lists(device, 'Discovered_IP_Addrs', list_of_ips)
        list_of_ips = tools.list_of_lists(device, 'Inferred_All_IP_Addrs', list_of_ips)
        list_of_ips = tools.list_of_lists(device, 'NIC_IPs', list_of_ips)

        list_of_names = []
        list_of_names = tools.list_of_lists(device, 'Device_Sysname', list_of_names)
        list_of_names = tools.list_of_lists(device, 'Device_Hostname', list_of_names)
        list_of_names = tools.list_of_lists(device, 'Device_FQDN', list_of_names)
        list_of_names = tools.list_of_lists(device, 'Inferred_Name', list_of_names)
        list_of_names = tools.list_of_lists(device, 'Inferred_Hostname', list_of_names)
        list_of_names = tools.list_of_lists(device, 'Inferred_FQDN', list_of_names)
        list_of_names = tools.list_of_lists(device, 'Inferred_Sysname', list_of_names)
        list_of_names = tools.list_of_lists(device, 'NIC_FQDNs', list_of_names)

        msg = "endpoint %s, list_of_names: %s, list_of_ips: %s" % (endpoint, list_of_names, list_of_ips)
        logger.debug(msg)

        try:
            if len(list_of_ips) > 0:
                list_of_ips = tools.sortlist(list_of_ips)
            if len(list_of_names) > 0:
                list_of_names = tools.sortlist(list_of_names)

            for ip in list_of_ips:
                if ip in endpoint_map:
                    endpoint_map[ip]["ips"].update(list_of_ips)
                    endpoint_map[ip]["names"].update(list_of_names)
                    logger.debug("Updated mapping for %s" % ip)
        except TypeError as e:
            msg = "TypeError: list_of_ips can't be hashed\n%s" % str(e)
            print("__endpoint__", endpoint)
            print("list_of_ips", list_of_ips)
            print(msg)
            logger.error(msg)
        except Exception as e:
            msg = "Error: list_of_ips could not be processed\n%s" % str(e)
            print("__endpoint__", endpoint)
            print("list_of_ips", list_of_ips)
            print(msg)
            logger.error(msg)

    unique_identities = []
    for endpoint in sorted(endpoint_map.keys()):
        ip_list = list(endpoint_map[endpoint]["ips"])
        name_list = list(endpoint_map[endpoint]["names"])
        if len(ip_list) > 0:
            ip_list = tools.sortlist(ip_list, "None")
            logger.debug("Sorted IP List: %s" % ip_list)
        if len(name_list) > 0:
            name_list = tools.sortlist(name_list, "None")
            logger.debug("Sorted Name List: %s" % name_list)
        unique_identities.append({
            "originating_endpoint": endpoint,
            "list_of_ips": ip_list,
            "list_of_names": name_list,
        })
    print(os.linesep)
    return unique_identities

def overlapping(tw_search, args):

    print("\nScheduled Scans Overlapping")
    print("---------------------------")
    logger.info("Running: Overlapping Report...")

    logger.debug("Executing scan range query: %s", queries.scanrange.get("query", queries.scanrange))
    scan_resp = tw_search.search(queries.scanrange,format="object")
    logger.debug("Scan range search HTTP status: %s", getattr(scan_resp, "status_code", "n/a"))
    scan_ranges = api.get_json(scan_resp)
    if not scan_ranges or not isinstance(scan_ranges, list):
        logger.error("Failed to retrieve scan ranges")
        return
    if len(scan_ranges) == 0:
        logger.error("No scan ranges returned")
        return

    # Build the results

    results = scan_ranges[0]
    if not isinstance(results, dict) or 'results' not in results:
        logger.error("Invalid scan range result structure")
        return

    range_ips = []
    full_range = []
    scheduled_ip_list = []
    matched_runs = []

    timer_count = 0
    for result in results.get('results'):
        timer_count = tools.completage("Gathering Results...", len(results.get('results')), timer_count)
        logger.debug("Scan Result:\n%s"%(result))
        for scan_range in result.get('Scan_Range'):
            r = scan_range
            i = result.get('ID')
            l = result.get('Label')
            list_of_ips = tools.range_to_ips(r)
            range_ips.append([i,list_of_ips,l])
            full_range.append([i,list_of_ips,l])
            logger.debug("List of IPs:%s"%(list_of_ips))

        runs = []

        for run in range_ips:
            logger.debug("Processing run:%s"%(run))
            run_ips = run[1]
            run_id = run[0]
            label = run[2]
            for ip in run_ips:
                logger.debug("Processing IP:%s"%(ip))
                scheduled_ip_list.append(str(ip))
                scheds = [ label ]
                matched = {}
                for range in full_range:
                    logger.debug("Processing Range:%s"%(range))
                    range_ip = range[1]
                    range_run = range[0]
                    range_label = range[2]
                    logger.debug("IP: %s, Range_IP: %s, Range_Run: %s, Run_ID: %s"%(ip,range_ip,range_run,run_id))
                    if ip in range_ip and range_run != run_id:
                        scheds.append(range_label)
                        scheds.sort()
                        matched = {"ip":ip,"runs":scheds}
                if matched:
                    runs.append(matched)

        # Unique
        matched_runs = tools.sortdic(runs)
        logger.debug("Matched Runs: %s"%(matched_runs))

    logger.debug("Executing excludes query: %s", queries.excludes)
    excludes_resp = tw_search.search(queries.excludes,format="object")
    logger.debug("Excludes search HTTP status: %s", getattr(excludes_resp, "status_code", "n/a"))
    excludes = api.get_json(excludes_resp)
    if not excludes or not isinstance(excludes, list):
        logger.error("Failed to retrieve excludes")
        return
    if len(excludes) == 0:
        logger.error("No excludes returned")
        return

    e = excludes[0]
    if not isinstance(e, dict) or 'results' not in e:
        logger.error("Invalid excludes result structure")
        return
    for result in e.get('results'):
        r = result['Scan_Range'][0]
        list_of_ips = tools.range_to_ips(r)
        logger.debug("List of Exclude Ips to be added to Scheduled_ip_list: %s"%(list_of_ips))
        for ip in list_of_ips:
            scheduled_ip_list.append(str(ip))

    scheduled_ip_list = tools.sortlist(scheduled_ip_list)

    # Check for missing IPs
    missing_ips = []
    ip_schedules = api.search_results(tw_search,queries.ip_schedules)
    for ip_sched in ip_schedules:
        endpoint = tools.getr(ip_sched,'endpoint')
        if endpoint not in scheduled_ip_list:
            missing_ips.append(endpoint)
            logger.debug("Missing endpoint: %s"%(endpoint))
    missing_ips = tools.sortlist(missing_ips)

    data=[]

    for matching in matched_runs:
        if len(matching.get("runs")) > 1:
            data.append([ matching.get("ip"), matching.get("runs") ])
            logger.debug("Matching Run: %s,%s"%(matching.get("ip"),matching.get("runs")))

    if len(data) == 0:
        msg = "No overlap between ranges."
        logger.info(msg)
        print(msg)
    matches = len(data)
    logger.debug("Matches:\n%s"%(matches))

    for missing_ip in missing_ips:
        data.append([ missing_ip, "Endpoint has previous DiscoveryAccess, but not currently scheduled." ])

    if len(data) == matches:
        msg = "No missing IPs in ranges."
        logger.info(msg)
        print(msg)

    output.report(data, [ "IP Address", "Scan Schedules" ], args, name="overlapping_ips")

def get_scans(results, list_of_ranges):
    scan_ranges = []
    for result in results:
        msg = "Result: %s" % result
        logger.debug(msg)
        ranges = result.get('Scan_Range')
        if ranges and isinstance(ranges, list):
            for scan_range in ranges:
                msg = "Scan Range: %s" % scan_range
                logger.debug(msg)
                r = scan_range
                l = result.get('Label')
                list_of_ips = tools.range_to_ips(r)
                msg = "List of IPs: %s" % list_of_ips
                logger.debug(msg)
                for ip in list_of_ranges:
                    msg = "Checking IP %s in list_of_ips" % ip
                    logger.debug(msg)
                    if ip in list_of_ips:
                        scan_ranges.append(l)
                        msg = "IP %s added to scheduled_scans" % ip
                        logger.debug(msg)
                    elif ip == "0.0.0.0/0,::/0":
                        scan_ranges.append(l)
                        msg = "IP %s added to scheduled_scans" % ip
                        logger.debug(msg)
    scan_ranges = tools.sortlist(scan_ranges)
    return scan_ranges