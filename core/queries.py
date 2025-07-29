# Discovery API queries for DisMAL

credential_success = """
                            search SessionResult where success
                            show (slave or credential) as 'UUID',
                            session_type as 'Session_Type'
                            processwith countUnique(1,0)
                        """
credential_failure = """
                            search SessionResult where not success
                            show (slave or credential) as 'UUID',
                            session_type as 'Session_Type'
                            processwith countUnique(1,0)
                        """
deviceinfo_success = """
                          search DeviceInfo where method_success and __had_inference
                          and nodecount(traverse DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess
                                            traverse DiscoveryAccess:Metadata:Detail:SessionResult) = 0
                          show (last_credential or last_slave) as 'UUID',
                          access_method as 'Session_Type'
                          process with countUnique(1,0)
                       """
deviceInfo = {"query":
                        """
                            search DeviceInfo
                            ORDER BY hostname
                            show
                            hostname as 'Device_Hostname',
                            hash(hostname) as 'Hashed_Device_Hostname',
                            os_type as 'OS_Type',
                            sysname as 'Device_Sysname',
                            device_type as 'Device_Type',
                            fqdn as 'Device_FQDN',
                            method_success as 'M_Success',
                            method_failure as 'M_Failure',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#::InferredElement:.name as 'Inferred_Name',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#::InferredElement:.hostname as 'Inferred_Hostname',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#::InferredElement:.local_fqdn as 'Inferred_FQDN',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#::InferredElement:.sysname as 'Inferred_Sysname',
                            kind as 'Kind',
                            (last_credential or last_slave or __preserved_last_credential) as 'Last_Credential',
                            (last_access_method or __preserved_last_access_method) as 'Last_Access_Method',
                            friendlyTime(#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.starttime) as 'DA_Start',
                            friendlyTime(#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.endtime) as 'DA_End',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.result as 'DA_Result',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.endpoint as 'DA_Endpoint',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.end_state as 'DA_End_State',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#DiscoveryAccess:Endpoint:Endpoint:Endpoint.endpoint as 'Chosen_Endpoint',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DiscoveredIPAddressList.#List:List:Member:DiscoveredIPAddress.ip_addr as 'Discovered_IP_Addrs',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#::InferredElement:.__all_ip_addrs as 'Inferred_All_IP_Addrs',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#::InferredElement:.#DeviceWithInterface:DeviceInterface:InterfaceOfDevice:NetworkInterface.ip_addr as 'NIC_IPs',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#::InferredElement:.#DeviceWithInterface:DeviceInterface:InterfaceOfDevice:NetworkInterface.fqdns as 'NIC_FQDNs',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#Member:List:List:DiscoveryRun.label as 'Discovery_Run',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess._last_marker as 'Last_Marker',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess._first_marker as 'First_Marker',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess._last_interesting as 'Last_Interesting',
                            #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.__had_inference as 'Had_Inference'
                            process with unique()
                        """
                }
da_ip_lookup = {
                    "query":
                            """
                                search DiscoveryAccess
                                show
                                endpoint as 'ip',
                                hash(endpoint) as 'Hashed_Endpoint',
                                #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.hostname as 'device_hostname',
                                (#DiscoveryAccess:Metadata:Detail:SessionResult.credential and success
                                    or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_credential
                                        or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_slave
                                            or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.__preserved_last_credential) as 'last_credential',
                                result as 'da_result',
                                end_state as 'da_end_state',
                                friendlyTime(starttime) as 'start_time',
                                friendlyTime(endtime) as 'end_time',
                                #Member:List:List:DiscoveryRun.label as 'discovery_run',
                                _last_marker as 'last_marker',
                                _first_marker as 'first_marker',
                                _last_interesting as 'last_interesting',
                                __had_inference as 'had_inference',
                                best_ip_score as 'best_ip_score',
                                (#DiscoveryAccess:Metadata:Detail:SessionResult.success or access_success) as 'access_success',
                                access_failure as 'access_failure',
                                message as 'message',
                                (#DiscoveryAccess:Metadata:Detail:SessionResult.session_type
                                    or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.access_method
                                        or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_access_method) as 'access_method',
                                (kind(#Associate:Inference:InferredElement:)
                                    or inferred_kind
                                        or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.kind) as 'inferred_node',
                                #::InferredElement:.__all_ip_addrs as 'Inferred_All_IP_Addrs',
                                #::InferredElement:.#DeviceWithInterface:DeviceInterface:InterfaceOfDevice:NetworkInterface.ip_addr as 'NIC_IPs'
                            """
                }
excludes = {"query": """search in '_System' ExcludeRange
                            show
                            exrange_id as 'ID',
                            name as 'Label',
                            range_strings as 'Scan_Range',
                            recurrenceDescription(schedule) as 'Date_Rules'"""}
scanrange = {
                "query":
                """
                search ScanRange where scan_type = 'Scheduled'
                show
                range_id as 'ID',
                label as 'Label',
                (range_strings or provider) as 'Scan_Range',
                scan_level as 'Level',
                recurrenceDescription(schedule) as 'Date_Rules'
                """
               }
last_disco = {
            "query":"""
                    search DiscoveryAccess where endtime
                    show
                    #id as "DA_ID",
                    #Next:Sequential:Previous:DiscoveryAccess.#id as "Previous_DA_ID",
                    #Previous:Sequential:Next:DiscoveryAccess.#id as "Next_DA_ID",
                    endpoint as 'Endpoint',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.hostname as 'Hostname',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.os_type as 'OS_Type',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.os_class as 'OS_Class',
                    #Member:List:List:DiscoveryRun.label as 'Discovery_Run',
                    friendlyTime(#Member:List:List:DiscoveryRun.starttime) as 'Run_Starttime',
                    friendlyTime(#Member:List:List:DiscoveryRun.endtime) as 'Run_Endtime',
                    friendlyTime(discovery_starttime) as 'Scan_Starttime',
                    friendlyTime(discovery_endtime) as 'Scan_Endtime',
                    whenWasThat(discovery_endtime) as 'When_Last_Scan',
                    (#DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_access_method in ['windows', 'rcmd']
                        and #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_slave
                            or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.probed_os and 'Probe'
                                or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_access_method) as 'Current_Access',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.os_version as 'OS_Version',
                    (nodecount(traverse DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo
                        traverse flags(include_destroyed) Primary:Inference:InferredElement: where not destroyed(#)) > 0) as 'Host_Node_Updated',
                    end_state as 'End_State',
                    #Next:Sequential:Previous:DiscoveryAccess.end_state as "Previous_End_State",
                    reason as 'Reason_Not_Updated',
                    (nodecount(traverse DiscoveryAccess:Metadata:Detail:SessionResult where not provider) > 0) as 'Session_Results_Logged',
                    (kind(#Associate:Inference:InferredElement:)
                        or inferred_kind
                            or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.kind) as 'Node_Kind',
                    (#DiscoveryAccess:Metadata:Detail:SessionResult.credential and success
                                    or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_credential
                                        or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_slave
                                            or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.__preserved_last_credential) as 'Last_Credential',
                    result as 'Result',
                    _last_marker as 'Last_Marker',
                    _first_marker as 'First_Marker',
                    _last_interesting as 'Last_Interesting',
                    __had_inference as 'Had_Inference',
                    best_ip_score as 'Best_IP_Score',
                    (#DiscoveryAccess:Metadata:Detail:SessionResult.success or access_success) as 'Access_Success',
                    access_failure as 'Access_Failure',
                    message as 'Message',
                    (#DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.access_method
                        or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.last_access_method
                            or #DiscoveryAccess:Metadata:Detail:SessionResult.session_type) as 'Access_Method',
                    #::InferredElement:.__all_ip_addrs as 'Inferred_All_IP_Addrs',
                    #::InferredElement:.#DeviceWithInterface:DeviceInterface:InterfaceOfDevice:NetworkInterface.ip_addr as 'NIC_IPs'
"""
}
ip_schedules = """search DiscoveryAccess
                    show endpoint,
                    nodecount(traverse Member:List:List:DiscoveryRun where scan_type = 'Scheduled') as 'schedules'
                    process with unique()"""

dropped_endpoints = """
                    search DroppedEndpoints
                    show explode endpoints as 'Endpoint',
                    reason as 'Reason_Not_Updated',
                    __reason as 'End_State',
                    friendlyTime(starttime) as 'Start',
                    friendlyTime(endtime) as 'End',
                    whenWasThat(endtime) as 'When_Last_Scan',
                    #EndpointRange:EndpointRange:DiscoveryRun:DiscoveryRun.label as "Run"
                """

sensitive_data = """
                        search DiscoveredProcess
                        where ((args has subword 'user' or args has substring 'username')
                            and (args has subword 'pass' or args has substring 'password'))
                        or (args matches regex '(?i)\\s-u(\\s+|=)\\S+'
                            and args matches regex '(?i)\\s-p(\\s+|=)\\S+')
                        show
                        #Member:List:List:ProcessList.#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.hostname as 'Host',
                        #Member:List:List:ProcessList.#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.endpoint as 'Endpoint',
                        username,
                        cmd,
                        args,
                        (extract(args, regex '(?i)(user(name)?.*?\\S+)', raw '\\1')
                            or extract(args, regex '(?i)(-u.*?\\S+)', raw '\\1')) as 'Matched Username String',
                        extract(args, regex '(?i)(password.*?\\S+|\\s-p.*?\\S+)', raw '\\1') as 'Matched Password String'
                    """

tpl_export = """
                    search KnowledgeUpload
                    where not origin = 'TKU'
                    traverse Upload:UploadContents:UploadItem:PatternModule
                    show
                    name,
                    content
                """

eca_error = """
                    search ECAError
                    show
                    summary,
                    action_name,
                    rule_name,
                    traceback,
                    #:::DiscoveryAccess.starttime as 'Discovery Start Time'
               """

scan_ranges = """
                    search ScanRange
                    where not scan_type = 'Snapshot'
                    show
                    label as 'Label',
                    range_strings as 'IP Range',
                    scan_level as 'Level',
                    recurrenceDescription(schedule) as 'Date Rules',
                    created_by as 'User',
                    created_time as 'Created',
                    enabled as 'enabled'
                 """

exclude_ranges = """
                        search in '_System' ExcludeRange
                        show
                        name as 'Label',
                        range_strings as 'Range',
                        recurrenceDescription(schedule) as 'Date Rules',
                        description as 'Description',
                        fullFoundationName(created_by) as 'User'
                    """

id_change = """
                    search flags(find_relationships) EndpointIdentity
                    order by endpoint, creationTime(#) desc
                    show
                    time(creationTime(#)) as 'Identity Change Time',
                    endpoint as 'Endpoint',
                    kind(#:Previous:.#) as 'Previous Kind',
                    nodeLink(#:Previous:.#InferredElement:Inference:Primary:DeviceInfo.#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#, time(#:Previous:.#InferredElement:Inference:Primary:DeviceInfo.#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.starttime)) as 'Last Update of Previous Identity',
                    nodeLink(#:Previous:.#, #:Previous:.name) as 'Previous Identity',
                    nodeLink(#:Next:.#, #:Next:.name) as 'Next Identity',
                    nodeLink(#:Next:.#InferredElement:Inference:Primary:DeviceInfo.#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#, time(#:Next:.#InferredElement:Inference:Primary:DeviceInfo.#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.starttime)) as 'Last Update of Next Identity',
                    kind(#:Next:.#) as 'Next Kind'
               """

open_ports = """
                    search DiscoveredListeningPort
                    with
                    ((local_port  = 161) and 'SNMP'
                    or (local_port  = 21) and 'FTP'
                    or (local_port  = 22) and 'SSH'
                    or (local_port  = 23) and 'Telnet'
                    or (local_port  = 25) and 'SMTP'
                    or (local_port  = 53) and 'DNS'
                    or (local_port  = 69) and 'TFTP'
                    or (local_port  = 110) and 'POP3'
                    or (local_port  = 119) and 'NNTP'
                    or (local_port  = 137) and 'NetBios'
                    or (local_port  = 143) and 'IMAP'
                    or (local_port  and 'other')) as openports
                    where @openports not in 'other'
                    show
                    #Member:List:List:NetworkConnectionList.#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.#DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:HostInfo.#Primary:Inference:InferredElement:Host.name as 'hostname',
                    #Member:List:List:NetworkConnectionList.#DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess.endpoint as 'endpoint',
                    @openports as 'Default Service Port Open'
                    process with countUnique(0)
                """
host_utilisation = """
                        search Host where type <> 'Hypervisor'
                        show
                        hostname,
                        hash(hostname) as 'hashed_hostname',
                        os,
                        virtual,
                        cloud,
                        #InferredElement:Inference:Associate:DiscoveryAccess.endpoint as 'Endpoint',
                        nodecount(traverse :::SoftwareInstance) as 'Running Software Instances',
                        nodecount(traverse :::CandidateSoftwareInstance) as 'Candidate Software Instances',
                        nodecount(traverse :::DiscoveryAccess where _last_marker traverse :::ProcessList traverse :::DiscoveredProcess) as 'Running Processes',
                        nodecount(traverse :::DiscoveryAccess where _last_marker traverse :::ServiceList traverse :::DiscoveredService where state = 'RUNNING') as 'Running Services (Windows)'
                      """

orphan_vms = """
                    search Host
                    where virtual
                    and nodecount(traverse ContainedHost:HostContainment:HostContainer:VirtualMachine) = 0
                    order by name
                    show
                    hostname,
                    hash(hostname) as 'hashed_hostname',
                    os,
                    virtual,
                    cloud,
                    #InferredElement:Inference:Associate:DiscoveryAccess.endpoint as 'endpoint',
                    vendor,
                    vm_class
                """

audit = """
            search in 'Audit' UserEventAuditRecord
            where not (user matches '^\[\w+\]$')
            show
            event,
            event_group,
            user,
            when,
            msg,
            ip_addr as 'Ip Addr'
           """

near_removal = """
                    search flags(no_segment) Host, StorageSystem, Printer
                    with value(getOption('MIN_FAILED_ACCESSES_BEFORE_DESTROY') + age_count) as scans,
                    value(abs(last_update_success) / 10000000) as lus,
                    value(currentTime() / 10000000 - getOption('MIN_SECONDS_SINCE_ACCESS_SUCCESS_BEFORE_DESTROY') + 2 * 24 * 3600) as time_threshold,
                    value((getOption('MIN_SECONDS_SINCE_ACCESS_SUCCESS_BEFORE_DESTROY') + abs(last_update_success) / 10000000 - currentTime() / 10000000) / 3600) as time_to_doom
                    where @scans < 3
                    show
                    kind(#) as 'CI Type',
                    type as 'Product/Class',
                    name as 'Name',
                    hash(name) as 'Hashed Name',
                    (os_type or instance) as 'Instance',
                    (#InferredElement:Inference:Associate:DiscoveryAccess.endpoint or 'DDD Aged Out') as 'Last Successful IP',
                    whenWasThat(last_update_success) as 'Last Successful Scan',
                    last_update_success as 'Last Successful Scan Date',
                    age_count * -1 as 'Consecutive Scan Failures',
                    (@scans > 0 and @time_to_doom > 0 and #'%d scans, %d hours'(@scans,@time_to_doom)
                    or @scans > 0 and #'%d scans'(@scans) or @time_to_doom > 0 and #'%d hours'(@time_to_doom)
                    or 'Next unsuccessful scan') as 'Removal Eligibility'
                  """

removed = """
                search flags(include_destroyed, exclude_current, no_segment) Host, Printer, StorageSystem
                with kind(#Previous:::.#) as pk,
                value(#Previous:EndpointIdentity:Next:.name) as ph,
                kind(#Next:::.#) as nk,
                value(#Next:EndpointIdentity:Previous:.name) as nh
                where not type matches 'Windows Desktop'
                and destructionTime(#) > (currentTime() - 7*24*3600*10000000)
                show
                kind(#) as 'kind',
                name as 'name',
                hash(name) as 'hashed_name',
                os as 'os',
                unique((#InferredElement:Inference:Associate:DiscoveryAccess.endpoint or 'DDD Aged Out')) as 'Last Successful IP',
                whenWasThat(last_update_success) as 'Last Successful Scan',
                fmt('%s (%s)', @ph, @pk) as 'Previous Found',
                fmt('%s (%s)', @nh, @nk) as 'Next Found',
                @nk as 'next kind', @pk as 'prv kind',
                time(destructionTime(#)) as 'Destroyed When'
             """

os_lifecycle = """
                    search Host
                    where #ElementWithDetail:SupportDetail:OSDetail:SupportDetail.retirement_date
                        or #ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_support_date
                            or #ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_ext_support_date
                    show
                    name,
                    (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.retirement_date
                        and formatTime(#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.retirement_date, '%Y-%m-%d')) as 'End of Life',
                    (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_support_date
                        and formatTime(#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_support_date, '%Y-%m-%d')) as 'End of Support',
                    (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_ext_support_date
                        and formatTime(#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_ext_support_date, '%Y-%m-%d')) as 'End of Ext Support',
                    (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_ext_support_date
                        and (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_ext_support_date < currentTime()
                        and 'EOES Exceeded')
                        or #ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_support_date
                            and (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_support_date < currentTime()
                            and 'EOS Exceeded') or #ElementWithDetail:SupportDetail:OSDetail:SupportDetail.retirement_date
                            and (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.retirement_date < currentTime()
                            and 'EOL Exceeded')
                            or (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.retirement_date
                                and (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.retirement_date < currentTime() + 182 * 864000000000
                                and 'EOL less than 6 months away')
                                or #ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_support_date
                                    and (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_support_date < currentTime() + 182 * 864000000000
                                    and 'EOS less than 6 months away')
                                    or #ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_ext_support_date
                                        and (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_ext_support_date < currentTime() + 182 * 864000000000
                                        and 'EOES less than 6 months away'))
                                        or (#ElementWithDetail:SupportDetail:OSDetail:SupportDetail.retirement_date
                                            and 'EOL more than 6 months away'
                                            or #ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_support_date
                                                and 'EOS more than 6 months away'
                                                or #ElementWithDetail:SupportDetail:OSDetail:SupportDetail.end_ext_support_date
                                                    and 'EOES more than 6 months away')) as 'Lifecycle Risk',
                    taxonomy 'summary_no_name'
                  """

software_lifecycle = """
                            search SoftwareInstance
                            where
                            #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                                or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                                    or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                            show
                            type,
                            product_version,
                            (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                                and formatTime(#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date, '%Y-%m-%d')) as 'End of Life',
                            (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                                and formatTime(#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date, '%Y-%m-%d')) as 'End of Support',
                            (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                                and formatTime(#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date, '%Y-%m-%d')) as 'End of Ext Support',
                            (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                                and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date < currentTime()
                                and 'EOES Exceeded')
                                or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                                    and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date < currentTime()
                                    and 'EOS Exceeded')
                                    or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                                        and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date < currentTime()
                                        and 'EOL Exceeded')
                                        or (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                                            and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date < currentTime() + 182 * 864000000000
                                            and 'EOL less than 6 months away')
                                            or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                                                and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date < currentTime() + 182 * 864000000000
                                                and 'EOS less than 6 months away')
                                                or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                                                    and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date < currentTime() + 182 * 864000000000
                                                    and 'EOES less than 6 months away'))
                                                    or (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                                                        and 'EOL more than 6 months away'
                                                        or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                                                            and 'EOS more than 6 months away'
                                                            or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                                                                and 'EOES more than 6 months away')) as 'Lifecycle Risk',
                            #:HostedSoftware:Host:Host.name as 'Host'
                        """

db_lifecycle = """
                    search Pattern
                    where
                    'Relational Database Management Systems' in categories
                    traverse Pattern:Maintainer:Element:SoftwareInstance
                        where #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                            or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                                or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                    show
                    type,
                    product_version,
                    (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                        and formatTime(#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date, '%Y-%m-%d')) as 'End of Life',
                    (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                        and formatTime(#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date, '%Y-%m-%d')) as 'End of Support',
                    (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                        and formatTime(#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date, '%Y-%m-%d')) as 'End of Ext Support',
                    (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                        and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date < currentTime()
                        and 'EOES Exceeded')
                        or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                            and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date < currentTime()
                            and 'EOS Exceeded')
                            or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                                and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date < currentTime()
                                and 'EOL Exceeded')
                                or (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                                    and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date < currentTime() + 182 * 864000000000
                                    and 'EOL less than 6 months away')
                                    or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                                        and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date < currentTime() + 182 * 864000000000
                                        and 'EOS less than 6 months away')
                                        or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                                            and (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date < currentTime() + 182 * 864000000000
                                            and 'EOES less than 6 months away'))
                                            or (#ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.retirement_date
                                                and 'EOL more than 6 months away'
                                                or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_support_date
                                                    and 'EOS more than 6 months away'
                                                    or #ElementWithDetail:SupportDetail:SoftwareDetail:SupportDetail.end_ext_support_date
                                                        and 'EOES more than 6 months away')) as 'Lifecycle Risk',
                    #:HostedSoftware:Host:Host.name as 'Host'
                """

licenses = """
                search Host
                where not (host_type has subword 'desktop' or host_type has subword 'client')
                show
                versionInfo() as 'BMC Discovery Version',
                (local_fqdn or name) as 'Name',
                hash((local_fqdn or name)) as 'Anonymized Name',
                os as 'Discovered OS'
                processwith unique(0)
             """

snmp_devices = """
                    search DiscoveryAccess where
                    _last_marker defined
                    and endtime defined
                    and end_state = 'UnsupportedDevice'
                    and nodecount(traverse flags(include_destroyed) ::InferredElement:Host) = 0
                    and #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.kind <> 'Host'
                    and nodecount (traverse DiscoveryAccess:Metadata:Detail:SessionResult where session_type has subword "SNMP" and success) > 0
                    show
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.os_class as 'OS_Class',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.sysobjectid as 'SNMP_sysObjectId',
                    (#DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.probed_os and 'Probe' or #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.access_method) as 'Current_Access',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.os as 'Discovered_OS',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.os_type as 'OS_Type',
                    #DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:DeviceInfo.os_version as 'OS_Version'
                    process with countUnique()
                  """

missing_vms = """
                    search VirtualMachine
                    where nodecount(traverse HostContainer:HostContainment:ContainedHost:) = 0
                    show
                    vm_type as 'VM_Type',
                    (product_version or cloud_class) as 'VM_Version',
                    #RunningSoftware:HostedSoftware:Host:.name as 'VM_Host',
                    #RunningSoftware:HostedSoftware:Host:.type as 'VM_Host_Type',
                    vm_name as 'Guest_VM_Name',
                    vm_guest_os as 'Guest_VM_OS',
                    guest_full_name as 'Guest_Full_Name',
                    (vm_status or cloud and "Cloud Hosted") as 'Status'
                """

agents = """
                search Host
                with
                nodecount(traverse Host:HostedSoftware::SoftwareInstance where type = 'Microsoft System Center Configuration Manager Client') as SCCM,
                nodecount(traverse Host:HostedSoftware::SoftwareInstance where type = 'Sophos Anti-Virus') as SophosAV,
                nodecount(traverse Host:HostedSoftware::SoftwareInstance where type = 'Qualys Cloud Agent') as QualysCloud,
                nodecount(traverse Host:HostedSoftware::SoftwareInstance where type = 'BMC Client Management Client') as BCM,
                nodecount(traverse Host:HostedSoftware::SoftwareInstance where type = 'McAfee Endpoint Security') as McAfee,
                nodecount(traverse Host:HostedSoftware::SoftwareInstance where type = 'BMC Patrol Agent') as Patrol,
                nodecount(traverse Host:HostedSoftware::SoftwareInstance where type = 'Symantec Endpoint Protection Client') as Symantec
                where os_type has subword 'Windows'
                show
                name as "Host_Name",
                hash(name) as 'hashed_name',
                os_version as "OS_Version",
                #:::SoftwareInstance.name as "Running_Software",
                serial as "Serial",
                uuid as "UUID",
                ((age_count < 0) and 'Aging' or 'Alive') as 'Age_Status',
                whenWasThat(last_update_success) as 'Last_Successful_Scan',
                last_update_success as 'Last_Scan_Date',
                (@SCCM and 'Yes' or '-') as 'SCCM',
                (@SophosAV and 'Yes' or '-') as 'Sophos_AV',
                (@QualysCloud and 'Yes' or '-') as 'Qualys_Agent',
                (@BCM and 'Yes' or '-') as 'BCM',
                (@McAfee and 'Yes' or '-') as 'McAfee',
                (@Patrol and 'Yes' or '-') as 'Patrol',
                (@Symantec and 'Yes' or '-') as 'Symantec'
            """

user_accounts = """
                        search SoftwareInstance
                        show
                        name as "Software_Instance",
                        #RunningSoftware:HostedSoftware:Host:.name as 'Host',
                        type as 'Type',
                        product_version as 'Version',
                        explode #InferredElement:Inference:Primary:DiscoveredProcess.username as 'User_Name'
                   """

cmdb_sync_config = """
                        SEARCH IN '_System' CMDBSyncConfig
                   """

patterns =    """
                    search PatternModule
                    show origin as 'Origin',
                    tree_path as 'Tree_Path',
                    name,
                    submitting_user,
                    submission_date as 'Submission_Date',
                    active as 'Active',
                    description as 'Description',
                    extra_node_kinds as 'Extra_Node_Kinds',
                    extra_rel_kinds as 'Extra_Rel_Kinds'
                """