# Transformation tools for DisMAL

import logging
import re

# PIP Modules
import ipaddress
from cidrize import cidrize

logger = logging.getLogger("_tools_")

def in_wsl() -> bool:
    """
        WSL is thought to be the only common Linux kernel with Microsoft in the name, per Microsoft:
        https://github.com/microsoft/WSL/issues/4071#issuecomment-496715404
    """
    return 'Microsoft' in uname().release

def getr(data,attribute,default_value=None):
    return data.get(attribute) or default_value

def range_to_ips(iprange):
    list_of_ips = []
    logger.info("Running range_to_ips function on %s"%iprange)
    if not iprange:
        # Return empty list
        return list_of_ips
    if re.search('[a-zA-Z]', iprange):
        logger.debug("IP range is cloud endpoint!")
        list_of_ips.append(iprange)
    elif iprange == "0.0.0.0/0,::/0":
        list_of_ips.append(iprange)
        logger.debug("All - List of IPs: %s"%list_of_ips)
    elif iprange:
        iprange = [ip for ip in iprange.split(",") if ip]
        #timer_count = 0
        for ip in iprange:
            #timer_count = Transform.completage("Processing IP Range", len(iprange), timer_count)
            try:
                ipaddr = ipaddress.ip_address(ip)
                list_of_ips.append(ipaddr)
                logger.debug("Single - List of IPs: %s"%list_of_ips)
            except:
                try:
                    subnet = ipaddress.ip_network(ip)
                    for ipaddr in subnet:
                        list_of_ips.append(ipaddr)
                        logger.debug("Subnet - List of IPs: %s"%list_of_ips)
                except:
                    try:
                        subnet = ipaddress.ip_network(ip,strict=False)
                        msg = 'Address %s is not valid CIDR syntax, recommended CIDR: %s' % (ip, subnet)
                        print(msg)
                        logger.warning(msg)
                        for ipaddr in subnet:
                            list_of_ips.append(ipaddr)
                            logger.debug("Subnet (not strict) - List of IPs: %s"%list_of_ips)
                    except:
                        try:
                            cidrip = cidrize(ip)
                            size = 0
                            for cidr in cidrip:
                                subnet = ipaddress.ip_network(cidr)
                                for ipaddr in subnet:
                                    list_of_ips.append(ipaddr)
                                    logger.debug("CIDRize - List of IPs: %s"%list_of_ips)
                        except:
                            msg = 'Address %s is not valid CIDR syntax, cannot process!' % (ip)
                            print(msg)
                            logger.warning(msg)
    return list_of_ips

def sortlist(lst,dv=None):
    logger.debug("List to sort and unique:\n%s"%lst)
    if dv:
        logger.debug("Replace None values with %s"%dv)
        lst = [ dv if v is None else v for v in lst ] # replace None values
    else:
        logger.debug("Remove None values")
        lst = [ v for v in lst if v is not None ] # remove None values
    lst = sorted(set(lst)) # sort and unique
    logger.debug(lst)
    return lst

def sortdic(lst):
    logger.debug("Dict to sort and unique:\n%s"%lst)
    lst2 = [i for n, i in enumerate(lst) if i not in lst[n + 1:]]
    logger.debug(lst)
    return lst2

def completage(message, record_count, timer_count):
    timer_count += 1
    pc = (float(timer_count) / float(record_count))
    print('%s: %d%%' % (message,100.0 * pc),end='\r')
    return timer_count

def list_of_lists(ci,attr,list_to_append):
    thing = ci.get(attr)
    if type(ci.get(attr)) is list:
        for item in thing:
            if type(item) is list:
                for sub_item in item:
                    list_to_append.append(sub_item)
            else:
                list_to_append.append(item)
    else:
        list_to_append.append(thing)
    return list_to_append

def session_get(results):
    sessions = {}
    for result in results:
        count = result.get('Count')
        uuid = result.get('UUID')
        restype = result.get('Session_Type')
        if uuid:
            sessions[uuid] = [ restype, count ]
    return sessions

def ip_or_string(value):
    try:
        ip = int(ipaddress.ip_address(value))
        msg = "Value %s converted to IPAddress %s."%(value,ip)
        logger.debug(msg)
        return ip
    except ValueError:
        msg = "Value %s Could not be convered to IPAddress"%value
        logger.warning(msg)
        return value