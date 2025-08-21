# Transformation tools for DisMAL

import logging
import re
from platform import uname

# PIP Modules
import ipaddress
from cidrize import cidrize

logger = logging.getLogger("_tools_")

def to_camel_case(value: str) -> str:
    """Convert a string with separators to CamelCase.

    Non-alphanumeric characters are treated as delimiters. For example,
    ``last_scanned`` becomes ``LastScanned``.

    Parameters
    ----------
    value : str
        The string to convert.

    Returns
    -------
    str
        The CamelCase version of ``value``. Non-string inputs are returned
        unchanged.
    """

    if not isinstance(value, str):
        return value

    parts = re.split(r"[^0-9a-zA-Z]+", value)
    return "".join(part.capitalize() for part in parts if part)

def snake_to_camel(value):
    """Convert snake_case string to Camel Case with spaces.

    Examples:
        >>> snake_to_camel("pre_scanning")
        'Pre Scanning'
    """
    if not isinstance(value, str):
        return value
    return " ".join(word.capitalize() for word in value.split("_"))

def in_wsl() -> bool:
    """
        WSL is thought to be the only common Linux kernel with Microsoft in the name, per Microsoft:
        https://github.com/microsoft/WSL/issues/4071#issuecomment-496715404
    """
    return 'Microsoft' in uname().release

def getr(data, attribute, default_value=None):
    """Return ``data[attribute]`` if present, else ``default_value``.

    This avoids treating falsy values like ``0`` or ``""`` as missing.
    """
    return data[attribute] if attribute in data else default_value

def range_to_ips(iprange):
    """Return a list of :class:`ipaddress.IPv4Network`/`IPv6Network` objects.

    The previous implementation expanded ranges into individual IP addresses
    which was expensive for large networks.  This helper now preserves the
    ranges and returns ``ip_network`` objects instead.  Cloud end points and
    the special "all" range are returned unchanged as strings.
    """

    networks = []
    logger.info("Running range_to_ips function on %s" % iprange)
    if not iprange:
        return networks

    if re.search("[a-zA-Z]", iprange):
        logger.debug("IP range is cloud endpoint!")
        networks.append(iprange)
    elif iprange == "0.0.0.0/0,::/0":
        networks.append(iprange)
        logger.debug("All - List of Networks: %s" % networks)
    else:
        parts = [ip for ip in iprange.split(",") if ip]
        for ip in parts:
            try:
                net = ipaddress.ip_network(ip, strict=False)
                networks.append(net)
                logger.debug("Network appended: %s", net)
            except Exception:
                try:
                    cidrip = cidrize(ip)
                    for cidr in cidrip:
                        net = ipaddress.ip_network(cidr, strict=False)
                        networks.append(net)
                        logger.debug("CIDRize - Network appended: %s", net)
                except Exception:
                    msg = "Address %s is not valid CIDR syntax, cannot process!" % ip
                    print(msg)
                    logger.warning(msg)
    return networks

def get_credential(data,uuid):
    credentials = data
    detail = {}
    for credential in credentials:
        if uuid == credential.get('uuid'):
            uuid = getr(credential,'uuid')
            index = getr(credential,'index')
            label = getr(credential,'label')
            enabled = getr(credential,'enabled')
            types = getr(credential,'types')
            username = None
            if 'username' in credential:
                username = getr(credential,'username')
            elif 'snmp.v3.securityname' in credential:
                username = getr(credential,'snmp.v3.securityname')
            elif 'aws.access_key_id' in credential:
                username = getr(credential,'aws.access_key_id')
            elif 'azure.application_id' in credential:
                username = getr(credential,'azure.application_id')
            iprange = getr(credential,'ip_range')
            exclusions = getr(credential,'ip_exclusion')
            detail = {"index":index,"uuid":uuid,"label":label,"username":username,"enabled":enabled,"iprange":iprange,"exclusions":exclusions,"types":types}
    return detail

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

def normalize_header(name: str) -> str:
    """Return *name* converted to CamelCase.

    Non-alphanumeric characters are treated as word separators.
    """
    if not name:
        return ""
    parts = re.split(r"[^0-9A-Za-z]+", str(name))
    return "".join(p.capitalize() for p in parts if p)

def normalize_key(key):
    """Return ``key`` converted from ``snake_case`` or dotted names to Title Case."""
    parts = re.split(r"[_\.]+", key)
    return " ".join(p.capitalize() for p in parts if p)

def normalize_headers(headers, return_lookup=False):
    """Normalize ``headers`` and optionally return a lookup map.

    Parameters
    ----------
    headers : Iterable[str]
        Header labels to normalize.
    return_lookup : bool, optional
        When ``True`` return a tuple of ``(headers, lookup)`` where ``lookup``
        maps the normalized labels back to their original values.  When
        ``False`` only the list of normalized headers is returned.
    """
    if not headers:
        return ([], {}) if return_lookup else []

    normalized = []
    lookup = {}
    for key in headers:
        norm = normalize_key(key)
        normalized.append(norm)
        lookup[norm] = key

    if return_lookup:
        return normalized, lookup
    return normalized

def completage(message, record_count, timer_count):
    timer_count += 1
    pc = (float(timer_count) / float(record_count))
    if timer_count >= record_count:
        end_char = '\n'
    else:
        end_char = '\r'
    print('%s: %d%%' % (message,100.0 * pc), end=end_char)
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
        # Cast count values to integers to ensure arithmetic works as expected
        count = int(result.get('SessionResult.count', 0))
        uuid = result.get('SessionResult.uuid')
        restype = result.get('SessionResult.session_type')
        if uuid:
            sessions[uuid] = [restype, count]
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

def extract_credential(entry):
    details = {}
    uuid = entry.get('uuid')
    index = entry.get('index')
    label = entry.get('label')
    enabled = entry.get('enabled')
    types = entry.get('types')
    usage = entry.get('usage')
    internal_store = entry.get('internal.store')
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
    details = {"index":index,"uuid":uuid,"label":label,"username":username,"enabled":enabled,"iprange":iprange,"exclusions":exclusions,"types":types,"usage":usage,"internal_store":internal_store}
    return details

def dequote(s):
    """
    If a string has double quotes around it, remove them.
    Make sure the pair of quotes match.
    If a matching pair of quotes is not found, return the string unchanged.
    """
    if (s[0] == s[-1]) and s.startswith('"'):
        return s[1:-1]
    return s


def json2csv(jsdata, return_map=False):
    header = []
    data = []
    for jsitem in jsdata:
        for label in jsitem.keys():
            header.append(label)
            header = sortlist(header)

    for jsitem in jsdata:
        values = []
        for key in header:
            values.append(getr(jsitem, key, "N/A"))
        data.append(values)

    lookup = {h: h for h in header}
    if return_map:
        return header, data, lookup

    return header, data, header

def snake_to_title(value):
    """Convert ``snake_case`` strings to Title Case with spaces.

    Common abbreviations such as ``os`` and ``id`` are preserved in uppercase.
    Non-string values or already formatted labels are returned unchanged.
    """
    if not isinstance(value, str):
        return value

    if not value.islower():
        return value

    abbreviations = {"os": "OS", "id": "ID"}
    parts = value.split("_")
    words = []
    for part in parts:
        if part in abbreviations:
            words.append(abbreviations[part])
            continue
        for abbr, repl in abbreviations.items():
            if part.endswith(abbr) and part != abbr:
                prefix = part[:-len(abbr)]
                if prefix:
                    words.append(prefix.capitalize())
                words.append(repl)
                break
        else:
            words.append(part.capitalize())
    return " ".join(words)

def list_table_to_json(rows):
    """Convert a list-of-lists table to a list of dictionaries.

    The first row is treated as headers.  If ``rows`` is not a list of
    lists, the value is returned unchanged.
    """
    if isinstance(rows, list) and rows and isinstance(rows[0], list):
        headers = rows[0]
        return [dict(zip(headers, r)) for r in rows[1:]]
    return rows

def normalize_keys(keys):
    """Return header names in Title Case with spaces.

    Any key containing underscores or entirely lowercase characters is
    converted to a human-friendly form. Keys that already contain
    capital letters or spaces are returned unchanged.
    """

    normalized = []
    for key in keys:
        if "_" in key or key.islower():
            normalized.append(key.replace("_", " ").title())
        else:
            normalized.append(key)
    return normalized

