#!/usr/bin/env python3
"""Minimal script to test credential success query."""
import argparse
import logging
import os
import sys
import json
import csv

logger = logging.getLogger("cred_debug")

def api_version(tw):
    """Return (about, version) tuple or (None, None) on failure."""
    host = getattr(tw, "host", getattr(tw, "url", "unknown"))
    token_present = bool(getattr(tw, "token", None))
    logger.debug("Calling tw.about() [host=%s, token_provided=%s]", host, token_present)
    try:
        about = tw.about()
    except Exception as e:  # pragma: no cover - network errors
        logger.error("Problem retrieving API version: %s", e)
        return None, None

    if not about.ok:
        logger.error(
            "About call failed: %s - %s",
            getattr(about, "status_code", "unknown"),
            about.reason,
        )
        return None, None

    try:
        version = about.json().get("api_versions", [])[-1]
    except Exception as e:
        logger.error("Error parsing about information: %s", e)
        version = None

    return about, version

def api_target(args):
    import tideway
    target = args.target
    token = args.token
    disco = None

    if args.f_token:
        if os.path.isfile(args.f_token):
            with open(args.f_token, "r") as f:
                token = f.read().strip()
        else:
            msg = "Token file not found!\n"
            print(msg)
            logger.error(msg)

    if not token:
        token = input("Bearer Token: ")
        if not token:
            msg = "Bearer token needed for API access.\n"
            print(msg)
            logger.error(msg)
            sys.exit(1)

    if token:
        msg = "\nChecking for Discovery API on %s..." % target
        print(msg)
        logger.info(msg)
        logger.debug("Creating appliance object for %s (token provided: %s)", target, bool(token))
        disco = tideway.appliance(target, token)

        try:
            about, apiver = api_version(disco)
            if about is not None:
                msg = "About: %s\n" % about.json()
                logger.info(msg)
            if apiver:
                logger.debug(
                    "Creating appliance object for %s with api_version=%s (token provided: %s)",
                    target,
                    apiver,
                    bool(token),
                )
                disco = tideway.appliance(target, token, api_version=apiver)
            else:
                logger.debug(
                    "Creating appliance object for %s with default API version (token provided: %s)",
                    target,
                    bool(token),
                )
                disco = tideway.appliance(target, token)
            msg = "API found on %s." % target
            logger.info(msg)
        except OSError as e:
            msg = "Error connecting to %s\n%s\n" % (target, e)
            print(msg)
            logger.error(msg)

        if disco:
            logger.debug(
                "Calling disco.swagger() for %s (token provided: %s)",
                target,
                bool(token),
            )
            swagger = disco.swagger()
            if swagger.ok:
                msg = "Successful API call to %s" % swagger.url
                print(msg)
                logger.info(msg)
            else:
                msg = "Problem with API version, please refer to developer.\nReason: %s, URL: %s\n" % (
                    swagger.reason,
                    swagger.url,
                )
                print(msg)
                logger.error(msg)

    return disco

def init_endpoints(api_target, args):
    try:
        logger.debug("Requesting discovery endpoint from %s", args.target)
        disco = api_target.discovery()
        logger.debug("Discovery endpoint obtained: %s", disco)
    except Exception:
        msg = "Error getting Discovery endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        logger.debug("Requesting data endpoint from %s", args.target)
        search = api_target.data()
        logger.debug("Data endpoint obtained: %s", search)
    except Exception:
        msg = "Error getting Data endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        logger.debug("Requesting credentials endpoint from %s", args.target)
        creds = api_target.credentials()
        logger.debug("Credentials endpoint obtained: %s", creds)
    except Exception:
        msg = "Error getting Credentials endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        logger.debug("Requesting vault endpoint from %s", args.target)
        vault = api_target.vault()
        logger.debug("Vault endpoint obtained: %s", vault)
    except Exception:
        msg = "Error getting Vault endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    try:
        logger.debug("Requesting knowledge endpoint from %s", args.target)
        knowledge = api_target.knowledge()
        logger.debug("Knowledge endpoint obtained: %s", knowledge)
    except Exception:
        msg = "Error getting Knowledge endpoint from %s\n" % (args.target)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    return disco, search, creds, vault, knowledge

def get_json(api_endpoint):
    """Return JSON data from a request object."""

    if callable(api_endpoint):
        try:
            api_endpoint = api_endpoint()
        except Exception as e:  # pragma: no cover - network errors
            msg = "Not able to make api call.\nException: %s\n%s" % (e.__class__, str(e))
            print(msg)
            logger.error(msg)
            return {}

    if not hasattr(api_endpoint, "status_code"):
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
            logger.debug("API response text from %s:\n%s" % (url, api_endpoint.text))
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
                logger.debug("Decoded JSON from %s:\n%s" % (url, json.dumps(data, indent=2)))
            except Exception:
                pass
        return data

def search_results(api_endpoint, query):
    try:
        if logger.isEnabledFor(logging.DEBUG):
            try:
                logger.debug("Search query: %s" % query)
            except Exception:
                pass
        if hasattr(api_endpoint, "search_bulk"):
            results = api_endpoint.search_bulk(query, format="object", limit=500)
        else:
            results = api_endpoint.search(query, format="object", limit=500)
        if hasattr(results, "json"):
            if logger.isEnabledFor(logging.DEBUG):
                try:
                    logger.debug("Raw search response: %s" % results.text)
                except Exception:
                    pass
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
                return data
        else:
            if logger.isEnabledFor(logging.DEBUG):
                try:
                    logger.debug("Parsed results length: %s" % len(results))
                except Exception:
                    pass
            return results
    except Exception as e:
        msg = "Not able to make api call.\nQuery: %s\nException: %s\n%s" % (query, e.__class__, str(e))
        print(msg)
        logger.error(msg)
        return []

def success(twcreds, twsearch, args, dir):
    from core import reporting
    reporting.successful(twcreds, twsearch, args)



def main():
    parser = argparse.ArgumentParser(description="Debug credential success")
    parser.add_argument('-i', '--discovery_instance', dest='target', type=str,
                        required=True, help='Discovery or Outpost target')
    parser.add_argument('-t', '--token', dest='token', type=str, required=False,
                        help='Discovery API token without "Bearer"')
    parser.add_argument('-T', '--token_file', dest='f_token', type=str,
                        required=False, help='File containing API token')
    parser.add_argument('-u', '--username', dest='username', type=str,
                        required=False, help='Login username for Discovery')
    parser.add_argument('-p', '--password', dest='password', type=str,
                        required=False, help='Login password for Discovery')
    parser.add_argument('-P', '--password_file', dest='f_passwd', type=str,
                        required=False, help='File containing password string')
    parser.add_argument('-c', '--csv', dest='output_csv', action='store_true',
                        help='Output in CSV format')
    parser.add_argument('-f', '--file', dest='output_file', type=str,
                        help='Output file path')
    parser.add_argument('--debug', dest='debugging', action='store_true',
                        help='Enable debug logging')

    args = parser.parse_args()

    if args.debugging:
        logging.basicConfig(level=logging.DEBUG)

    api_target_obj = api_target(args)
    disco, search, creds, _, _ = init_endpoints(api_target_obj, args)

    # Execute the credential success report
    success(creds, search, args, '.')


if __name__ == '__main__':
    main()
