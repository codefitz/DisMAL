#!/usr/bin/env python3
"""Minimal script to test credential success query."""
import argparse
import logging
from core import access, api


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

    api_target = access.api_target(args)
    disco, search, creds, _, _ = api.init_endpoints(api_target, args)

    # Execute the credential success report
    api.success(creds, search, args, '.')


if __name__ == '__main__':
    main()
