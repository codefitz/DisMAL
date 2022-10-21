# Discovery access methods for DisMAL

import logging
import os
import sys
import platform
import getpass

# PIP Packages
import tideway
import paramiko

# Local library
from . import access

logger = logging.getLogger("_access_")

def api_version(tw):
    about = tw.about()
    if about.ok:
        version = about.json()['api_versions'][-1]
        return(about, version)

def ping(target):
    current_os = platform.system().lower()
    if current_os == "windows":
        parameters = "-n 1 -w 2"
        null = "$null"
    elif current_os == "Linux":
        parameters = "-c 1 -w2"
        null = "/dev/null"
    else: # Mac
        parameters = "-c 1 -i2"
        null = "/dev/null"
    exit_code = os.system(f"ping {parameters} {target} > {null} 2>&1")
    if os.path.exists("$null"):
        # Windows outputs to a '$null' file instead of Null
        os.remove("$null")
    return exit_code

def run_cmd(cmd, client):
    stdin, stdout, stderr = client.exec_command(cmd)
    logger.info("Ran command %s:" % (cmd))
    logger.debug("STDIN:" + str(stdin))
    logger.debug("STDOUT:" + str(stdout))
    logger.error("STDERR:" + str(stderr))
    return stdin, stdout, stderr

def remote_cmd(cmd, client):
    stdin, stdout, stderr = run_cmd(cmd, client)
    out=""
    error=""
    output=None
    for line in stdout.readlines():
        out+=line
    for line in stderr.readlines():
        error+=line
    if out:
        output = out
    elif error:
        output = error
    return output

def method(args):
    target = args.discovery
    token = args.token
    passwd = args.twpass
    disco = None
    use_api = False
    use_ssh = False
    system_user = False
    if not target:
        target = input("URL or IP address: ")
        if not target:
            msg = "Must enter valid URL or IP address.\n"
            print(msg)
            logger.error(msg)
            sys.exit(1)

    if args.f_token:
        exists = os.path.isfile(args.f_token)
        if exists:
            f=open(args.f_token, 'r')
            token=f.read().strip()
            f.close()
        else:
            msg = "Token file not found!\n"
            print(msg)
            logger.error(msg)
            sys.exit(1)

    if args.f_passwd:
        exists = os.path.isfile(args.f_passwd)
        if exists:
            f=open(args.f_passwd, 'r')
            passwd=f.read()
            f.close()
        else:
            msg = "Password file not found!\n"
            print(msg)
            logger.error(msg)
            sys.exit(1)
    exit_code = ping(target)
    if not args.noping:
        if exit_code != 0:
            msg = "Endpoint %s not found (ping)\nExit Code: %s"%(target,exit_code)
            print(msg)
            logger.warning(msg)
            sys.exit(1)

    disco = tideway.appliance(target,token)

    if not token and not passwd:
        msg = "No access details supplied.\n"
        print(msg)
        logger.error(msg)
        sys.exit(1)

    client = None
    if token:
        msg = "\nChecking for Discovery API on %s..." % target
        print(msg)
        logger.info(msg)

        try:
            about, apiver = api_version(disco)
            msg = "About: %s\n"%about.json()
            logger.info(msg)
            if apiver:
                disco = tideway.appliance(target,token,api_version=apiver)
            else:
                disco = tideway.appliance(target,token)
            msg = "API found on %s." % target
            logger.info(msg)            
        except OSError as e:
            msg = "Error connecting to %s\n%s\n" % (target,e)
            print(msg)
            logger.error(msg)

        if disco:
            swagger = disco.swagger()
            if swagger.ok:
                msg = "Successful API call to %s" % swagger.url
                print(msg)
                logger.info(msg)
            else:
                msg = "Problem with API version, please refer to developer.\nReason: %s, URL: %s\n" % (swagger.reason, swagger.url)
                print(msg)
                logger.error(msg)
            use_api = True

    if passwd:
        msg = "\nChecking target login for %s..." % target
        print(msg)
        logger.info(msg)
        if not args.noping:
            exit_code = ping(target)
            if exit_code != 0:
                msg = "CLI endpoint %s not found (ping)\nExit Code: %s"%(target,exit_code)
                print(msg)
                logger.warning(msg)
                sys.exit(1)
        client = paramiko.SSHClient()
        # Accept unknown target host
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(target, username="tideway", password=passwd)
            output = remote_cmd('echo -n "Successfully logged in as " && whoami', client)
            logger.info(output)
            print(output)
            use_ssh = True
        except Exception as e:
            msg = "Problem logging into %s\n%s" % (target,e)
            print(msg)
            logger.error(msg)

    syspass = args.password
    if not syspass:
        if args.f_passwd:
            exists = os.path.isfile(args.f_passwd)
            if exists:
                f=open(args.f_passwd, 'r')
                syspass=f.read()
                f.close()
            else:
                msg = "File %s does not exist!\n"%args.f_passwd
                logger.error(msg)
        if not syspass:
            syspass = getpass.getpass(prompt='Please enter your system administrator password: ')
    
    if syspass:
        system_user = True
    else:
        msg = "No system user supplied."
        print(msg)
        logger.warning(msg)

    return disco, token, client, use_api, use_ssh, system_user