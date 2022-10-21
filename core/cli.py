# Discovery CLI commands for DisMAL

import sys
import logging
import getpass
import time
import sys

# Local modules
from . import access, output

logger = logging.getLogger("_cli_")

def user_management(args, client):
    twuser = args.a_user_man
    passwd = args.twpass
    if passwd:
        msg = "Checking for user login %s...\n" % twuser
        logger.info(msg)
        print(msg)
        output = access.remote_cmd('tw_listusers --filter %s' % twuser, client)
        logger.info(output)
        if not output:
            msg = "User not found: %s\n" % twuser
            logger.warning(msg)
            print(msg)
            sys.exit(1)

        print(output)

        while True:
            print("Options:\n\n 1. Set User %s Active"%twuser)
            print(" 2. Change User %s Password"%twuser)
            print(" 3. Set User %s Password OK"%twuser)
            print(" 4. Exit\n")
            management = input("Choice: ")
            if management == "1":
                upduser = access.remote_cmd('tw_upduser --active %s' % twuser, client)
                logger.info("Selected 1: %s"%upduser)
                print(upduser)
            if management == "2":
                passwd = getpass.getpass(prompt='Enter new password: ')
                stdin, stdout, stderr = client.exec_command('tw_passwd %s' % twuser)
                time.sleep(3)
                # Set password (2x)
                stdin.write('%s\n'%passwd)
                stdin.write('%s\n'%passwd)
                stdin.flush()
                out = []
                errors = []
                passwdset = False
                for line in out.readlines():
                    if "at least 8 characters" in line:
                        print("WARNING:",line)
                    if "Password set for user" in line:
                        passwdset = True
                        print("INFO:",line)
                    out.append(line)
                for line in stderr.readlines():
                    if "ERROR:" in line:
                        print(line)
                    errors.append(line)
                logger.info("Selected 2: %s,%s"%(out,errors))
                if not passwdset:
                    print("Problem with password change, check the logfile for details.\n")
            if management == "3":
                passok = access.remote_cmd('tw_upduser --passwd-ok %s' % twuser, client)
                logger.info("Selected 3: %s"%passok)
                print(passok)
            if management == "4":
                break
            print(output)

def service_management(args, client):
    cmd = args.a_services
    msg = "Sending Command: tw_service_control --%s\n" % cmd
    logger.info(msg)
    print(msg)
    output = access.remote_cmd('tw_service_control --%s'%cmd, client)
    logger.debug(output)
    print(output)
    return output

def clear_queue(client):
    gonogo = input("Continue with removing persistent reasoning files, no recovery (Y/y)?")
    if gonogo == "Y" or gonogo == "y":
        msg = "Stopping services..."
        logger.info(msg)
        print(msg)
        service_management("stop", client)
        msg = "Deleting persistent data..."
        logger.info(msg)
        cmd = 'rm -rfv /usr/tideway/var/persist/reasoning/engine/queue/*.pq'
        print("Sending:",cmd)
        output = access.remote_cmd(cmd, client)
        logger.info(output)
        print(output)
        cmd = 'rm -rfv /usr/tideway/var/persist/reasoning/engine/queue/*.rc'
        print("Sending:",cmd)
        output = access.remote_cmd(cmd, client)
        logger.info(output)
        print(output)
        msg = "Starting services..."
        logger.info(msg)
        service_management("start", client)
    elif gonogo == "No":
        print("Cancelled. No action taken.")

def baseline(client,args,instance_dir):
    cmd = 'tw_baseline --no-highlight'
    logger.info("Running %s"%cmd)
    data = access.remote_cmd(cmd,client)
    logger.debug("Baseline Ouptut:\n%s"%data)
    header = [ "Check", "Result", "Description" ]
    checked = []
    for line in data.split("\r\n"):
        checklist = line.split("\n",2)[2]
        for checks in checklist.split("\n"):
            check = checks.split(":")
            checked.append([s.strip() for s in check])
    header.insert(0,"Discovery Instance")
    for row in checked:
        row.insert(0, args.discovery)
    output.csv_file(checked, header, instance_dir+"/baseline.csv")