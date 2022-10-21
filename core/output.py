# Process output for DisMAL

import sys
import datetime
import logging
import csv
import os

# PIP Modules
from tabulate import tabulate

logger = logging.getLogger("_output_")

def csv_out(data, heads):
    data.insert(0, heads)
    try:
        w = csv.writer(sys.stdout)
        w.writerows(data)
    except Exception as e:
        logger.error("Problem outputting CSV data:%s\n%s"%(e.__class__,str(e)))
        logger.debug("CSV Data:\n%s"%data)

def txt_dump(output,filename):
    try:
        f=open(filename, 'w', encoding="utf-8")
        f.write(output)
        f.close()
    except Exception as e:
        logger.error("Problem dumping output:\n%s\n%s\n%s"%(filename,e.__class__,str(e)))
        logger.debug("Dump Data:\n%s"%output)

def csv_file(data, heads, filename):
    data.insert(0, heads)
    logger.debug("CSV Data:\n%s"%data)
    with open(filename, 'w', newline='') as file:
        try:
            writer = csv.writer(file, delimiter=",")
            writer.writerows(data)
            msg = "Results written to %s" % filename
            print(msg)
            logger.info(msg)
        except Exception as e:
            logger.error("Problem writing CSV file:\n%s\n%s\n%s"%(file,e.__class__,str(e)))
            # Try dumping it
            txt_dump(data,filename)
            msg = "Error writing %s, check logs." % filename
            print(msg)
            logger.info(msg)

def fancy_out(data, heads):
    try:
        output = tabulate(data, headers=heads, tablefmt='fancy_grid', showindex="always")
        print(output)
        logger.debug("Printed:\n%s"%output)
    except Exception as e:
        logger.error("Problem printing fancy output:%s\n%s"%(e.__class__,str(e)))

def report(data, heads, args):
    if len(data) > 0:
        logger.debug("Report Info:\n%s"%data)
        if args.nullreport:
            msg = "\n:%s Results\n" % len(data)
            logger.info(msg)
            print(msg)
        elif args.csv_export:
            csv_out(data, heads)
            logger.info("Output to CSV")
        elif args.f_name:
            csv_file(data, heads, args.f_name)
            logger.info("Output to CSV file")
        else:
            fancy_out(data, heads)
            logger.info("Fancy output")
    else:
        msg = "No results found!\n"
        print(msg)
        logger.warning(msg)