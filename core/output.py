# Process output for DisMAL

import sys
import logging
import csv

# PIP Modules
from tabulate import tabulate

# Local
from . import tools, api

logger = logging.getLogger("_output_")

def csv_out(data, heads):
    data.insert(0, heads)
    try:
        w = csv.writer(sys.stdout)
        w.writerows(data)
    except Exception as e:
        logger.error("Problem outputting CSV data:%s\n%s"%(e.__class__,str(e)))
        logger.debug("CSV Data:\n%s"%data)

def cmd2csv_out(header,result,seperator):
    data = []
    for line in result.split("\r\n"):
        lines = line.split("\n")
        for item in lines:
            try:
                row = item.split(seperator)
                data.append([s.strip() for s in row])
            except Exception as e:
                msg = "Problem outputting to CSV:\n%s\n%s\n%s"%(item,e.__class__,str(e))
                logger.error(msg)
                print(msg)
    csv_out(data, header)

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

def save2csv(clidata, filename, appliance):
    try:
        header = clidata.split("\n",1)[0].strip().split(',')
        body = clidata.split("\n",1)[1]
        data = []
        header.insert(0,"Discovery Instance")
        for line in body.split("\r\n"):
            if line:
                try:
                    columns = [c.strip() for c in line.split(',')]
                    columns.insert(0, appliance)
                    data.append([tools.dequote(c) for c in columns])
                except Exception as e:
                    logger.error("Problem writing line to CSV:\n%s\n%s\n%s"%(line,e.__class__,str(e)))
                    # Try dumping it instead
                    msg = "save2csv: Parsing CLI data failed, dumping body data to %s"%filename
                    logger.info(msg)
                    print(msg)
                    txt_dump(clidata,filename)
        csv_file(data, header, filename)
    except Exception as e:
        logger.error("Problem parsing data:\n%s\n%s"%(e.__class__,str(e)))
        # Try dumping it instead
        msg = "save2csv: Parsing CLI data failed, dumping data to %s"%filename
        logger.info(msg)
        print(msg)
        txt_dump(clidata,filename)

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
        if args.output_null:
            msg = "\n:%s Results\n" % len(data)
            logger.info(msg)
            print(msg)
        elif args.output_csv:
            csv_out(data, heads)
            logger.info("Output to CSV")
        elif args.output_file:
            csv_file(data, heads, args.output_file)
            logger.info("Output to CSV file")
        else:
            fancy_out(data, heads)
            logger.info("Fancy output")
    else:
        msg = "No results found!\n"
        print(msg)
        logger.warning(msg)

def cmd2csv(header,result,seperator,filename,appliance):
    data = []
    header.insert(0,"Discovery Instance")
    for line in result.split("\r\n"):
        lines = line.split("\n")
        for item in lines:
            try:
                row = item.split(seperator)
                row.insert(0, appliance)
                data.append([s.strip() for s in row])
            except Exception as e:
                logger.error("Problem outputting to CSV:\n%s\n%s\n%s"%(item,e.__class__,str(e)))
                # Try dumping it instead
                msg = "cmd2csv: Parsing CLI data failed, dumping data to %s"%filename
                logger.info(msg)
                print(msg)
                txt_dump(result,filename)
    csv_file(data, header, filename)

def query2csv(search, query, filename, appliance):
    response = api.search_results(search, query)
    if type(response) == list and len(response) > 0:
        header, data = tools.json2csv(response)
        header.insert(0,"Discovery Instance")
        for row in data:
            row.insert(0, appliance)
        csv_file(data, header, filename)
    else:
        txt_dump("No results.",filename)

def define_txt(args,result,path,filename):
    # Manage all Output options
    if args.access_method == "all":
        txt_dump(result,path)
    elif args.output_file:
        if filename:
            output_file = filename+"_"+args.output_file
        else:
            output_file = args.output_file
        txt_dump(result,output_file)
    elif args.output_csv:
        msg ="DisMAL: Output cannot be converted into CSV, defaulting to text."
        logger.warning(msg)
        print(msg)
        txt_dump(result,filename)
    elif args.output_null:
        print("Report completed (null).")
    else:
        print(result)

def define_csv(args,head_ep,data,path,file,target,type):
    # Manage all Output options
    if type == "cmd":
        if args.access_method == "all":
            cmd2csv(head_ep, data, ":", path, target)
        elif args.output_file:
            cmd2csv(head_ep, data, ":", file, target)
        elif args.output_csv:
            cmd2csv_out(head_ep, data, ":")
        elif args.output_null:
            print("Report completed (null).")
        else:
            print(data)
    elif type == "csv":
        if args.access_method == "all":
            save2csv(data, path, target)
        elif args.output_file:
            save2csv(data, file, target)
        elif args.output_csv:
            print(data)
        elif args.output_null:
            print("Report completed (null).")
        else:
            print(data)
    elif type == "query":
        if args.access_method == "all":
            query2csv(head_ep, data, path, target)
        elif args.output_file:
            query2csv(head_ep, data, file, target)
        elif args.output_csv:
            msg ="DisMAL: Output cannot be export to CLI."
            logger.warning(msg)
            print(msg)
        elif args.output_null:
            print("Report function completed (null).")
        else:
            msg ="DisMAL: Output cannot be export to CLI."
            logger.warning(msg)
            print(msg)
    elif type == "csv_file":
        if args.access_method == "all":
            csv_file(data, head_ep, path)
        elif args.output_file:
            csv_file(data, head_ep, file)
        elif args.output_csv:
            msg ="DisMAL: Output cannot be export to CLI."
            logger.warning(msg)
            print(msg)
        elif args.output_null:
            print("Report function completed (null).")
        else:
            msg ="DisMAL: Output cannot be export to CLI."
            logger.warning(msg)
            print(msg)