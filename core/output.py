# Process output for DisMAL

import sys
import logging
import csv
import os

# PIP Modules
from tabulate import tabulate

# Local
from . import tools, api, cli

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
                    data.append( tools.dequote(columns) )
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

def tpl_export(search, query, dir, method, client, sysuser, syspass):
    tpldir = dir + "/tpl"
    if not os.path.exists(tpldir):
        os.makedirs(tpldir)
    files=0
    if method == "api":
        response = api.search_results(search, query)
        if type(response) == list and len(response) > 0:
            header, data = tools.json2csv(response)
            for row in data:
                filename = "%s/%s.tpl"%(tpldir,row[1])
                files+=1
                try:
                    f=open(filename, 'w', encoding="utf-8")
                    f.write(row[0])
                    f.close()
                except Exception as e:
                    logger.error("Problem with TPL: %s\n%s\n%s\nRow Data:\n%s"%(filename,e.__class__,str(e),row))
                    txt_dump(str(row),"%s/module_%s.tpl"%(tpldir,files))
        else:
            txt_dump("No results.","%s/tpl_export.txt"%tpldir)
    else:
        results = cli.run_query(client,sysuser,syspass,query)
        try:
            body = results.split("\n",1)[1]
            for line in body.split("\r\n"):
                files+=1
                if line:
                    try:
                        columns = [c.strip() for c in line.split(',')]
                        filename = "%s/%s.tpl"%(tpldir,columns[0])
                        columns.pop(0)
                        row = [ tools.dequote(columns) ]
                        logger.debug("Parsing row:\n%s"%row)
                        row2 = ''.join(row[0])
                        row3 = tools.dequote(row2)
                        newrow = row3.replace('""""','","')
                        logger.debug("NEW row:\n%s"%newrow)
                        try:
                            f=open(filename, 'w', encoding="utf-8")
                            f.write(newrow)
                            f.close()
                        except Exception as e:
                            logger.error("Problem with TPL: %s\n%s\n%s\nRow Data:\n%s"%(filename,e.__class__,str(e),row))
                            txt_dump(str(row),"%s/module_%s.tpl"%(tpldir,files))
                    except Exception as e:
                        logger.error("Problem with TPL:\n%s\n%s\nRow Data:\n%s"%(e.__class__,str(e),line))
                        # Dump
                        txt_dump(str(line),"%s/module_%s.tpl"%(tpldir,files))
        except Exception as e:
            logger.error("Problem parsing data:\n%s\n%s"%(e.__class__,str(e)))
            # Try dumping it instead
            txt_dump(results,"%s/tpl_export.txt"%tpldir)

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