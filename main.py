#!/usr/bin/env python3

"""
CVE-Checker takes a csv file as input and checks every software for new entries in CVE Database of NVD.
If there are new entries the user gets a notification for this software in this version.

main.py: 
"""

__author__ = "Raphael Kreft"
__version__ = 0.1
__email__ = "raphael.kreft@bis.org"

import argparse
import datetime
import json
import csv
import os

import api

NVD_TIME_FORMAT = "%Y-%m-%dT%H:%MZ"

def parse_args():
    parser = argparse.ArgumentParser(description="Enter IP and Port to Connect to")
    parser.add_argument('-input', '-i', type=str, required=True)
    parser.add_argument('-excel', '-e', action='store_true')
    parser.add_argument('-delimiter', '-d', type=str, default=',')
    return parser.parse_args()


def read_software_data(inputfile, dilimeter, excel):
    if not os.path.isfile(inputfile):
        raise IOError(f"File {inputfile} doesn't exist!")
    else:
        software_dict = {}
        with open(inputfile, newline='') as f:
            if excel:
                csvreader = csv.reader(f, dialect='excel')
            else:
                csvreader = csv.reader(f, dilimeter=dilimeter)
            for row in csvreader:
                software_dict[str(row[0])] = row[1] if len(row) >= 2 else "" 
        return software_dict


def dumb_updated_data(outputfile, dilimeter, excel, software_dict):
    if not os.path.isfile(outputfile):
        raise IOError(f"File {outputfile} doesn't exist!")
    else:
        with open(outputfile, newline='', mode='w') as f:
            if excel:
                csvwriter = csv.writer(f, dialect='excel')
            else:
                csvwriter = csv.writer(f, dilimeter=dilimeter)
            for key in software_dict.keys():
                csvwriter.writerow([key, software_dict[key]])


if __name__ == "__main__":
    print(f"--- CVE_Checker ---\n-Version: {__version__}\n-By: {__author__}\n-Contact me: {__email__}\n\n")
    args = parse_args()
    try:
        data = read_software_data(args.input, args.dilimeter, args.excel)
        for key in data.keys():
            try:
                ID, date_string = api.search_for_entries(key, data[key][1])
                new_date = datetime.strptime(date_string, NVD_TIME_FORMAT)
                if data[key][1] == "" or new_date > datetime.strptime(data[key][1], NVD_TIME_FORMAT):
                    data[key][0] = date_string
                    print(f"New latest entry for {key}!: {ID}\n")
            except IOError as e:
                print(e)
        dumb_updated_data(args.output, args.dilimeter, args.excel, data)
    except IOError as e:
        exit(e)
