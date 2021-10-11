#!/usr/bin/env python3

"""
CVE-Checker takes a csv file as input and checks every software for new entries in CVE Database of NVD.
If there are new entries the user gets a notification for this software in this version.

main.py: uses excel-utils and api to perform following action:
            For every software read from the source as software-dict, the api is queried for new results
"""

__author__ = "Raphael Kreft"
__version__ = 0.2
__email__ = "r.kreft@unibas.ch"

import argparse
import datetime

from api import search_by_name_and_date, NoDataReceivedError
from excel_utils import read_software_data, dumb_updated_data


def parse_args():
    parser = argparse.ArgumentParser(description="CVE_Checker takes a list of Software with dates from a csv or excel "
                                                 "file and queries Nvd api to check for new CVE's")
    parser.add_argument('-input', '-i', type=str, required=True, help="Input file that contains the Softwaredata")
    parser.add_argument('-excel', '-e', action='store_true', help="Flag, that tells whether the given file is an "
                                                                  "excel file or not")
    parser.add_argument('-delimiter', '-d', type=str, default=',', help="Separator of data fields in a row. Default "
                                                                        "is ,. Not neccessary when -excel is True")
    parser.add_argument('-output', '-o', type=str, default=False)
    parser.add_argument('-name_col', '-nc', type=int, default="Name", help="The number of the column that contains "
                                                                           "the Name of the Software")
    parser.add_argument('-date_col', '-dc', type=int, default="Last_checked", help="The number of the column that "
                                                                                   "contains the date when the last "
                                                                                   "security check was performed")
    return parser.parse_args()


if __name__ == "__main__":
    print(f"--- CVE_Checker ---\n-Version: {__version__}\n-By: {__author__}\n-Contact me: {__email__}\n\n")
    args = parse_args()
    try:
        # 1st step: Read file to get Software Information
        data = read_software_data(args.input, args.name_col, args.date_col, args.delimiter, args.excel)
        # 2nd step: For each entry from the file, perform a search for new Cve's
        for i in range(1, len(data)):  # TODO: make more modular -> dynamic handling of column headers
            try:
                print(f"Checking {data[i][args.name_col]}...")
                result = search_by_name_and_date(data[i][args.name_col], data[i][args.date_col])
                data[i][args.date_col] = datetime.datetime.now()
                data[i][2] = f"[{len(result.get_cve_id_list())}]-> " + ",".join(result.get_cve_id_list())
                data[i][3] = result.get_max_severity()
            except IOError as e:
                print(e)
            except NoDataReceivedError as e:
                print(e)
                continue
        # if no output is specified, overwrite input-file
        if not args.output:
            args.output = args.input
        # 3rd step: Write back data to a file
        dumb_updated_data(output_file=args.output, software_list=data, delimiter=args.delimiter, excel=args.excel)
    except IOError as e:
        print(e)
        exit()
