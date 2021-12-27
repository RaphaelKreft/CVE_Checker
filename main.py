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
import logging
import os

from nvd_api import APIError, NvdApi
from excel_utils import read_software_data, dumb_updated_data


# configure logger
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(filename=f'logs/{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
                    encoding='utf-8',
                    level=logging.INFO,
                    format='[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
                    datefmt='%H:%M:%S')


def parse_args():
    parser = argparse.ArgumentParser(description="CVE_Checker takes a list of Software with dates from a csv or excel "
                                                 "file and queries Nvd api to check for new CVE's")
    parser.add_argument('-input', '-i', type=str, required=True, help="Input file that contains the Softwaredata")
    parser.add_argument('-excel', '-e', action='store_true', help="Flag, that tells whether the given file is an "
                                                                  "excel file or not")
    parser.add_argument('-delimiter', '-d', type=str, default=',', help="Separator of data fields in a row. Default "
                                                                        "is ,. Not neccessary when -excel is True")
    parser.add_argument('-output', '-o', type=str, default=False)
    parser.add_argument('-name_col', '-nc', type=int, default=1, help="The number of the column that contains "
                                                                      "the Name of the Software")
    parser.add_argument('-date_col', '-dc', type=int, default=2, help="The number of the column that "
                                                                      "contains the date when the last "
                                                                      "security check was performed")
    return parser.parse_args()


if __name__ == "__main__":
    print(f"--- CVE_Checker ---\n-Version: {__version__}\n-By: {__author__}\n-Contact me: {__email__}\n\n")
    logging.info("Program Start - Parse args...\n")
    args = parse_args()
    nvdApi = NvdApi()
    try:
        # 1st step: Read file to get Software Information
        logging.info(f"Start reading in Data from file: {args.input}")
        data = read_software_data(args.input, args.name_col, args.date_col, args.delimiter, args.excel)
        # 2nd step: For each entry from the file, perform a search for new Cve's
        for i in range(1, len(data)):
            try:
                logging.info(f"Checking {data[i][args.name_col]}...")
                # send query and save result
                result = nvdApi.search_by_name_and_date(data[i][args.name_col], data[i][args.date_col])
                data[i][args.date_col] = datetime.datetime.now()
                data[i][2] = f"[{len(result.get_cve_id_list())}]-> " + ",".join(result.get_cve_id_list())
                data[i][3] = result.get_max_severity()
            except APIError as e:
                pass
            finally:
                continue
        # if no output is specified, overwrite input-file
        if not args.output:
            logging.warning("As no outfile is given: Overwrite Inputfile!")
            args.output = args.input
        # 3rd step: Write back data to a file
        logging.info(f"Write results to {args.output}")
        dumb_updated_data(output_file=args.output, software_list=data, delimiter=args.delimiter, excel=args.excel)
    except IOError as e:
        logging.critical(f"IOError: {e}")
        exit()
