#!/usr/bin/env python3

"""
SW-Manager is a Software that helps Softwaremanagers and Admins but also private users to keep an overview
over their Softwarestack. Supported are the check of EULA Changes and Vulnerabilities.
"""

__author__ = "Raphael Kreft"
__version__ = 0.2
__email__ = "r.kreft@unibas.ch"

import argparse
import logging.config
import os

from src.controller import Controller
from config.logconf import LOGGING_CONFIG
from src.model import ModelError

# configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.config.dictConfig(LOGGING_CONFIG)


def parse_args():
    parser = argparse.ArgumentParser(description="SW-Manager")
    parser.add_argument('-cli', action="store_True", help="If given, Program opens in commandline Interface. "
                                                          "If not It runs as script based on input")
    parser.add_argument('-input', '-i', type=str, required=True, help="Path to input for Software Data.")
    parser.add_argument('-output', '-o', type=str, default=False)
    return parser.parse_args()


def cli():
    controller = None
    running = True
    while running:
        command_input = input(">> ")
        if command_input == "help":
            print("Commands: help, exit, list, check_eula, check_cve")
        elif command_input == "exit":
            running = False


if __name__ == "__main__":
    print(f"--- SW-Manager ---\n-Version: {__version__}\n-By: {__author__}\n-Contact me: {__email__}\n\n")
    args = parse_args()
    try:
        # create controller and load cli if wanted. If not, continue as script
        controller = Controller()
        controller.load_model(args.input)
        if args.cli:
            cli()
        
        # list all software
        logging.info("--- Script Mode ---")
        logging.info("Following Software is Available in the Model:")
        all_software = controller.all_software(verbose=True)
        for num, sw in enumerate(all_software):
            logging.info(f"--> {num}: {sw}")

        # run eula Check
        controller.run_eula_check()
        
    except ModelError as ex:
        logging.error(str(ex))

