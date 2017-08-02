#!/usr/bin/env python
import ipaddress
import os

import time

from populate_role_vars import main as populator
from populate_role_vars import select_playbook, generate_temporary_playbook
from populate_role_vars import query_yes_no
from populate_role_vars import POPULATED_VARS_OUTPUT
from populate_role_vars import PLAYBOOK_PATH
import argparse
from utils import UserLog
userlog = UserLog()


def_run_parameters = {
    "user": "root",
    "password": False,
    "sudo": False,
    "interactive": False,
    "populate_vars": False,
    "debug": False,
    "roles": False,
    "custom_vars": "populated_vars.json"
}

parser = argparse.ArgumentParser(description="Orchestrator is a cool wrapper for using Ansible :) ")
parser.add_argument('--interactive',
                    help='Runs the wrapper in an interactive manner.',
                    default=def_run_parameters["interactive"],
                    action='store_true')

parser.add_argument('--populate_vars',
                    help='Populate vars for execution?',
                    default=def_run_parameters["populate_vars"],
                    action='store_true')

parser.add_argument('--password',
                    help='Use Password Based authentication.',
                    default=def_run_parameters["interactive"],
                    action='store_true')

parser.add_argument('--sudo',
                    help='Privilege Escalation.',
                    default=def_run_parameters["interactive"],
                    action='store_true')

parser.add_argument('--debug',
                    help='Dry Run Execution.',
                    default=def_run_parameters["debug"] or False,
                    action='store_true')

parser.add_argument('--custom_vars',
                    type=str,
                    help='Provides a custom variables file to Ansible runtime',
                    default=def_run_parameters["custom_vars"])

parser.add_argument('--user',
                    type=str,
                    help='User to run ansible as.',
                    default='root')

parser.add_argument('--inventory',
                    type=str,
                    help='Supply inventory.',
                    default=None)

parser.add_argument('--limit',
                    type=str,
                    help='Supply limited subset of targets.',
                    default=None)

parser.add_argument('--playbook',
                    type=str,
                    help='Provide playbook.',
                    default=None)

parser.add_argument('--roles',
                    help='Choose from a list of Roles.',
                    default=def_run_parameters["roles"],
                    action='store_true')


def main():
    playbook = args.playbook
    if not playbook:
        if not args.roles and query_yes_no(userlog.warn("Select a playbook?")):
            playbook = select_playbook()
        elif args.roles or query_yes_no(userlog.warn("Select roles?")):
            print(userlog.error("=== Creating Custom Playbook ==="))
            generate_temporary_playbook()
            playbook = "temporary"
        else:
            exit()

    if args.populate_vars or query_yes_no(userlog.info("Populate Vars?"), default="no"):
        populator(playbook=playbook)

    # RUN USER FOR ANSIBLE
    user = args.user or def_run_parameters["user"]
    password = args.password or def_run_parameters["password"]
    sudo = args.sudo or def_run_parameters["sudo"]
    inventory = args.inventory
    limit = args.limit

    if args.interactive:
        # Interactively READ RUN USER
        while query_yes_no(userlog.warn("Change value?\n\"user\":\t{0}".format(user)), default="no"):
            user = input(userlog.error("Please enter the user to run Ansible as: >> "))

        # Interactively READ RUN USER
        while query_yes_no(userlog.warn("Change value?\n\"password\":\t{0}".format(str(password))),
                           default="no"):
            password = query_yes_no(userlog.info("Password Authentication?"))

        # Interactively READ RUN USER
        while query_yes_no(userlog.warn("Change value?\n\"sudo\":\t{0}".format(str(sudo))),
                           default="no"):
            sudo = query_yes_no("Elevate privileges?")

        # Interactively READ INVENTORY/LIMIT
        if query_yes_no(userlog.info("Read IP?")):
            ip_addr = None
            while not ip_addr:
                try:
                    ip_addr = ipaddress.ip_address(input(userlog.error("Enter IP address for target host: >>\t")))
                except ValueError:
                    print("Enter a valid IP!\n")

            inventory = (str(ip_addr))

        if query_yes_no("Read Inventory Host/Group?"):
            limit = (input("Please enter a name for Host or Group: >>\t"))

    # TODO read private key file

    exec_list = [
        'ansible-playbook',
        '{0}/{1}.yml'.format(PLAYBOOK_PATH, playbook),
        '-u',
        user
    ]

    if password:
        exec_list.append('-k')

    if sudo:
        exec_list.append('-K')

    if inventory:
        exec_list.append("-i")
        exec_list.append("'{0}',".format(args.inventory))

    if limit:
        exec_list.append("-l")
        exec_list.append("'{0}'".format(args.limit))

    if inventory or limit or query_yes_no(userlog.error("Run on all hosts in \"/etc/ansible/hosts\" ?")):
        pass
    else:
        exit()

    if args.custom_vars:
        exec_list.append('-e')
        exec_list.append("@" + POPULATED_VARS_OUTPUT)

    command = ""
    for elem in exec_list:
        command += elem + ' '

    print(userlog.info(command))
    if args.debug and not query_yes_no(userlog.warn("Do you want to execute the command?"), default="no"):
        exit()
    else:
        time.sleep(2)

    os.system(command)

if __name__ == "__main__":
    args = parser.parse_args()
    main()
