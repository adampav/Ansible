#!/usr/bin/env python
import ipaddress
import os

from populate_role_vars import main as populator
from populate_role_vars import select_playbook
from populate_role_vars import query_yes_no
from populate_role_vars import POPULATED_VARS_OUTPUT
from populate_role_vars import PLAYBOOK_PATH
import argparse


def_run_parameters = {
    "user": "root",
    "password": False,
    "sudo": False,
    "interactive": False,
    "populate_vars": False,
    "debug": False
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


def main():
    playbook = args.playbook
    if not playbook:
        playbook = select_playbook()
        if args.populate_vars or query_yes_no("Populate Vars."):
            populator(playbook=playbook)

    user = def_run_parameters["user"]

    while args.interactive and query_yes_no("Change value?\n\"user\":\t{0}".format(user), default="no"):
        user = input("Please enter the user to run Ansible as: >> ")

    # TODO read private key file

    exec_list = [
        'ansible-playbook',
        '{0}/{1}.yml'.format(PLAYBOOK_PATH, playbook),
        '-u',
        args.user or user
    ]

    password = def_run_parameters["password"]

    while args.interactive and query_yes_no("Change value?\n\"password\":\t{0}".format(str(password)), default="no"):
        password = query_yes_no("Password Authentication?")

    if args.password or password:
        exec_list.append('-k')

    sudo = def_run_parameters["sudo"]

    while args.interactive and query_yes_no("Change value?\n\"sudo\":\t{0}".format(str(sudo)), default="no"):
        sudo = query_yes_no("Elevate privileges?")

    if args.sudo or sudo:
        exec_list.append('-K')

    # TODO read inventory? / read IP ???

    if args.interactive and query_yes_no("Read IP?"):
        exec_list.append("-i")
        ip_addr = None
        while not ip_addr:
            try:
                ip_addr = ipaddress.ip_address(input("Enter IP address for target host: >>\t"))
            except ValueError:
                print("Enter a valid IP!\n")

        exec_list.append(str(ip_addr))

    elif args.interactive and query_yes_no("Read Inventory Host/Group?"):
        exec_list.append("-l")
        exec_list.append(input("Please enter a name for Host or Group: >>\t"))
    else:
        if args.inventory:
            exec_list.append("-i")
            exec_list.append("'{0}',".format(args.inventory))
        elif args.limit:
            exec_list.append("-l")
            exec_list.append("'{0}'".format(args.limit))
        elif query_yes_no("Do you want to run against all hosts in \"/etc/ansible/hosts\" ?"):
            pass
        else:
            exit()

    exec_list.append('-e')
    exec_list.append("@" + POPULATED_VARS_OUTPUT)

    command = ""
    for elem in exec_list:
        command += elem + ' '

    print(command)
    if args.debug and not query_yes_no("Do you want to execute the command?", default="no"):
        exit()

    os.system(command)

if __name__ == "__main__":
    args = parser.parse_args()
    main()
