#!/usr/bin/env python
from populate_role_vars import main as populator
from populate_role_vars import select_playbook
from populate_role_vars import query_yes_no
from populate_role_vars import POPULATED_VARS_OUTPUT
from populate_role_vars import PLAYBOOK_PATH
import subprocess
import argparse
from argparse import RawTextHelpFormatter

# parser = argparse.ArgumentParser(
#     prog="Orchestrator",
#     formatter_class=RawTextHelpFormatter,
#     epilog=
# )


def str2bool(value):
    ret_value = None
    if value.lower() in ["true"]:
        ret_value = True
    elif value.lower() in ["false"]:
        ret_value = False
    return ret_value


def_run_parameters = {
    "user": "root",
    "password": False,
    "sudo": False,
    "interactive": False
}

parser = argparse.ArgumentParser(description="Orchestrator is a cool wrapper for using Ansible :) ")
parser.add_argument('--interactive',
                    help='Runs the wrapper in an interactive manner.',
                    default=def_run_parameters["interactive"],
                    action='store_true')

parser.add_argument('--password',
                    help='Use Password Based authentication.',
                    default=def_run_parameters["interactive"],
                    action='store_true')

parser.add_argument('--sudo',
                    help='Privilege Escalation.',
                    default=def_run_parameters["interactive"],
                    action='store_true')

parser.add_argument('--user',
                    type=str,
                    help='User to run ansible as.',
                    default='root')


def main(args):
    playbook = select_playbook()
    if query_yes_no("Populate Vars."):
        populator(playbook=playbook)

    user = def_run_parameters["user"]

    while args.interactive and not user and query_yes_no("Change value?\n\"user\":\t{0}".format(user), default=False):
        user = input("Please enter the user to run Ansible as: >> ")

    # TODO read private key file

    exec_list = [
        'ansible-playbook',
        '{0}/{1}.yml'.format(PLAYBOOK_PATH, playbook),
        '-u',
        user,
        '-e',
        POPULATED_VARS_OUTPUT
    ]

    password = def_run_parameters["password"]

    while args.interactive and query_yes_no("Change value?\n\"password\":\t{0}".format(str(password)), default=False):
        password = query_yes_no("Password Authentication?")

    if password:
        exec_list.append('-k')

    sudo = def_run_parameters["sudo"]

    while args.interactive and query_yes_no("Change value?\n\"sudo\":\t{0}".format(str(sudo)), default=False):
        sudo = query_yes_no("Elevate privileges?")

    if sudo:
        exec_list.append('-K')

    # TODO read inventory? / read IP ???

    if query_yes_no("Read IP?"):
        exec_list.append("-i")
    elif query_yes_no("Read Inventory Host/Group?"):
        exec_list.append("-l")
    else:
        pass
    subprocess.call(exec_list)

if __name__ == "__main__":
    args = parser.parse_args()
    print(args)

    main(args)
