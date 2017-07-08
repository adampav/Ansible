#!/usr/bin/env python
from populate_role_vars import main as populator
from populate_role_vars import select_playbook
from populate_role_vars import query_yes_no
from populate_role_vars import POPULATED_VARS_OUTPUT
from populate_role_vars import PLAYBOOK_PATH
import subprocess

def_run_parameters = {
    "user": "root",
    "password": False,
    "sudo": False
}

interactive = True


def main():
    playbook = select_playbook()
    if query_yes_no("Populate Vars."):
        populator(playbook=playbook)

    user = def_run_parameters["user"]

    while interactive and not user and query_yes_no("Change value?\n\"user\":\t{0}".format(user), default=False):
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

    while interactive and query_yes_no("Change value?\n\"password\":\t{0}".format(str(password)), default=False):
        password = query_yes_no("Password Authentication?")

    if password:
        exec_list.append('-k')

    sudo = def_run_parameters["sudo"]

    while interactive and query_yes_no("Change value?\n\"sudo\":\t{0}".format(str(sudo)), default=False):
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
    main()
    # TODO implement argparse
