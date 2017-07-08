#!/usr/bin/env python
from populate_role_vars import main as populator
from populate_role_vars import select_playbook
from populate_role_vars import query_yes_no
from populate_role_vars import POPULATED_VARS_OUTPUT
from populate_role_vars import PLAYBOOK_PATH
import subprocess


def main():
    playbook = select_playbook()
    if query_yes_no("Populate Vars."):
        populator(playbook=playbook)

    # TODO read user
    user = "some_user"

    # TODO read private key file

    exec_list = [
        'ansible-playbook',
        '{0}/{1}.yml'.format(PLAYBOOK_PATH, playbook),
        '-e',
        user
    ]

    # TODO read sudo
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