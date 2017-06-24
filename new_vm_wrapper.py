#!/usr/bin/env python

import json
import os
import sys
import ipaddress
from pathlib import Path

DEFAULTS_PATH = '/tmp/defaults.json'


def query_yes_no(question, default="yes"):
    # Available from https://stackoverflow.com/questions/3041986/apt-command-line-interface-like-yes-no-input
    """

    :param question: String to be asked as a question
    :param default: Default answer to the question
    :return: True or False to the question
    """

    valid = {"yes": True, "y": True, "ye": True, "Y": True, "YES": True,
             "no": False, "n": False, "N": False, "NO": False}

    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def handle_list_of_dicts():
    pass


def read_ip():
    pass


def main():
    # Variables for Packages (base_packages, extra_packages, UPGRADE_DIST_FLAG)

    # json.loads default values
    try:
        with open(os.path.expanduser(DEFAULTS_PATH), 'r') as f:
            def_vars = json.load(f)
    except IOError:
        print("Skipping loaded variables, No such FILE: %s" % DEFAULTS_PATH)
        print("You have to provide all variables")
        def_vars = None

    if def_vars:
        print(def_vars)
        for k, v in def_vars.items():
            print(k, v)

    ip_args = ["primary_ip", "primary_netmask", "primary_network",
               "primary_broadcast", "primary_dns1", "primary_dns2", "gateway"]

    # Validate Upgrade Dist
    # "UPGRADE_DIST_FLAG"
    vm_vars = dict()

    UPGRADE_DIST_FLAG = query_yes_no("Do you want to update/upgrade the system?")

    # Validate Key Path
    if "main_key_path" not in def_vars or not Path(os.path.expanduser(def_vars["main_key_path"])).is_file():
        print("default \"main_key_path\" points to an invalid file. Ignoring\n")
        main_key_path = None
    else:
        print("Default value for \"main_key_path\" points to %s.\n" % def_vars["main_key_path"])
        if query_yes_no("Keep the default value?"):
            main_key_path = def_vars["main_key_path"]
        else:
            main_key_path = None
            while not main_key_path or not Path(os.path.expanduser(main_key_path)).is_file():

    print(main_key_path)
    for ip_arg in ip_args:
        if ip_arg in def_vars:
            print("\nDefault Value for \"%s\" is:\t %s\n" % (ip_arg, def_vars[ip_arg]))
            if query_yes_no("Keep the default value?"):
                vm_vars[ip_arg] = def_vars[ip_arg]
                break
        else:
            print("\nNo default value for \"%s\". Please enter one!\n" % ip_arg)
            ip_arg = None
            while not ip_arg:
                try:
                    ip_arg = ipaddress.ip_address(input("Enter a file path for main_key: >> "))
                except ValueError:
                    print("Bad IP address!")
                    ip_addr = None
            # TODO check about variable mutable cod
            vm_vars[ip_arg] = def_vars[ip_arg]


    # TODO
    priv_args = []



    extra_pack = []
    # main_key_path,3no
    # exempt addresses

    # network stuff

    print(vm_vars)

    with open('/tmp/vars.json', 'w') as f:
        json.dump(vm_vars, f)
    # FIND FREE IP
    return 0

if __name__ == '__main__':
    main()
