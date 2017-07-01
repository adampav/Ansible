#!/usr/bin/env python

import json
import os
import sys
import ipaddress
from pathlib import Path

DEFAULTS_PATH = 'new_vm_defaults.json'

ip_args = ["primary_ip", "primary_netmask", "primary_network",
           "primary_broadcast", "primary_dns1", "primary_dns2", "gateway"]


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


def read_priviliged_hosts(priv_len=1):
    func_priv_args = []
    while True:
        priv_dict = dict()
        ip_addr = None
        while not ip_addr:
            read_host = input("Enter an IP Address for Privileged Host : >> ")
            try:
                ip_addr = ipaddress.ip_address(read_host)
            except ValueError:
                if read_host == "":
                    break
                print("Bad IP address!")

        if not read_host:
            break

        read_state = query_yes_no("Host Present?")

        priv_dict["addr"] = ip_addr
        priv_dict["id"] = priv_len

        if read_state:
            priv_dict["state"] = "present"
        else:
            priv_dict["state"] = "absent"

        priv_len += 1

        func_priv_args.append(priv_dict)

    return func_priv_args


def main():
    # Variables for Packages (base_packages, extra_packages, UPGRADE_DIST_FLAG)

    # json.loads default values
    try:
        with open(os.path.expanduser(DEFAULTS_PATH), 'r') as f:
            def_vars = json.load(f)
    except IOError:
        print("Skipping loaded variables, No such FILE: %s" % DEFAULTS_PATH)
        print("You have to provide all variables")
        def_vars = dict()

    if def_vars:
        print(def_vars)
        for k, v in def_vars.items():
            print(k, v)

    # Validate Upgrade Dist
    # "UPGRADE_DIST_FLAG"
    vm_vars = dict()

    UPGRADE_DIST_FLAG = query_yes_no("Do you want to update/upgrade the system?")

    # Validate Key Path
    if "main_key_path" not in def_vars or not Path(os.path.expanduser(def_vars["main_key_path"])).is_file():
        print("default \"main_key_path\" points to an invalid file or does not exist. Ignoring\n")
        main_key_path = None
    else:
        print("Default value for \"main_key_path\" points to %s.\n" % def_vars["main_key_path"])
        if query_yes_no("Keep the default value?"):
            main_key_path = def_vars["main_key_path"]
        else:
            main_key_path = None
            while not main_key_path or not Path(os.path.expanduser(main_key_path)).is_file():
                main_key_path = input("Enter a file path for main_key: >> ")

    print(main_key_path)

    # Validate IP Settings
    for ip_arg in ip_args:
        if ip_arg in def_vars:
            print("\nDefault Value for \"%s\" is:\t %s\n" % (ip_arg, def_vars[ip_arg]))
            if query_yes_no("Keep the default value?"):
                vm_vars[ip_arg] = def_vars[ip_arg]
                break
        else:
            print("\nNo default value for \"%s\"." % ip_arg)
            ip_addr = None

            while not ip_addr:
                try:
                    ip_addr = ipaddress.ip_address(input("Enter an IP Address for %s : >> " % ip_arg))
                except ValueError:
                    print("Bad IP address!")

            # TODO check about variable mutable cod
            vm_vars[ip_arg] = str(ip_addr)

    # TODO
    priv_args = []
    if "privileged_host" in def_vars:
        priv_args = def_vars["privileged_host"]

        # TODO CHECK THE PRIV_HOSTS

        # TODO ASK IF YOU WANT MORE
        for elem in read_priviliged_hosts(priv_len=len(priv_args)):
            priv_args.append(elem)
    else:
        print("\nNo privileged host. Please enter IPs. Or enter empty string to stop\n")
        for elem in read_priviliged_hosts():
            priv_args.append(elem)

    vm_vars["privileged_host"] = priv_args

    # TODO
    extra_pack = []
    # exempt addresses

    vm_vars["extra_packages"] = extra_pack

    print(json.dumps(vm_vars, indent=4))

    with open('new_vm_vars.json', 'w') as f:
        json.dump(vm_vars, f)
    # FIND FREE IP
    return 0

if __name__ == '__main__':
    main()
