#!/usr/bin/env python

import json
import os
import sys
import ipaddress
from pathlib import Path

DEFAULTS_PATH = 'new_vm_defaults.json'

ip_args = ["primary_ip", "primary_netmask", "primary_network",
           "primary_broadcast", "primary_dns1", "primary_dns2", "gateway"]


class HostExemption:
    def __init__(self, **kwargs):
        validator = self.validate(**kwargs)

    @staticmethod
    def validate(raise_f=True, **kwargs):
        needed_args = ["id", "state", "addr"]
        acceptable = {
            "state": ["absent", "present"]
        }

        for arg in needed_args:
            if arg not in kwargs or not kwargs[arg]:
                if raise_f:
                    raise ValueError
                else:
                    return False

        if not isinstance(kwargs["id"], int):
            if raise_f:
                raise TypeError("id is not an Integer")
            else:
                return False

        if kwargs["state"] != "present" and kwargs["state"] != "absent":
            print("\nValue not acceptable!\n"+json.dumps(acceptable["state"], indent=4))
            if raise_f:
                raise ValueError("Invalid state value. Select one from the list.")
            else:
                return False

        try:
            ipaddress.ip_address(kwargs["addr"])
        except ValueError:
            if raise_f:
                ipaddress.ip_address(kwargs["addr"])
            else:
                return False

        return True

    @staticmethod
    def read_priviliged_hosts(priv_len=1):
        func_priv_args = []
        while True:
            priv_dict = {
                "addr": input("Enter an IP Address for Privileged Host, Empty to Stop : >> "),
                "id": priv_len,
                "state": query_yes_no("State: Present?")
            }
            if priv_dict["state"]:
                priv_dict["state"] = "present"
            else:
                priv_dict["state"] = "absent"

            if not priv_dict["addr"]:
                break

            if HostExemption.validate(raise_f=False, **priv_dict):
                func_priv_args.append(priv_dict)

            priv_len += 1

        return func_priv_args


class ExtraPackages:
    def __init__(self, **kwargs):
        validator = self.validate(**kwargs)

    @staticmethod
    def validate(raise_f=True, **kwargs):
        needed_args = ["name", "state"]
        acceptable = {
            "state": ["absent", "present", "latest"],
            "name": ["vim", "git", "nmap", "tcpdump", "iptables", "iptables-persistent", "ufw", "netstat"]
        }

        for arg in needed_args:
            if arg not in kwargs or not kwargs[arg]:
                if raise_f:
                    raise ValueError
                else:
                    return False

        if kwargs["name"] not in acceptable["name"]:
            print("\nValue not acceptable!\n"+json.dumps(acceptable["name"], indent=4))
            if raise_f:
                raise ValueError("Invalid Package Name. Select one from the list.")
            else:
                return False

        if kwargs["state"] not in acceptable["state"]:
            print("\nValue not acceptable!\n"+json.dumps(acceptable["state"], indent=4))
            if raise_f:
                raise ValueError("Invalid state value. Select one from the list.")
            else:
                return False

        return True

    @staticmethod
    def read_extra_packages():
        func_extra_packages = []
        while True:
            package_dict = {
                "name": input("Enter Package Name, Empty to Stop : >> "),
                "state": input("Enter the state of the package, Empty = Present : >> ") or "present"
            }

            if not package_dict["name"]:
                break

            if ExtraPackages.validate(raise_f=False, **package_dict):
                func_extra_packages.append(package_dict)
        return func_extra_packages


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


def read_pub_key():
    main_key_path = None
    while not main_key_path or not Path(os.path.expanduser(main_key_path)).is_file():
        main_key_path = input("Enter a file path for main_key: >> ")

    return main_key_path


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

    print(json.dumps(def_vars, indent=4))

    # Validate Upgrade Dist
    # "UPGRADE_DIST_FLAG"
    vm_vars = dict()

    vm_vars["UPGRADE_DIST_FLAG"] = query_yes_no("Do you want to update/upgrade the system?")

    # Validate Key Path
    if "main_key_path" not in def_vars or not Path(os.path.expanduser(def_vars["main_key_path"])).is_file():
        print("default \"main_key_path\" points to an invalid file or does not exist. Ignoring\n")

        main_key_path = read_pub_key()

    else:
        print("Default value for \"main_key_path\" points to %s.\n" % def_vars["main_key_path"])
        if query_yes_no("Keep the default value?"):
            main_key_path = def_vars["main_key_path"]
        else:
            main_key_path = read_pub_key()

    print(main_key_path)
    vm_vars["main_key_path"] = main_key_path

    # Validate IP Settings
    for ip_arg in ip_args:
        if ip_arg in def_vars:
            print("\nDefault Value for \"%s\" is:\t %s\n" % (ip_arg, def_vars[ip_arg]))
            if query_yes_no("Keep the default value?"):
                vm_vars[ip_arg] = def_vars[ip_arg]
                continue
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
    if "privileged_host" in def_vars:
        # VALIDATE Already Present vars
        priv_args = [elem for elem in def_vars["privileged_host"]
                     if HostExemption.validate(raise_f=False, **elem)
                     and query_yes_no(json.dumps(elem, indent=4)+"\nKeep this?\n")]

        print("\nAll Hosts:\n"+json.dumps(def_vars["privileged_host"]))
        if query_yes_no("Do you want to insert more?"):
            print("\nPlease enter IPs. Or enter empty string to stop\n")
            for elem in HostExemption.read_priviliged_hosts(priv_len=len(priv_args)+1):
                priv_args.append(elem)

            print("\nAll Hosts:\n" + json.dumps(priv_args))

    else:
        priv_args = []
        print("\nNo privileged host. Please enter IPs. Or enter empty string to stop\n")
        for elem in HostExemption.read_priviliged_hosts():
            priv_args.append(elem)

    vm_vars["privileged_host"] = priv_args

    if "extra_packages" in def_vars:
        # VALIDATE Already Present vars
        extra_pack = [elem for elem in def_vars["extra_packages"]
                      if ExtraPackages.validate(raise_f=False, **elem)
                      and query_yes_no(json.dumps(elem, indent=4)+"\nKeep this?\n")]

        print("\nAll packages:\n"+json.dumps(def_vars["extra_packages"]))

        if query_yes_no("Do you want to insert more?"):
            print("\nEnter Packages.\n")
            for elem in ExtraPackages.read_extra_packages():
                extra_pack.append(elem)

        print("\nAll packages:\n"+json.dumps(def_vars["extra_packages"]))

    else:
        extra_pack = []
        print("\nNo packages. Please enter package name. Or enter empty string to stop\n")
        for elem in ExtraPackages.read_extra_packages():
            extra_pack.append(elem)

    vm_vars["extra_packages"] = extra_pack

    print(json.dumps(vm_vars, indent=4))

    with open('new_vm_vars.json', 'w') as f:
        json.dump(vm_vars, f, indent=4)
    # FIND FREE IP
    return 0

if __name__ == '__main__':
    main()
