#!/usr/bin/env python

import json
import yaml
import os
import sys
import ipaddress
from pathlib import Path

DEFAULTS_PATH = 'new_vm_defaults.json'
ROLE_PATH = 'administration/roles'
CUSTOM_ROLE_VARS = 'ansible-files/roles_var'
PLAYBOOK_PATH = 'administration'
ROLES = 'roles.json'
PLAYBOOKS = 'playbooks.json'
PLAYBOOK_ROLES = 'playbook_roles.json'
POPULATED_VARS_OUTPUT = 'populated_vars.json'
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


class Packages:
    def __init__(self, **kwargs):
        self.validated = self.validate(**kwargs)

    @staticmethod
    def validate(raise_f=True, **kwargs):
        needed_args = ["name", "state"]
        acceptable = {
            "state": [
                "absent",
                "present",
                "latest"
            ],
            "name": [
                "vim", "nano", "git",
                "nmap", "tcpdump", "iptables", "iptables-persistent", "ufw", "netstat",
                "python", "python3"
            ]
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

            if Packages.validate(raise_f=False, **package_dict):
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


def read_pub_key():
    key_path = None
    while not key_path or not Path(os.path.expanduser(key_path)).is_file():
        key_path = input("Enter a file path for main_key: >> ")

    return key_path


def read_beats():
    pass


def read_fail2ban():
    pass


def read_iptables():
    pass


def read_hostnames():
    pass


def read_network_configuration(def_vars):
    read_dict = dict()
    # Validate IP Settings
    for ip_arg in ip_args:
        if ip_arg in def_vars:
            print("\nDefault Value for \"%s\" is:\t %s\n" % (ip_arg, def_vars[ip_arg]))
            if query_yes_no("Keep the default value?"):
                read_dict[ip_arg] = def_vars[ip_arg]
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
            read_dict[ip_arg] = str(ip_addr)

    return read_dict


def read_packages(def_vars):
    read_dict = dict()

    # UPGRADE SYSTEM
    read_dict["UPGRADE_DIST_FLAG"] = query_yes_no("Do you want to update/upgrade the system?")

    # READ BASE PACKAGES
    if "base_packages" in def_vars:
        # VALIDATE Already Present vars
        base_pack = [elem for elem in def_vars["base_packages"]
                     if Packages.validate(raise_f=False, **elem)
                     and query_yes_no(json.dumps(elem, indent=4)+"\nKeep this?\n")]

        print("\nAll packages:\n"+json.dumps(def_vars["base_packages"]))

        if query_yes_no("Do you want to insert more?"):
            print("\nEnter Packages.\n")
            for elem in Packages.read_extra_packages():
                base_pack.append(elem)

        print("\nAll packages:\n"+json.dumps(def_vars["base_packages"]))
    else:
        base_pack = []
        print("\nNo packages. Please enter package name. Or enter empty string to stop\n")
        for elem in Packages.read_extra_packages():
            base_pack.append(elem)

    if base_pack:
        read_dict["base_packages"] = base_pack
    else:
        if query_yes_no("Install NO base packages?"):
            read_dict["base_packages"] = base_pack

    # READ EXTRA PACKAGES
    if "extra_packages" in def_vars:
        # VALIDATE Already Present vars
        extra_pack = [elem for elem in def_vars["extra_packages"]
                      if Packages.validate(raise_f=False, **elem)
                      and query_yes_no(json.dumps(elem, indent=4)+"\nKeep this?\n")]

        print("\nAll packages:\n"+json.dumps(def_vars["extra_packages"]))

        if query_yes_no("Do you want to insert more?"):
            print("\nEnter Packages.\n")
            for elem in Packages.read_extra_packages():
                extra_pack.append(elem)

        print("\nAll packages:\n"+json.dumps(def_vars["extra_packages"]))
    else:
        extra_pack = []
        print("\nNo packages. Please enter package name. Or enter empty string to stop\n")
        for elem in Packages.read_extra_packages():
            extra_pack.append(elem)

    if extra_pack:
        read_dict["extra_packages"] = extra_pack
    else:
        if query_yes_no("Install NO extra packages?"):
            read_dict["extra_packages"] = extra_pack
    read_dict["extra_packages"] = extra_pack

    return read_dict


def read_saltstack():
    pass


def read_ssh_keys(def_vars):
    read_dict = dict()
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
    read_dict["main_key_path"] = main_key_path

    return read_dict


def read_sshd_configuration(def_vars):
    read_dict = dict()
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

    read_dict["privileged_host"] = priv_args

    return read_dict


def select_roles():
    try:
        with open(ROLES, 'r') as f:
            roles = list(json.load(f))
        print("\nAvailable Roles are:\n"+json.dumps(roles, indent=4))

        chosen_roles = []

        while True:
            i = 0
            for role in roles:
                print('{0} -> {1}'.format(i, role))
                i += 1

            choice = input("\nSelet one from the choices above using the number.\nEmpty to stop.\n")

            if not choice:
                if chosen_roles:
                    break
            elif int(choice) not in range(0, len(roles)):
                print("\nInvalid Choice\n")
                continue
            else:
                chosen_roles.append(roles[int(choice)])
                roles.remove(roles[int(choice)])

        print(json.dumps(list(set(chosen_roles)), indent=4))

        return list(set(chosen_roles))
    except IOError:
        print("No Roles specified. Exiting")
        return None


def select_playbook():
    try:
        # Another implementation is to read all YML files in a directory
        with open(PLAYBOOKS, 'r') as f:
            playbooks = json.load(f)
    except IOError:
        print("No valid file for Playbook provided. Returning \"None\"")
        return None

    playbooks.sort()
    while True:
        i = 0
        for playbook in playbooks:
            print('{0} -> {1}'.format(i, playbook))
            i += 1

        choice = input("\nPlease Select one choice as listed above.\n")

        if choice and int(choice) in range(0, len(playbooks)):
            break
        else:
            print("\nInvalid Choice\n")

    # TODO FOR PLAYBOOK READ ROLES

    chosen_playbook = playbooks[int(choice)]
    print(chosen_playbook)

    return chosen_playbook


def generate_temporary_playbook():
    pass


def read_role_vars(role=None):
    # TODO read defaults/main.yml

    # update the role_vars dict with CUSTOM_ROLE_VARS
    try:
        with open(CUSTOM_ROLE_VARS + "/{0}/my_vars.yml".format(role)) as f:
            role_vars = yaml.load(f)
        print(json.dumps(role_vars, indent=4))
    except IOError:
        print("File: " + CUSTOM_ROLE_VARS + "/{0}/my_vars.yml not found.".format(role))
        role_vars = dict()

    if role == "manage-beats":
        # TODO read important role_vars for beats
        print(role)
        role_vars = read_beats(role_vars)
    elif role == "manage-fail2ban":
        # TODO read important role_vars for fail2ban
        print(role)
        role_vars = read_fail2ban(role_vars)
    elif role == "manage-hostnames":
        # TODO read important role_vars for hostname
        print(role)
        role_vars = read_hostnames(role_vars)
    elif role == "manage-iptables":
        # TODO read important role_vars for iptables
        print(role)
        role_vars = read_iptables(role_vars)
    elif role == "manage-network-configuration":
        print(role)
        role_vars = read_network_configuration(role_vars)
    elif role == "manage-packages":
        print(role)
        role_vars = read_packages(role_vars)
    elif role == "manage-saltstack-deployment":
        # TODO read important role_vars for saltstack
        print(role)
        role_vars = read_saltstack(role_vars)
    elif role == "manage-ssh-keys":
        print(role)
        role_vars = read_ssh_keys(role_vars)
    elif role == "manage-ssh-known_hosts":
        print(role)
        role_vars = {}
    elif role == "manage-sshd-configuration":
        print(role)
        role_vars = read_sshd_configuration(role_vars)
    else:
        role_vars = {}

    try:
        os.makedirs(CUSTOM_ROLE_VARS + "/{0}/".format(role))
    except FileExistsError:
        pass

    with open(CUSTOM_ROLE_VARS + "/{0}/my_vars.yml".format(role), 'w') as f:
        yaml.dump(role_vars, f)
    print("Printing to File: " + CUSTOM_ROLE_VARS + "/{0}/my_vars.yml\n".format(role)
          + json.dumps(role_vars, indent=4) + "\n\n")

    return role_vars


def main(playbook=None):
    roles = None
    # Case 1 -> Playbooks available
    if playbook or query_yes_no("Select a playbook?"):
        if not playbook:
            playbook = select_playbook()
        try:
            with open(PLAYBOOK_PATH + "/{0}.yml".format(playbook)) as f:
                role_yaml = yaml.load(f)
                roles = role_yaml[1]["roles"]
            print(json.dumps(roles, indent=4))
        except IOError:
            print("Problem extracting roles from playbook")
            playbook = None

    if not roles and not query_yes_no("Select Roles?"):
        print("No valid Options. Exiting")
        return 0

    # Case 2 -> Select Roles Ad Hoc
    if not roles:
        roles = select_roles()

    vm_vars = {}
    for role in roles:
        vm_vars.update(read_role_vars(role=role))

    print(json.dumps(vm_vars, indent=4))

    with open(POPULATED_VARS_OUTPUT, 'w') as f:
        json.dump(vm_vars, f, indent=4)
    return 0

if __name__ == '__main__':
    if len(sys.argv) != 2:
        main()
    else:
        main(playbook=sys.argv[1])