#!/usr/bin/env python

from utils import UserLog
import json
import yaml
import os
import sys
import ipaddress
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# TODO put this to configuration

# TODO adopt userlog
userlog = UserLog()
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


### PLAN TO REFACTOR read_iptables() ###
# read
# iptables.
#
# # FILTER/VALIDATE OLD PUBLIC_SERVICES
# # FILTER/VALIDATE OLD RESTRICTED_SERVICES
# # READ NEW SERVICES
# # FAILSAFE: CHECK THERE IS A RULE FOR SSH
#
#
# FirewallRule:
#
# read_public
# read_restricted
#
# read_service
# query
# validate
### END OF PLAN ###

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
                "state": query_yes_no(userlog.warn("State: Present?"))
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
                "name": input(userlog.info("Enter Package Name, Empty to Stop : >>") + ' '),
                "state": input(userlog.info("Enter the state of the package, Empty = Present : >>") + ' ') or "present"
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


def read_pub_key(key="some", break_flag=True):
    key_path = input(userlog.info("Enter a file path for {0} user's key: >>").format(key) + ' ')
    while True:
        if not key_path and break_flag:
            return None
        elif not Path(os.path.expanduser(key_path)).is_file():
            key_path = input(userlog.error("Enter a file path for {0} user's key: >>").format(key) + ' ')
        else:
            return key_path


def read_ip(custom_message="", accept_none=False):
    ip_addr = None
    ip_input = None
    while not ip_addr:
        try:
            ip_input = input(userlog.info("Please enter an IP address{0}: >>").format(custom_message) + ' ')
            ip_addr = ipaddress.ip_address(ip_input)
        except ValueError:
            if accept_none and not ip_input:
                return None
            else:
                print(userlog.error("Bad IP Format. Try again!\n\n"))

    return ip_addr


def read_beats(def_vars):
    read_dict = dict()

    return read_dict


def read_fail2ban(def_vars):
    read_dict = dict()

    return read_dict


def read_iptables(def_vars):
    # TODO fix bug on duplicate addition! do not allow rules on the same port
    read_dict = dict()
    # Filter old rules in public_services
    try:
        read_dict["public_services"] = [elem for elem in def_vars["public_services"]
                                        if (elem["service"] == "ssh" and elem["port"] == 22)
                                        or query_yes_no(userlog.warn("Keep this public service?\n" +
                                                                     json.dumps(elem, indent=4)))]
    except KeyError:
        read_dict["public_services"] = list()

    # Filter old rules in restricted_services
    read_dict["restricted_services"] = [elem for elem in def_vars["restricted_services"]
                                        if (elem["service"] == "ssh" and elem["port"] == 22)
                                        or query_yes_no(userlog.warn("Keep this restricted service?\n" +
                                                                     json.dumps(elem, indent=4)))]
    try:
        pass
    except KeyError:
        read_dict["restricted_services"] = list()

    if query_yes_no(userlog.warn("Enable SSH?")):
        # DEFINE SSH SERVICE
        ssh_service = dict()
        ssh_service["port"] = 22
        ssh_service["service"] = "ssh"
        ssh_service["protocol"] = "tcp"
        ssh_service["iface"] = "{{ iface }}"
        ssh_service["direction"] = "in"

        # REMOVE OLD SSH RULES from public_services
        read_dict["public_services"] = [elem for elem in read_dict["public_services"]
                                        if elem["service"] != "ssh"
                                        and elem["port"] != 22]

        # REMOVE OLD SSH RULES from restricted_services
        read_dict["restricted_services"] = [elem for elem in read_dict["restricted_services"]
                                            if elem["service"] != "ssh"
                                            and elem["port"] != 22]

        if query_yes_no(userlog.warn("Restrict SSH?")):
            ssh_service["sources"] = list()
            while True:
                ip_addr = read_ip(custom_message=" to allow SSH from", accept_none=True)
                if not ip_addr:
                    break
                else:
                    ssh_service["sources"].append(str(ip_addr))

            read_dict["restricted_services"].append(ssh_service)
        else:
            read_dict["public_services"].append(ssh_service)

    while True:
        print(userlog.info("\nPlease Enter New Service\n"))
        service = dict()
        try:
            service["port"] = int(input(userlog.info("Enter Port number: >>") + ' '))
        except ValueError:
            break
        service["service"] = input(userlog.info("Enter Service Name: >> ") + ' ')
        if not service["service"]:
            break

        if query_yes_no("TCP?"):
            service["protocol"] = "tcp"
        elif query_yes_no("UDP?"):
            service["protocol"] = "udp"
        else:
            print(userlog.error("Ignoring Service\n"))
            continue

        service["iface"] = "{{ iface }}"
        if query_yes_no("Ingress?"):
            service["direction"] = "in"
        else:
            service["direction"] = "out"

        if query_yes_no("Restrict Service?"):
            service["sources"] = list()
            while True:
                ip_addr = read_ip(custom_message=" to allow {0} from".format(service["service"]), accept_none=True)
                if not ip_addr:
                    break
                else:
                    service["sources"].append(str(ip_addr))

            read_dict["restricted_services"].append(service)
        else:
            read_dict["public_services"].append(service)

            # TODO Refactor this to a class, like Packages-Hosts

    read_dict["RELOAD_FLAG"] = query_yes_no(userlog.error("ATTENTION!\nReload the rules immediately?\n"
                                                          "This might result in a loss of connectivity"),
                                            default="no")

    # TODO Ask for application of FW rules
    # READ Template for Rules
    # READ allow out ?
    # TODO Implement more services
    # READ BASE services
    # READ RESTRICTED services
    return read_dict


def read_hostnames(def_vars):
    read_dict = dict()

    return read_dict


def read_network_configuration(def_vars):
    read_dict = dict()
    # Validate IP Settings
    for ip_arg in ip_args:
        if ip_arg in def_vars:
            print(userlog.info("\nDefault Value:\t{1}\tfor\t\"{0}\"\n".format(ip_arg, def_vars[ip_arg])))
            if query_yes_no(userlog.warn("Keep the default value?")):
                read_dict[ip_arg] = def_vars[ip_arg]
                continue
            else:
                print(userlog.warn("\nOverwriting default value for \"{0}\".".format(ip_arg)))
                read_dict[ip_arg] = str(read_ip(custom_message=" for {0}".format(ip_arg)))
        else:
            print(userlog.warn("\nNo default value for \"{0}\".".format(ip_arg)))
            read_dict[ip_arg] = str(read_ip(custom_message=" for {0}".format(ip_arg)))

    return read_dict


def read_packages(def_vars):
    read_dict = dict()

    # TODO ditch current logic. Ask for the entire dictionary Keep It ? Else check each one. Consider BASE only?

    # UPGRADE SYSTEM
    read_dict["UPGRADE_DIST_FLAG"] = query_yes_no(userlog.warn("Do you want to update/upgrade the system?"))

    # READ BASE PACKAGES
    if "base_packages" in def_vars:
        # VALIDATE Already Present vars
        base_pack = [elem for elem in def_vars["base_packages"]
                     if Packages.validate(raise_f=False, **elem)
                     and query_yes_no(userlog.info(json.dumps(elem, indent=4)+"\nKeep this?"))]

        print(userlog.warn("\nAll packages:\n"+json.dumps(def_vars["base_packages"], indent=4)))

        if query_yes_no(userlog.info("Do you want to insert more BASE packages?")):
            print(userlog.warn("\nEnter Additional Base Packages.\n"))
            for elem in Packages.read_extra_packages():
                base_pack.append(elem)

        print(userlog.warn("\nAll packages:\n"+json.dumps(def_vars["base_packages"], indent=4)))
    else:
        base_pack = []
        print(userlog.error("\nNo BASE packages. Please enter package name. Or enter empty string to stop\n"))
        for elem in Packages.read_extra_packages():
            base_pack.append(elem)

    if base_pack:
        read_dict["base_packages"] = base_pack
    else:
        if query_yes_no(userlog.warn("Install NO BASE packages?")):
            read_dict["base_packages"] = base_pack

    # READ EXTRA PACKAGES
    if "extra_packages" in def_vars:
        # VALIDATE Already Present vars
        extra_pack = [elem for elem in def_vars["extra_packages"]
                      if Packages.validate(raise_f=False, **elem)
                      and query_yes_no(userlog.info(json.dumps(elem, indent=4)+"\nKeep this?"))]

        print(userlog.warn("\nAll packages:\n"+json.dumps(def_vars["extra_packages"], indent=4)))

        if query_yes_no("Do you want to insert more EXTRA packages?"):
            print("\nEnter Packages.\n")
            for elem in Packages.read_extra_packages():
                extra_pack.append(elem)

        print("\nAll packages:\n"+json.dumps(def_vars["extra_packages"], indent=4))
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


def read_saltstack(def_vars):
    read_dict = dict()
    read_dict["SALT_INSTALL_FLAG"] = query_yes_no(userlog.warn("Install Salt?"), default="no")
    read_dict["SALT_CONFIGURE_FLAG"] = query_yes_no(userlog.info("Configure Salt?"))
    read_dict["SALT_MINION_FLAG"] = query_yes_no(userlog.info("Salt Minion?"))
    read_dict["SALT_MASTER_FLAG"] = query_yes_no(userlog.warn("Salt Master?"), default="no")
    read_dict["SALT_MASTER_IP"] = str(read_ip(custom_message=" for Salt Master"))

    salt_packages = []

    if read_dict["SALT_MASTER_FLAG"]:
        salt_packages.append({
            "name": "salt-master",
            "state": "latest"
        })

    if read_dict["SALT_MINION_FLAG"]:
        salt_packages.append({
            "name": "salt-minion",
            "state": "latest"
        })

    read_dict["salt_packages"] = salt_packages
    return read_dict


def read_ssh_keys(def_vars):
    read_dict = dict()

    if not def_vars:
        def_vars = dict()

    # Validate Key Path
    if "exec_user_keys" in def_vars:
        exec_user_keys = [key for key in def_vars["exec_user_keys"] if Path(os.path.expanduser(key["file"])).is_file()
                          and query_yes_no(userlog.warn("Keep this Key Option? ---> {0}").format(key))]

    else:
        exec_user_keys = []

    print(userlog.info("Current Public Keys that will be installed for Ansible runner:\n"
          + json.dumps(exec_user_keys, indent=4))+"\n")

    print(userlog.warn("Reading Additional Keys. Enter \"empty\" string to stop."))

    while True:
        key = read_pub_key(key="exec user")

        if not key:
            break

        if query_yes_no(userlog.warn("=== Present? ===")):
            state = "present"
        else:
            state = "absent"

        exec_user_keys.append({"file": key, "state": state})

    # Keys for Root
    root_keys = []
    if query_yes_no(userlog.warn("Will you execute as ROOT?")):
        print(userlog.error("Beware! The keys you have specified for the exec user will be installed to Root")+"\n")

    elif query_yes_no(userlog.error("Install a key to ROOT?")):

        if "root_keys" in def_vars:
            root_keys = [key for key in def_vars["root_keys"] if Path(os.path.expanduser(key)).is_file()
                         and query_yes_no(userlog.warn("Keep this Key? ---> {0}").format(key))]

        print(userlog.info("Current Public Keys that will be installed for ROOT:\n"
                           + json.dumps(root_keys, indent=4)))

        print(userlog.warn("\nReading Additional Keys. Enter \"empty\" string to stop."))

        while True:
            key = read_pub_key(key="root user")

            if not key:
                break

            if query_yes_no(userlog.warn("=== Present? ===")):
                state = "present"
            else:
                state = "absent"

            root_keys.append({"file": key, "state": state})

    else:
        pass

    custom_user_keys = []
    if "custom_user_keys" in def_vars:
        custom_user_keys = [key for key in def_vars["custom_user_keys"] if Path(os.path.expanduser(key)).is_file()
                            and query_yes_no(userlog.warn("Keep this Key? ---> {0}").format(key))]

    # TODO this part need a bit of refinement
    print(userlog.info("Current Public Keys that will be installed for the user:\n"
                       + json.dumps(custom_user_keys, indent=4)))

    while not key:
        key = read_pub_key(key="Custom user")

        if not key:
            break

        if query_yes_no(userlog.warn("=== Present? ===")):
            state = "present"
        else:
            state = "absent"

        custom_user_keys.append({"file": key, "state": state})

    read_dict["exec_user_keys"] = exec_user_keys
    read_dict["root_keys"] = root_keys
    read_dict["custom_user_keys"] = custom_user_keys

    return read_dict


def read_sshd_configuration(def_vars):
    read_dict = dict()
    if "privileged_host" in def_vars:
        # VALIDATE Already Present vars
        priv_args = [elem for elem in def_vars["privileged_host"]
                     if HostExemption.validate(raise_f=False, **elem)
                     and query_yes_no(json.dumps(elem, indent=4)+"\nKeep this?")]

        print(userlog.info("\nAll Privileged Hosts:\n"+json.dumps(priv_args, indent=4)))

        if query_yes_no(userlog.warn("Do you want to insert more?")):
            print(userlog.info("\nPlease enter an IP. Or enter empty string to stop\n"))
            for elem in HostExemption.read_priviliged_hosts(priv_len=len(priv_args)+1):
                priv_args.append(elem)

            print("\nAll Hosts:\n" + json.dumps(priv_args, indent=4))

    else:
        priv_args = []
        print(userlog.warn("\nNo privileged host. Please enter IPs. Or enter empty string to stop\n"))
        for elem in HostExemption.read_priviliged_hosts():
            priv_args.append(elem)

    read_dict["privileged_host"] = priv_args

    return read_dict


def select_roles():
    try:
        with open(ROLES, 'r') as f:
            roles = dict(json.load(f))
        print(userlog.info("\nAvailable Roles are:\n"+json.dumps(roles, indent=4)))

        chosen_roles = []

        while roles:
            for role_id in sorted(roles.keys()):
                print('{0} -> {1}'.format(role_id, roles[role_id]))

            choice = input("\nPlease select one from the choices above using the number.\nEmpty to stop.\n")

            if not choice:
                if chosen_roles:
                    break
            elif choice not in roles:
                print(userlog.error("\nInvalid Choice\n"))
                continue
            else:
                chosen_roles.append(roles[choice])
                roles.pop(choice)

        print(userlog.info(json.dumps(chosen_roles, indent=4)))

        return chosen_roles
    except IOError:
        print(userlog.error("No Roles specified. Exiting"))
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
            print('{0}\t->\t{1}'.format(i, playbook))
            i += 1

        choice = input("\nPlease Select one choice as listed above.\n")
        try:
            if choice and int(choice) in range(0, len(playbooks)):
                break
            else:
                print("\nInvalid Choice\n")
        except ValueError:
            print("\nInvalid Choice\n")

    chosen_playbook = playbooks[int(choice)]
    print("Chose playbook is: \"{0}\"".format(chosen_playbook))

    return chosen_playbook


def generate_temporary_playbook(roles=None, become=True, gather_facts=False, reboot=False):
    JINJA_FILE = 'administration/temporary.yml.j2'
    jinja_args = {
        "become": query_yes_no(userlog.warn("Become?")),
        "gather_facts": query_yes_no(userlog.warn("Gather Facts?"), default="no"),
        "reboot": query_yes_no(userlog.error("Reboot after the execution?"), default="no")
    }
    if not roles:
        roles = select_roles()

    env = Environment(loader=FileSystemLoader(os.path.dirname(os.path.realpath(__file__))))
    env.trim_blocks = True
    env.lstrip_blocks = True
    temporary_playbook = env.get_template(JINJA_FILE).render(roles=roles,
                                                             become=jinja_args["become"],
                                                             gather_facts=jinja_args["gather_facts"],
                                                             reboot=jinja_args["reboot"])

    with open('administration/temporary.yml', 'w') as f:
        f.write(temporary_playbook)


def read_role_vars(role=None):
    # TODO read defaults/main.yml

    # update the role_vars dict with CUSTOM_ROLE_VARS
    try:
        with open(CUSTOM_ROLE_VARS + "/{0}/my_vars.yml".format(role)) as f:
            role_vars = yaml.load(f)
        if role_vars:
            print("Custom Role VARS from file: " + CUSTOM_ROLE_VARS + "/{0}/my_vars.yml\n".format(role)
                  + json.dumps(role_vars, indent=4) + "\n\n")
    except IOError:
        print(userlog.error("File: " + CUSTOM_ROLE_VARS + "/{0}/my_vars.yml not found.".format(role)))
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
    print(userlog.warn("Printing to File: " + CUSTOM_ROLE_VARS + "/{0}/my_vars.yml\n".format(role)
          + json.dumps(role_vars, indent=4) + "\n\n"))

    return role_vars


def main(playbook=None, temp_playbook=False):
    roles = None
    # Case 1 -> Playbooks available
    if playbook or query_yes_no(userlog.warn("Select a playbook?")):
        if not playbook:
            playbook = select_playbook()
        try:
            with open(PLAYBOOK_PATH + "/{0}.yml".format(playbook)) as f:
                role_yaml = yaml.load(f)
                roles = role_yaml[1]["roles"]
        except IOError:
            print(userlog.error("Problem extracting roles from playbook"))
            playbook = None

    if not roles and not temp_playbook and not query_yes_no("Select Roles?"):
        print(userlog.error("No valid Options. Exiting"))
        return 0
    elif not roles:
        generate_temporary_playbook(roles=roles, become=True, gather_facts=False, reboot=True)
    else:
        pass

    print(userlog.info(json.dumps(roles, indent=4)))

    vm_vars = {}
    for role in roles:
        vm_vars.update(read_role_vars(role=role))

    print(userlog.info("\nContents of {0} are:\n".format(POPULATED_VARS_OUTPUT) + json.dumps(vm_vars, indent=4)))

    with open(POPULATED_VARS_OUTPUT, 'w') as f:
        json.dump(vm_vars, f, indent=4)
    return 0

if __name__ == '__main__':
    if len(sys.argv) != 2:
        main()
    else:
        main(playbook=sys.argv[1])
