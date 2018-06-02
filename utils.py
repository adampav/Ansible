import ipaddress
import json
import os
import sys
from pathlib import Path


# Colors and Userlog is Based on Linos Giannopoulos Code, https://github.com/linosgian/ #
class Colors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class UserLog:
    @staticmethod
    def info(format_string):
        return "{0}[*] {1}{2}".format(Colors.GREEN, format_string, Colors.END)

    @staticmethod
    def warn(format_string, bold=True):
        if bold:
            return "{0}{1}[*] {2}{3}".format(Colors.YELLOW, Colors.BOLD, format_string, Colors.END)
        else:
            return "{0}[*] {1}{2}".format(Colors.YELLOW, format_string, Colors.END)

    @staticmethod
    def error(format_string):
        return "{0}[*] {1}{2}".format(Colors.RED, format_string, Colors.END)

    def infopr(self, format_string):
        print(self.info(format_string))

    def warnpr(self, format_string, bold=True):
        print(self.warn(format_string, bold=bold))

    def errorpr(self, format_string):
        print(self.error(format_string))


userlog = UserLog()


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


def read_ip(custom_message="", accept_none=False, maskless=True):
    ip_addr = None
    ip_input = None
    while not ip_addr:
        try:
            ip_input = input(userlog.info("Please enter an IP address{0}: >> ").format(custom_message))
            ip_addr = ipaddress.ip_interface(u'{0}'.format(ip_input))
        except ValueError:
            if accept_none and not ip_input:
                return None
            else:
                print(userlog.error("Bad IP Format. Try again!\n\n"))

    if maskless:
        return ip_addr.ip
    else:
        return ip_addr


def read_hostname(custom_message="", accept_none=False):
    hostname = None
    while not hostname:
        hostname = input(userlog.info("Please enter a hostname {0}: >> ").format(custom_message))
        if accept_none:
            break

    return hostname
