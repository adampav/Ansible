#!/usr/bin/env python

import json


def main():
    # Variables for Packages (base_packages, extra_packages, UPGRADE_DIST_FLAG)

    # json.loads default values
    defaults = dict()
    defaults['main_key_path'] = '~/.ssh/id_rsa.pub'
    defaults['exempt_addresses'] = list()

    # main_key_path,
    # exempt addresses

    # network stuff
    defaults['netmask'] = '255.255.255.0'

    vars = {
        "extra_packages": "",
        "UPGRADE_DIST_FLAG": True,
        "main_key_path": "~/.ssh/id_rsa.pub",
        "primary_ip": "",
        "primary_netmask": "",
        "primary_network": "",
        "primary_broadcast": "",
        "primary_dns1": "",
        "primary_dns2": "",
        "gateway": "",
        "privileged_host": [{"addr": "", "id": 1, "state": "present"},
                            {"addr": "", "id": 2, "state": "present"}]
    }

    with open('/tmp/vars.json', 'w') as f:
        json.dump(vars, f)
    # FIND FREE IP
    return 0

if __name__ == '__main__':
    main()
