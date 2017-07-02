#!/bin/bash

# python new_vm_var_populate.py

# INPUT Playbook to run

# INPUT enter username

# INPUT sudo (-K)?

# INPUT password (-k)?

# INPUT JSON FILE

# INPUT target host

echo "ansible-playbook $1 -i '$2', -kK -u $3 -e @$4"

# TODO Possibly Pythonize it ?

ansible-playbook $1 -i '$2', -kK -u $3 -e @$4
