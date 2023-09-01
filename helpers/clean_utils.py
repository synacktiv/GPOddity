import os
import configparser

from helpers.ldap_utils import unset_attribute, modify_attribute
from conf import CLEAN_DIR, CLEAN_FILE, bcolors

def init_save_file():
    with open(os.path.join(CLEAN_DIR, CLEAN_FILE), "w") as f:
        f.truncate(0)

def save_attribute_value(attribute_name, value):
    with open(os.path.join(CLEAN_DIR, CLEAN_FILE), 'a') as f:
        f.write(f"[{attribute_name}]\nold_value={value}\n\n")

def clean(ldap_session, gpo_dn):
    to_clean = configparser.ConfigParser()
    to_clean.read(os.path.join(CLEAN_DIR, CLEAN_FILE))

    for key in to_clean:
        if 'old_value' not in to_clean[key]:
            continue
        print(f"[*] Restoring value of {key} - {to_clean[key]['old_value']}")
        if (key == "gPCMachineExtensionNames" or key == "gPCUserExtensionNames") \
            and (to_clean[key]['old_value'] == '[]' or to_clean[key]['old_value'] == ''):
            result = unset_attribute(ldap_session, gpo_dn, key)
        else:
            result = modify_attribute(ldap_session, gpo_dn, key, to_clean[key]['old_value'])
        
        if result is True:
            print(f"{bcolors.OKGREEN}[+] Successfully restored {key}{bcolors.ENDC}")
        else:
            print(f"{bcolors.FAIL}[-] Couldn't clean value for {key}. You can try to re-run gpoddity with the {bcolors.ENDC}{bcolors.BOLD}--just-clean{bcolors.ENDC} flag, or clean LDAP attributes manually{bcolors.ENDC}")