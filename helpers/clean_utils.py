import os
import time
import configparser

from helpers.ldap_utils import unset_attribute, modify_attribute
from conf import CLEAN_DIR, CLEAN_FILE, bcolors

def init_save_file(gpo_id):
    os.makedirs(os.path.join(CLEAN_DIR, gpo_id), exist_ok=True)

    timestr = time.strftime("%Y_%m_%d-%H_%M_%S")
    save_file_name = os.path.join(CLEAN_DIR, gpo_id, timestr + ".txt")

    open(save_file_name, "x")
    return save_file_name

def save_attribute_value(attribute_name, value, save_file):
    with open(save_file, 'a') as f:
        f.write(f"[{attribute_name}]\nold_value={value}\n\n")


def clean(ldap_session, gpo_dn, save_file):
    to_clean = configparser.ConfigParser()
    to_clean.read(save_file)

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