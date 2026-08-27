import os
import json
from datetime import datetime
from ldap3 import MODIFY_DELETE
from helpers.utils import logger, bcolors
from helpers.ldap import unset_attribute, modify_attribute


def clean_create_folder():
    clean_folder = datetime.now().strftime("%Y_%m_%d_%H%M%S_%f")
    os.makedirs("cleaning", exist_ok=True)
    os.makedirs(os.path.join("cleaning", clean_folder))
    os.makedirs(os.path.join("cleaning", clean_folder, "revert"))

    with open(os.path.join("cleaning", clean_folder, "actions.json"), "w") as f:
        json.dump({"actions": []}, f)
    return os.path.join("cleaning", clean_folder)

def clean_save_action(clean_folder, action, item, attribute=None, old_value=None, new_value=None, added=None):
    with open(os.path.join(clean_folder, "actions.json"), 'r+') as f:
        data = json.load(f)
        data["actions"].append({
            "action": action,
            "item": item,
            "attribute": attribute,
            "old_value": old_value,
            "new_value": new_value,
            "added": added
        })
        f.seek(0)
        json.dump(data, f, indent=2, default=str)


def revert_gpoddity_actions(cfg):
    # Read actions.json and revert performed actions
    actions_file = os.path.join(cfg.clean_folder, "actions.json")
    try:
        with open(actions_file, "r") as f:
            data = json.load(f)
        
        for action in data.get("actions", []):
            if action.get("action") == "ldap_modify_attribute":
                try:
                    logger.warning(f"[*] Reverting {action.get('attribute')} for {action.get('item')}")
                    modify_attribute(cfg.ldap_session, action.get("item"), action.get("attribute"), action.get("old_value"))
                    logger.warning(f"{bcolors.OKGREEN}[+] Reverted {action.get('attribute')} for {action.get('item')} to {action.get('old_value')}{bcolors.ENDC}")
                except Exception as e:
                    logger.error(f"{bcolors.FAIL}[-] Failed to revert {action.get('attribute')} for {action.get('item')} to {action.get('old_value')}{bcolors.ENDC}")
                    logger.error(e)
            if action.get("action") == "ldap_set_attribute":
                try:
                    logger.warning(f"[*] Unsetting {action.get('attribute')} for {action.get('item')}")
                    unset_attribute(cfg.ldap_session, action.get("item"), action.get("attribute"))
                    logger.warning(f"{bcolors.OKGREEN}[+] Reverted {action.get('attribute')} for {action.get('item')}{bcolors.ENDC}")
                except Exception as e:
                    logger.error(f"{bcolors.FAIL}[-] Failed to revert {action.get('attribute')} for {action.get('item')}{bcolors.ENDC}")
                    logger.error(e)
    except Exception as e:
        import traceback
        traceback.print_exc()
        logger.error(f"{bcolors.FAIL}[-] Failed to read {actions_file}{bcolors.ENDC}")