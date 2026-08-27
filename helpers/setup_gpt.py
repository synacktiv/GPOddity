import os
import typer
import base64
from helpers.utils import bcolors, logger
from gpblib.parsing.validate import validate_modules
from gpblib.modules_configs import MODULES_CONFIG

def dispatch(modules, state_folder):
    output = {
        "computer": {},
        "user": {}
    }

    for module in modules:
        output[module.MODULECONFIG.type].setdefault(module.MODULECONFIG.name, b"")
    for module in modules:
        logger.info(f"[INFO] Generating XML for module '{module.MODULECONFIG.name}' ({module.MODULECONFIG.type})")
        module_instance = MODULES_CONFIG[module.MODULECONFIG.name]["class"](module.MODULECONFIG, module.MODULEOPTIONS, module.MODULEFILTERS, output[module.MODULECONFIG.type][module.MODULECONFIG.name], state_folder)
        module_xml = module_instance.get_xml()
        output[module.MODULECONFIG.type][module.MODULECONFIG.name] = module_xml
    return output


def create_gpt(cfg) -> dict:
    modules = cfg.modules
    
    if cfg.command:
        shell = "cmd.exe" if cfg.command_shell == "cmd" else "powershell.exe"
        arguments = f"/c {cfg.command}" if cfg.command_shell == "cmd" else f"-windowstyle hidden -nop -enc {base64.b64encode(cfg.command.encode('UTF-16LE')).decode('utf-8')}"

        with open(f"{cfg.clean_folder}/command_generated_module.ini", "w") as f:
            f.write(f"[MODULECONFIG]\nname = Scheduled Tasks\ntype = {cfg.command_type}\n\n")
            f.write(f"[MODULEOPTIONS]\ntask_type = immediate\nprogram = {shell}\narguments = {arguments}\n\n")
            f.write(f"[MODULEFILTERS]\n")
        modules = [f"{cfg.clean_folder}/command_generated_module.ini"]

    modules = validate_modules(modules)
    logger.warning(f"{bcolors.OKGREEN}[+] All modules validated{bcolors.ENDC}")
    modules = dispatch(modules, cfg.clean_folder)

    version_increase = 0
    if len(modules["computer"].keys()) > 0:
        logger.info("[INFO] Computer GPO version should be increased")
        version_increase += 1
    if len(modules["user"].keys()) > 0:
        logger.info("[INFO] User GPO version should be increased")
        version_increase += 65536
    cfg.updated_gpo_version = cfg.current_gpo_version + version_increase
    logger.info(f"[INFO] Updated GPO version number: {cfg.updated_gpo_version}")

    gpt_dir = f"{cfg.clean_folder}/GPT"

    os.makedirs(gpt_dir, exist_ok=True)
    os.makedirs(f"{gpt_dir}/Machine", exist_ok=True)
    os.makedirs(f"{gpt_dir}/User", exist_ok=True)

    with open(f"{gpt_dir}/gpt.ini", "w") as f:
        f.write(f"[General]\nVersion={cfg.updated_gpo_version}\ndisplayName=New Group Policy Object\n")

    for module_type, module_list in modules.items():
        base_path = fr"{gpt_dir}/User" if module_type == "user" else fr"{gpt_dir}/Machine"
        for module_name, module_xml in module_list.items():
            logger.info(f"[INFO] Writing module {module_name} ({module_type})")
            target_path = base_path
            for directory in MODULES_CONFIG[module_name]["gpt_path"].split("\\")[:-1]:
                to_create = f"{target_path}/{directory}"
                os.makedirs(to_create, exist_ok=True)
                logger.info(f"[INFO] Created directory {to_create}")
                target_path = to_create
            file_path = MODULES_CONFIG[module_name]['gpt_path'].replace('\\', '/')
            target_file = f"{base_path}/{file_path}"
            with open(target_file, "wb") as f:
                f.write(module_xml)
            logger.info(f"[INFO] Wrote XML to file {target_file}")
    
    return modules
