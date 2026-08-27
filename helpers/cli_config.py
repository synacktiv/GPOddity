import configparser
import uuid
import typer
from dataclasses import dataclass
from typing import Optional, List
from helpers.utils import logger
from ldap3 import Connection

@dataclass
class Config:
    gpo_guid: str
    gpo_dn: str
    current_gpo_version: int
    updated_gpo_version: int
    domain: str
    dc_fqdn: str
    dc_ip: str
    domain_dn: str

    kerberos: bool
    username: Optional[str]
    password: Optional[str]
    nthash: Optional[str]
    ldaps: bool

    smb_mode: str
    smb_ip: str
    smb_share: str
    smb_machine: Optional[str]
    smb_nt: Optional[str]
    smb_aes: Optional[str]
    smb_iface: str

    modules: Optional[List[str]]
    command: Optional[str]
    command_type: str
    command_shell: str

    clean_folder: Optional[str]
    ldap_session: Optional[Connection]


def parse_config(config_path: str, clean: bool = False) -> Config:
    options = configparser.ConfigParser()
    options.read(config_path)

    ### Argument coherence check
    if not options.has_section("GENERAL"):
        logger.error("Missing GENERAL section in configuration")
        raise typer.Exit(1)

    gpo_guid = options.get("GENERAL", "gpo_guid", fallback=None)
    domain = options.get("GENERAL", "domain", fallback=None)
    dc_fqdn = options.get("GENERAL", "dc-fqdn", fallback=None)
    dc_ip = options.get("GENERAL", "dc-ip", fallback=dc_fqdn)

    for item_name, val in zip(["gpo_guid", "domain", "dc-fqdn"], [gpo_guid, domain, dc_fqdn]):
        if not val:
            logger.error(f"Missing '{item_name}' in GENERAL section")
            raise typer.Exit(1)

    domain_dn = ",".join([f"DC={part}" for part in domain.split(".")])
    gpo_dn = f'CN={{{gpo_guid}}},CN=Policies,CN=System,{domain_dn}'
    current_gpo_version = -1
    updated_gpo_version = -1

    kerberos = options.getboolean("GENERAL", "kerberos", fallback=False)
    username = options.get("GENERAL", "username", fallback=None)
    password = options.get("GENERAL", "password", fallback=None)
    nthash = options.get("GENERAL", "hash", fallback=None)
    ldaps = options.getboolean("GENERAL", "ldaps", fallback=False)
    
    if not kerberos:
        if not (username and (password or nthash)):
            logger.error("Either username and password, or username and hash must be provided in GENERAL section (unless kerberos is true)")
            raise typer.Exit(1)
        if password is None and nthash is not None:
            password = '0' * 32 + ':' + nthash
    
    if clean is True:
        return Config(
            gpo_guid=gpo_guid,
            gpo_dn=gpo_dn,
            current_gpo_version=current_gpo_version,
            updated_gpo_version=updated_gpo_version,
            domain=domain,
            dc_fqdn=dc_fqdn,
            dc_ip=dc_ip,
            domain_dn=domain_dn,
            kerberos=kerberos,
            username=username,
            password=password,
            nthash=nthash,
            ldaps=ldaps,
            smb_mode="",
            smb_ip="",
            smb_share="",
            smb_machine="",
            smb_nt="",
            smb_aes="",
            smb_iface="",
            modules=[],
            command="",
            command_type="",
            command_shell="",
            clean_folder=None,
            ldap_session=None,
        )

    if not options.has_section("SMB"):
        logger.error("Missing SMB section in configuration")
        raise typer.Exit(1)

    smb_mode = options.get("SMB", "smb-mode", fallback=None)
    smb_ip = options.get("SMB", "smb-ip", fallback=None)
    for item_name, val in zip(["smb-mode", "smb-ip"], [smb_mode, smb_ip]):
        if not val:
            logger.error(f"Missing '{item_name}' in SMB section")
            raise typer.Exit(1)

    smb_mode = smb_mode.lower()
    if smb_mode not in ["domain", "embedded"]:
        logger.error("Invalid 'smb-mode' in SMB section: must be either 'domain' or 'embedded'")
        raise typer.Exit(1)

    smb_share = options.get("SMB", "smb-share", fallback=None)
    smb_machine = options.get("SMB", "smb-machine", fallback=None)
    smb_nt = options.get("SMB", "smb-nt", fallback=None)
    smb_aes = options.get("SMB", "smb-aes", fallback=None)
    smb_iface = options.get("SMB", "smb-iface", fallback="eth0")

    if smb_mode == "domain":
        if not smb_ip or not smb_share:
            logger.error("If 'smb-mode' is 'domain', 'smb-ip' and 'smb-share' must be provided in SMB section")
            raise typer.Exit(1)
    else:
        if not smb_machine:
            logger.error("The machine account acting as the SMB server must be specified with 'smb-machine' in SMB section")
            raise typer.Exit(1)
        if not smb_nt and not smb_aes:
            logger.error("The password for the machine account acting as the SMB server must be specified with 'smb-nt' or 'smb-aes' in SMB section")
            raise typer.Exit(1)
        if not smb_share:
            smb_share = "GPOddity"

    if not options.has_section("COMMANDS"):
        logger.error("Missing COMMANDS section in configuration")
        raise typer.Exit(1)

    modules = options.get("COMMANDS", "modules", fallback=None)
    if modules:
        modules = modules.split(',')
    command = options.get("COMMANDS", "command", fallback=None)
    command_type = options.get("COMMANDS", "command-type", fallback="computer").lower()
    if command_type not in ["computer", "user"]:
        logger.error("Invalid 'command-type' in COMMANDS section: must be either 'computer' or 'user'")
        raise typer.Exit(1)

    command_shell = options.get("COMMANDS", "command-shell", fallback="cmd").lower()
    if command_shell not in ["cmd", "powershell"]:
        logger.error("Invalid 'command-shell' in COMMANDS section: must be either 'cmd' or 'powershell'")
        raise typer.Exit(1)

    if modules and command:
        logger.error("COMMANDS section: 'modules' cannot be specified together with 'command'")
        raise typer.Exit(1)
    if not modules and not command:
        logger.error("COMMANDS section: must specify either 'modules' or 'command'")
        raise typer.Exit(1)

    return Config(
        gpo_guid=gpo_guid,
        gpo_dn=gpo_dn,
        current_gpo_version=current_gpo_version,
        updated_gpo_version=updated_gpo_version,
        domain=domain,
        dc_fqdn=dc_fqdn,
        dc_ip=dc_ip,
        domain_dn=domain_dn,
        kerberos=kerberos,
        username=username,
        password=password,
        nthash=nthash,
        ldaps=ldaps,
        smb_mode=smb_mode,
        smb_ip=smb_ip,
        smb_share=smb_share,
        smb_machine=smb_machine,
        smb_nt=smb_nt,
        smb_aes=smb_aes,
        smb_iface=smb_iface,
        modules=modules,
        command=command,
        command_type=command_type,
        command_shell=command_shell,
        clean_folder=None,
        ldap_session=None,
    )
