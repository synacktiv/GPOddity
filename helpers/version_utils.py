import os
import re

from helpers.ldap_utils                     import get_attribute
from conf                                   import OUTPUT_DIR

def update_GPT_version_number(ldap_session, gpo_dn, gpo_type):
    versionNumber = int(get_attribute(ldap_session, gpo_dn, "versionNumber"))
    if gpo_type == "computer":
        updated_version = versionNumber + 1
    else:
        updated_version = versionNumber + 65536
    with open(os.path.join(OUTPUT_DIR, "gpt.ini"), 'r') as f:
        content = f.read()
    new_content = re.sub('=[0-9]+', '={}'.format(updated_version), content)
    with open(os.path.join(OUTPUT_DIR, "gpt.ini"), 'w') as f:    
        f.write(new_content)