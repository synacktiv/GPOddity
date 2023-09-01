import logging

from ldap3 import SUBTREE, MODIFY_REPLACE, MODIFY_DELETE

def get_attribute(ldap_session, dn, attribute):
    try:
        ldap_session.search(
        search_base=dn,
        search_filter='(objectClass=*)',
        search_scope=SUBTREE,
        attributes=[attribute,],
        )

        searchResult = ldap_session.response[0]
        value = searchResult['attributes'][attribute]
        return value
    except:
        logging.error(f"‼️  Error: couldn't find attribute {attribute} for dn {dn}. Things will probably break.")
        return None
    

def modify_attribute(ldap_session, dn, attribute, new_value):
    result = ldap_session.modify(dn, {attribute: [(MODIFY_REPLACE, [new_value])]})
    return result

def unset_attribute(ldap_session, dn, attribute):
    result = ldap_session.modify(dn, {attribute: [(MODIFY_DELETE, [])]})
    return result

def update_extensionNames(extensionName):
    val1 = "00000000-0000-0000-0000-000000000000"
    val2 = "CAB54552-DEEA-4691-817E-ED4A4D1AFC72"
    val3 = "AADCED64-746C-4633-A97C-D61349046527"

    if extensionName is None:
        extensionName = ""

    try:
        if not val2 in extensionName:
            new_values = []
            toUpdate = ''.join(extensionName)
            test = toUpdate.split("[")
            for i in test:
                new_values.append(i.replace("{", "").replace("}", " ").replace("]", ""))

            if val1 not in toUpdate:
                new_values.append(val1 + " " + val2)

            elif val1 in toUpdate:
                for k, v in enumerate(new_values):
                    if val1 in new_values[k]:
                        toSort = []
                        test2 = new_values[k].split()
                        for f in range(1, len(test2)):
                            toSort.append(test2[f])
                        toSort.append(val2)
                        toSort.sort()
                        new_values[k] = test2[0]
                        for val in toSort:
                            new_values[k] += " " + val

            if val3 not in toUpdate:
                new_values.append(val3 + " " + val2)

            elif val3 in toUpdate:
                for k, v in enumerate(new_values):
                    if val3 in new_values[k]:
                        toSort = []
                        test2 = new_values[k].split()
                        for f in range(1, len(test2)):
                            toSort.append(test2[f])
                        toSort.append(val2)
                        toSort.sort()
                        new_values[k] = test2[0]
                        for val in toSort:
                            new_values[k] += " " + val

            new_values.sort()

            new_values2 = []
            for i in range(len(new_values)):
                if new_values[i] is None or new_values[i] == "":
                    continue
                value1 = new_values[i].split()
                new_val = ""
                for q in range(len(value1)):
                    if value1[q] is None or value1[q] == "":
                        continue
                    new_val += "{" + value1[q] + "}"
                new_val = "[" + new_val + "]"
                new_values2.append(new_val)

            return "".join(new_values2)
        else:
            return extensionName
    except:
        return "[{" + val1 + "}{" + val2 + "}]" + "[{" + val3 + "}{" + val2 + "}]"