#!/usr/bin/env python3
"""
LDAP Account Investigator (Optimized Version)
"""

import argparse
import os
from datetime import datetime, timedelta
from ldap3 import Server, Connection, NTLM, SYNC, SASL, GSSAPI
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

# Credential loader
def get_credentials():
    home = os.path.expanduser("~")
    credentials = {}
    secrets_file_path = f"secrets"             # Needs 3 rows, domain=<REALM>, username=<USER>, password=<PASS>
    if not os.path.exists(secrets_file_path):
        raise FileNotFoundError(f"Credential file not found at: {secrets_file_path}")

    with open(secrets_file_path, "r") as file:
        for line in file:
            line = line.strip()
            if line and '=' in line:
                key, value = line.split('=', 1)
                credentials[key] = value
    required = {'domain', 'username', 'password'}
    if not required.issubset(credentials):
        missing = required - credentials.keys()
        raise ValueError(f"Missing keys in .secrets: {', '.join(missing)}. Ensure domain, username, and password are set.")
    return credentials

# Account disabled check
def is_account_disabled(uac):
    try:
        # User Account Control (UAC) flag 2 indicates ACCOUNT_DISABLED
        # See https://docs.microsoft.com/en-us/windows/win32/ad/user-account-control-flags
        return bool(int(uac) & 2)
    except (ValueError, TypeError):
        return False

# Format attribute values
def filetime_to_datetime(filetime):
    try:
        filetime = int(filetime)
        if filetime == 0 or filetime == 9223372036854775807:
            return "Never"
        return (datetime(1601, 1, 1) + timedelta(microseconds=filetime // 10)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(filetime)

def generalized_time_to_datetime(timestr):
    try:
        # Example: 20211010133610.0Z
        return datetime.strptime(timestr.split('.')[0], "%Y%m%d%H%M%S").strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return timestr

def format_ldap_value(attr, value):
    if attr in ['whenCreated', 'whenChanged']:
        return generalized_time_to_datetime(value)
    if attr in ['lastLogonTimestamp', 'accountExpires', 'pwdLastSet', 'lastLogon', 'lastLogoff', 'lockoutTime']:
        return filetime_to_datetime(value)
    return value

# Attribute labels for readability
attribute_labels = {
    'sAMAccountName'                    : 'Login Name',
    'userPrincipalName'                 : 'UPN',
    'distinguishedName'                 : 'DN',
    'cn'                                : 'Common Name',
    'employeeID'                        : 'Employee ID',
    'mail'                              : 'Email',
    'memberOf'                          : 'Group Memberships',
    'whenCreated'                       : 'Created On',
    'whenChanged'                       : 'Last Modified',
    'lastLogonTimestamp'                : 'Last Logon',
    'accountExpires'                    : 'Account Expires',
    'pwdLastSet'                        : 'Password Last Set',
    'badPwdCount'                       : 'Bad Password Count',
    'logonCount'                        : 'Logon Count',
    'userAccountControl'                : 'User Flags',
    'description'                       : 'Description',
    'telephoneNumber'                   : 'Phone',
    'title'                             : 'Title',
    'department'                        : 'Department',
    'manager'                           : 'Manager',
    'lockoutTime'                       : 'Lockout Time',
    'lastLogon'                         : 'Last Logon (Non-Replicated)', # Note: lastLogon is not replicated and varies per DC. lastLogonTimestamp is replicated.
    'lastLogoff'                        : 'Last Logoff',
    'logonHours'                        : 'Logon Hours',
    'userWorkstations'                  : 'Allowed Workstations',
    'adminCount'                        : 'Admin Count',
    'primaryGroupID'                    : 'Primary Group ID',
    'msDS-AllowedToDelegateTo'          : 'Allowed to Delegate To',
    'servicePrincipalName'              : 'Service Principal Names',
    'msDS-User-Account-Control-Computed': 'Computed User Flags',
    #'dSCorePropagationData'             : 'Replication Metadata'
}

# Argument parsing
parser = argparse.ArgumentParser(description='LDAP Account Investigator')
parser.add_argument('-u', '--username', required=True, help='Username to investigate')
parser.add_argument('--auth', choices=['NTLM', 'KERBEROS'], default='NTLM', help='Authentication method: NTLM or KERBEROS')
args = parser.parse_args()

creds = {}
conn = None # Initialize conn to None for finally block

try:
    creds = get_credentials()
    ad_user = f"{creds['domain']}\\{creds['username']}"
    server = Server(creds['domain'], get_info=None) # No need for server info on bind, speed up server object creation
    
    if args.auth == 'NTLM':
        conn = Connection(server, user=ad_user, password=creds['password'], authentication=NTLM, client_strategy=SYNC)
    else:
        # For Kerberos, user and password are not needed if you have a valid TGT in your Kerberos ticket cache
        conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI, client_strategy=SYNC)

    if not conn.bind():
        # More specific error if bind fails
        if conn.result['description'] == 'invalidCredentials':
            raise LDAPBindError(f"LDAP bind failed: Invalid credentials for {ad_user}")
        else:
            raise LDAPBindError(f"LDAP bind failed: {conn.result['description']}")

    print(f"\nInvestigating account: {args.username}\n")

    # Consider narrowing this base_dn if users are typically in a specific OU
    base_dn = ','.join([f'DC={x}' for x in creds['domain'].split('.')])
    search_filter = f'(sAMAccountName={args.username})'
    attributes = list(attribute_labels.keys()) # Get all desired attributes

    # Perform the primary search
    conn.search(base_dn, search_filter, attributes=attributes)

    if conn.entries:
        entry = conn.entries[0]
        attrs = entry.entry_attributes_as_dict

        # userAccountControl handling
        uac_value = attrs.get('userAccountControl')
        if isinstance(uac_value, list):
            uac_value = uac_value[0] if uac_value else None
        disabled = is_account_disabled(uac_value)

        # generic attribute loop
        for attr_name, label in attribute_labels.items():
            val = attrs.get(attr_name)

            # skip completely missing or empty attributes
            if not val:
                continue

            if isinstance(val, list) and attr_name != 'memberOf':
                formatted_value = format_ldap_value(attr_name, val[0])
                print(f"{label}: {formatted_value}")
            elif attr_name == 'memberOf':
                print(f"{label}:")
                for group in val:
                    print(f"  - {group}")
            else:
                formatted_value = format_ldap_value(attr_name, val)
                print(f"{label}: {formatted_value}")
        print(f"Account Disabled: {disabled}")
    else:
        # Suggest similar usernames (this part uses a wildcard, which is slower)
        # You might consider if this "did you mean" feature is worth the potential performance hit
        # for very large directories, or only enable it for interactive use.
        print(f"No exact match for '{args.username}'. Searching for similar usernames...")
        conn.search(base_dn, f'(sAMAccountName={args.username}*)', attributes=['sAMAccountName', 'employeeID'])
        if conn.entries:
            print("Did you mean:")
            for entry in conn.entries:
                attrs = entry.entry_attributes_as_dict
                uname = attrs.get('sAMAccountName', [''])[0]
                eid = attrs.get('employeeID', [''])[0]
                print(f"  - {uname} (Employee ID: {eid})")
        else:
            print(f"No entries or similar usernames found for '{args.username}'.")

except FileNotFoundError as e:
    print(f"Error: {e}")
    print("Please ensure your .secrets file exists in your home directory and has 'domain', 'username', and 'password' set.")
except ValueError as e:
    print(f"Error: {e}")
    print("Please check the format and content of your .secrets file.")
except LDAPBindError as e:
    print(f"Error: {e}")
    print("Possible causes:\n1. Incorrect username or password.\n2. User account locked out or disabled.")
except LDAPSocketOpenError as e:
    print(f"Error: Could not connect to LDAP server: {e}")
    print("Possible causes:\n1. Server address is incorrect.\n2. Server is unreachable (firewall, network issue).\n3. LDAP service is not running on the server.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

finally:
    if conn:
        try:
            conn.unbind()
            print("LDAP connection unbound.") # Uncomment for debugging
        except Exception as e:
            print(f"Error during LDAP unbind: {e}")
