#!/usr/bin/env python3
"""
LDAP Account Investigator (Enhanced Version)
"""

import argparse
import os
from datetime import datetime, timedelta
from ldap3 import Server, Connection, NTLM, SYNC
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError
import logging

# Configure logging
logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)

# UserAccountControl flag for disabled accounts
ACCOUNT_DISABLED_FLAG = 0x0002

# Display label mapping
ATTRIBUTE_LABELS = {
    'sAMAccountName': 'Login Name',
    'userPrincipalName': 'UPN',
    'distinguishedName': 'DN',
    'cn': 'Common Name',
    'employeeID': 'Employee ID',
    'mail': 'Email',
    'memberOf': 'Group Memberships',
    'whenCreated': 'Created On',
    'whenChanged': 'Last Modified',
    'lastLogonTimestamp': 'Last Logon',
    'accountExpires': 'Account Expires',
    'pwdLastSet': 'Password Last Set',
    'badPwdCount': 'Bad Password Count',
    'logonCount': 'Logon Count',
    'userAccountControl': 'User Flags',
    'description': 'Description',
    'telephoneNumber': 'Phone',
    'title': 'Title',
    'department': 'Department',
    'manager': 'Manager',
    'lockoutTime': 'Lockout Time',
    'lastLogon': 'Last Logon (Non-Replicated)',
    'lastLogoff': 'Last Logoff',
    'logonHours': 'Logon Hours',
    'userWorkstations': 'Allowed Workstations',
    'adminCount': 'Admin Count',
    'primaryGroupID': 'Primary Group ID',
    'msDS-AllowedToDelegateTo': 'Allowed to Delegate To',
    'servicePrincipalName': 'Service Principal Names',
    'msDS-User-Account-Control-Computed': 'Computed User Flags'
}

# Time formatters
def filetime_to_datetime(filetime):
    try:
        filetime = int(filetime)
        if filetime in (0, 9223372036854775807):
            return "Never"
        dt = datetime(1601, 1, 1) + timedelta(microseconds=filetime // 10)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(filetime)

def generalized_time_to_datetime(timestr):
    try:
        return datetime.strptime(timestr.split('.')[0], "%Y%m%d%H%M%S").strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return timestr

def format_ldap_value(attr, value):
    if attr in ['whenCreated', 'whenChanged']:
        return generalized_time_to_datetime(value)
    if attr in ['lastLogonTimestamp', 'accountExpires', 'pwdLastSet', 'lastLogon', 'lastLogoff', 'lockoutTime']:
        return filetime_to_datetime(value)
    return value

def is_account_disabled(uac):
    try:
        return bool(int(uac) & ACCOUNT_DISABLED_FLAG)
    except (ValueError, TypeError):
        return False

def print_account_info(attrs):
    for attr_name, label in ATTRIBUTE_LABELS.items():
        val = attrs.get(attr_name)
        if not val:
            continue
        if attr_name == 'memberOf' and isinstance(val, list):
            print(f"{label}:")
            for group in val:
                print(f"  - {group}")
        else:
            val = val[0] if isinstance(val, list) else val
            print(f"{label}: {format_ldap_value(attr_name, val)}")
    
    uac = attrs.get('userAccountControl', [None])[0]
    print(f"Account Disabled: {is_account_disabled(uac)}")

def bind_ldap(domain, username, password):
    fq_user = f"{domain}\\{username}"
    server = Server(domain, get_info=None)
    conn = Connection(server, user=fq_user, password=password, authentication=NTLM, client_strategy=SYNC)

    if not conn.bind():
        reason = conn.result['description']
        raise LDAPBindError(f"LDAP bind failed: {reason} for {fq_user}")
    return conn

def get_base_dn(conn):
    conn.search('', '(objectClass=*)', search_scope='BASE', attributes=['defaultNamingContext'])
    return str(conn.entries[0]['defaultNamingContext']) if conn.entries else None

def search_user(conn, base_dn, target, attributes):
    conn.search(base_dn, f'(sAMAccountName={target})', attributes=attributes)
    return conn.entries

def suggest_similar_users(conn, base_dn, target):
    conn.search(base_dn, f'(sAMAccountName={target}*)', attributes=['sAMAccountName', 'employeeID'])
    if conn.entries:
        print("Did you mean:")
        for entry in conn.entries:
            data = entry.entry_attributes_as_dict
            uname = data.get('sAMAccountName', [''])[0]
            eid = data.get('employeeID', [''])[0]
            print(f"  - {uname} (Employee ID: {eid})")
    else:
        print(f"No similar usernames found for '{target}'.")

def main():
    parser = argparse.ArgumentParser(description='LDAP Account Investigator')
    parser.add_argument('-u', '--username', required=True, help='LDAP bind username')
    parser.add_argument('-p', '--password', required=True, help='LDAP bind password')
    parser.add_argument('--domain', required=True, help='Domain for LDAP bind')
    parser.add_argument('--target', help='Target account to investigate (default is bind user)')
    args = parser.parse_args()

    target = args.target if args.target else args.username
    attributes = list(ATTRIBUTE_LABELS.keys())

    try:
        conn = bind_ldap(args.domain, args.username, args.password)
        logging.info(f"Connected to LDAP. Investigating: {target}\n")

        base_dn = get_base_dn(conn)
        if not base_dn:
            raise Exception("Could not determine defaultNamingContext from the LDAP server.")

        entries = search_user(conn, base_dn, target, attributes)
        if entries:
            print_account_info(entries[0].entry_attributes_as_dict)
        else:
            print(f"No exact match for '{target}'. Searching for similar usernames...\n")
            suggest_similar_users(conn, base_dn, target)

    except LDAPBindError as e:
        logging.error(e)
        print("Check credentials or account status.")
    except LDAPSocketOpenError as e:
        logging.error(f"Could not connect to LDAP server: {e}")
        print("Possible causes: incorrect server, firewall, network, or LDAP not running.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.unbind()

if __name__ == "__main__":
    main()
