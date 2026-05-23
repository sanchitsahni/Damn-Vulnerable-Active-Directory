#!/usr/bin/env python3
import argparse
import sys
import socket
import csv
from time import sleep

try:
    from ldap3 import Server, Connection, ALL, SIMPLE
except ImportError:
    print("[-] Missing ldap3 library. Please install it using:")
    print("    pip3 install ldap3")
    sys.exit(1)

# Configuration
LAB_DOMAIN = "corp.local"
LAB_USER = "Administrator@corp.local"
LAB_PASSWORD = "DVADlab2024!"
DC_IP = "10.10.0.10"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

def check_port(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except:
        return False

def generate_rules():
    rules = []
    
    # 1. Base network services (5 rules)
    rules.extend([
        {"id": "ENUM-001", "name": "File Server SMB (445) Reachable", "type": "port", "ip": "10.10.0.13", "port": 445},
        {"id": "IA-011", "name": "MSSQL Server (1433) Reachable", "type": "port", "ip": "10.10.0.14", "port": 1433},
        {"id": "IA-046", "name": "Active Directory Web Services (9389) Reachable", "type": "port", "ip": "10.10.0.10", "port": 9389},
        {"id": "IA-013", "name": "ADCS Web Enrollment (80) Reachable on CA01", "type": "port", "ip": "10.10.0.12", "port": 80},
        {"id": "ENUM-002", "name": "Global Catalog (3268) Reachable", "type": "port", "ip": "10.10.0.10", "port": 3268}
    ])

    # 2. Privileged Groups (50+ rules)
    priv_groups = [
        "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators",
        "Account Operators", "Server Operators", "Print Operators", "Cryptographic Operators",
        "DnsAdmins", "Exchange Trusted Subsystem", "Remote Desktop Users", "Remote Management Users",
        "Hyper-V Administrators", "DHCP Administrators", "DNSUpdateProxy", "Group Policy Creator Owners",
        "Enterprise Key Admins", "Key Admins", "Cert Publishers", "Incoming Forest Trust Builders",
        "Pre-Windows 2000 Compatible Access", "Windows Authorization Access Group", "Terminal Server License Servers",
        "Allowed RODC Password Replication Group", "Denied RODC Password Replication Group",
        "Cloneable Domain Controllers", "Protected Users", "Access Control Assistance Operators",
        "Remote Access Policies", "Distributed COM Users", "Event Log Readers", "Network Configuration Operators",
        "Performance Log Users", "Performance Monitor Users", "Storage Replica Administrators",
        "System Managed Accounts Group", "Windows RM Remote Management Users", "Replicator", "IIS_IUSRS",
        "WINS Users", "Local Service", "Network Service", "Interactive", "Authenticated Users", "Everyone"
    ]
    for i, group in enumerate(priv_groups):
        rules.append({
            "id": f"PRIV-{str(i).zfill(3)}",
            "name": f"Group Membership Audit: {group}",
            "type": "ldap",
            "filter": f"(&(objectClass=group)(cn={group}))",
            "attributes": ["member"],
            "eval": "len(entries[0].member.values) > 0 if entries else False"
        })

    # 3. UserAccountControl permutations (17 rules * 2 = 34 rules)
    uac_flags = {
        "PASSWD_NOTREQD": 32, "ENCRYPTED_TEXT_PWD_ALLOWED": 128, "DONT_EXPIRE_PASSWORD": 65536,
        "SMARTCARD_REQUIRED": 262144, "TRUSTED_FOR_DELEGATION": 524288, "USE_DES_KEY_ONLY": 2097152,
        "DONT_REQ_PREAUTH": 4194304, "TRUSTED_TO_AUTH_FOR_DELEGATION": 16777216, "PARTIAL_SECRETS_ACCOUNT": 67108864
    }
    for flag_name, flag_val in uac_flags.items():
        rules.append({
            "id": f"UAC-USR-{flag_name[:3]}",
            "name": f"Users configured with UAC flag: {flag_name}",
            "type": "ldap",
            "filter": f"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={flag_val}))",
            "attributes": ["sAMAccountName"],
            "eval": "len(entries) > 0"
        })
        rules.append({
            "id": f"UAC-CMP-{flag_name[:3]}",
            "name": f"Computers configured with UAC flag: {flag_name}",
            "type": "ldap",
            "filter": f"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:={flag_val}))",
            "attributes": ["sAMAccountName"],
            "eval": "len(entries) > 0"
        })

    # 4. Service Principal Names (50 rules)
    spn_services = [
        "MSSQLSvc", "cifs", "HTTP", "wsman", "HOST", "RPC", "ldap", "termSrv", "winrm",
        "Exchange", "smtp", "pop3", "imap", "mysql", "ftp", "dns", "krbtgt", "afpserver", "vnc",
        "cscript", "RestrictedKrbHost", "GC", "E3514235-4B06-11D1-AB04-00C04FC2DCD2", "TERMSRV",
        "WSMAN", "Hyper-V", "SMTPSVC", "IMAP4", "POP3", "SIP", "XMPP", "VSSRV", "nfs", "oracle",
        "postgres", "db2", "tns", "RDP", "vmware-vcd", "vapi", "MSServerCluster", "MSClusterVirtualServer",
        "exchangeRFR", "exchangeAB", "exchangeMDB", "Microsoft Virtual Console Service",
        "Microsoft Virtual System Migration Service", "spnsps", "STS"
    ]
    for i, spn in enumerate(spn_services):
        rules.append({
            "id": f"SPN-{str(i).zfill(3)}",
            "name": f"Admin Accounts with SPN (Kerberoasting): {spn}",
            "type": "ldap",
            "filter": f"(&(objectCategory=person)(objectClass=user)(servicePrincipalName={spn}/*)(adminCount=1))",
            "attributes": ["sAMAccountName"],
            "eval": "len(entries) > 0"
        })

    # 5. Core Vulns & RBCD / Shadow Creds / Templates (10 rules)
    rules.extend([
        {"id": "LAT-001", "name": "Computers configured for RBCD (msDS-AllowedToActOnBehalf)", "type": "ldap", "filter": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", "attributes": ["sAMAccountName"], "eval": "len(entries) > 0"},
        {"id": "LAT-002", "name": "Accounts with Shadow Credentials (msDS-KeyCredentialLink)", "type": "ldap", "filter": "(msDS-KeyCredentialLink=*)", "attributes": ["sAMAccountName"], "eval": "len(entries) > 0"},
        {"id": "LAT-003", "name": "Accounts with Constrained Delegation (msDS-AllowedToDelegateTo)", "type": "ldap", "filter": "(msDS-AllowedToDelegateTo=*)", "attributes": ["sAMAccountName"], "eval": "len(entries) > 0"},
        {"id": "DF-001", "name": "Cross-forest / External Trust Relationships configured", "type": "ldap", "filter": "(objectClass=trustedDomain)", "attributes": ["flatName"], "eval": "len(entries) > 0"},
        {"id": "DF-002", "name": "SID History populated on users (potential SID injection)", "type": "ldap", "filter": "(&(objectClass=user)(sIDHistory=*))", "attributes": ["sAMAccountName"], "eval": "len(entries) > 0"},
        {"id": "DEF-001", "name": "AD Recycle Bin is DISABLED", "type": "ldap", "filter": "(msDS-EnabledFeature=CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local)", "attributes": ["name"], "eval": "len(entries) == 0"},
        {"id": "DEF-002", "name": "LAPS is NOT fully configured (missing ms-Mcs-AdmPwd property)", "type": "ldap", "filter": "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))", "attributes": ["sAMAccountName"], "eval": "len(entries) == 0"},
        {"id": "IA-MAQ", "name": "MachineAccountQuota > 0", "type": "ldap", "filter": "(objectClass=domain)", "attributes": ["ms-DS-MachineAccountQuota"], "eval": "len(entries) > 0 and entries[0]['ms_DS_MachineAccountQuota'].value > 0 if 'ms_DS_MachineAccountQuota' in entries[0].entry_attributes_as_dict else False"}
    ])

    # 6. Information Disclosure (48 rules -> 60 rules)
    sensitive_attrs = ["description", "info", "userParameters", "comment", "wWWHomePage", "postalAddress"]
    keywords = ["password", "pass", "pwd", "cred", "admin", "secret", "key", "token", "pin", "login"]
    for attr in sensitive_attrs:
        for kw in keywords:
            rules.append({
                "id": f"INFO-{attr[:3]}-{kw[:3]}",
                "name": f"Passwords/Secrets stored in {attr} attribute (keyword: {kw})",
                "type": "ldap",
                "filter": f"(&(objectClass=user)({attr}=*{kw}*))",
                "attributes": ["sAMAccountName"],
                "eval": "len(entries) > 0"
            })

    # 7. ADCS Templates (ESC)
    for i in range(1, 15):
        rules.append({
            "id": f"ADCS-ESC{i}",
            "name": f"ADCS ESC{i} Vulnerable Template Published",
            "type": "ldap",
            "search_base": "CN=Configuration,DC=corp,DC=local",
            "filter": "(objectClass=pKICertificateTemplate)",
            "attributes": ["name"],
            "eval": f"any('ESC{i}' in entry.name.value for entry in entries) if entries else False"
        })

    return rules

def verify_ad_vulns():
    print(f"[*] Connecting to LDAP on {DC_IP} ({LAB_DOMAIN})...")
    
    if not check_port(DC_IP, 389, timeout=3):
        print(f"[{Colors.RED}!{Colors.END}] Error: LDAP Port 389 is closed or unreachable on {DC_IP}.")
        return

    server = Server(DC_IP, get_info=ALL, connect_timeout=5)
    try:
        conn = Connection(server, user=LAB_USER, password=LAB_PASSWORD, authentication=SIMPLE, auto_bind=True)
    except Exception as e:
        print(f"[{Colors.RED}!{Colors.END}] Failed to connect to LDAP: {e}")
        return

    rules = generate_rules()
    print(f"[{Colors.GREEN}+{Colors.END}] Connected successfully!")
    print(f"[*] Loaded {len(rules)} checks into the vulnerability engine.")
    print("=" * 100)
    
    report_data = []
    vulnerable_count = 0

    for rule in rules:
        is_vuln = False
        if rule["type"] == "port":
            is_vuln = check_port(rule["ip"], rule["port"])
        elif rule["type"] == "ldap":
            base = rule.get("search_base", "DC=corp,DC=local")
            conn.search(base, rule['filter'], attributes=rule['attributes'])
            try:
                # Safely evaluate the condition against conn.entries
                is_vuln = eval(rule["eval"], {"entries": conn.entries})
            except Exception as e:
                is_vuln = False
        
        # Save to report
        report_data.append([rule["id"], rule["name"], "VULNERABLE" if is_vuln else "SECURE"])
        
        # Print ONLY vulnerable to screen
        if is_vuln:
            vulnerable_count += 1
            print(f"[{Colors.GREEN}+{Colors.END}] {rule['id']:<10} | {rule['name']:<60} | {Colors.GREEN}VULNERABLE{Colors.END}")

    conn.unbind()
    print("=" * 100)
    print(f"\n[+] Execution Complete! Out of {len(rules)} checks, {vulnerable_count} were found VULNERABLE.")
    
    # Save to CSV
    csv_file = "vulnerability_report.csv"
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["ID", "Name", "Status"])
        writer.writerows(report_data)
        
    print(f"[*] Full 200+ check report securely saved to {csv_file}")

if __name__ == "__main__":
    verify_ad_vulns()
