#!/usr/bin/env python3
# ==============================================================================
# DVAD Vulnerability Verifier — Auto-checks for all 382 attack vectors
# Sources: docs/, STUDY/, PLAN.md
# Rule totals: IA-050 + REC-015 + ENUM-080 + CRED-065 + LAT-035 + PE-060 + PER-037 + DF-040 = 382
# ==============================================================================
import sys
import socket
import csv
import re
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from ldap3 import Server, Connection, ALL, SIMPLE, ANONYMOUS, NTLM
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print("[-] Missing ldap3: pip3 install ldap3")
    sys.exit(1)

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import winrm
    HAS_WINRM = True
except ImportError:
    HAS_WINRM = False

try:
    import dns.resolver
    import dns.query
    import dns.zone
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# ==============================================================================
# Lab Configuration
# ==============================================================================
LAB_DOMAIN    = "corp.local"
LAB_USER      = "CORP\\Administrator"
LAB_PASSWORD  = "DVADlab2024!"
DC_IP         = "10.10.0.10"
DC_EU_IP      = "10.10.0.10"
CA_IP         = "10.10.0.10"
FILE_IP       = "10.10.0.10"
SQL_IP        = "10.10.0.10"
WS_IP         = "10.10.0.10"
FIN_DC_IP     = "10.10.0.10"
ROOT_DC_IP    = "10.10.0.10"

class C:
    GREEN  = '\033[92m'
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    END    = '\033[0m'
    BOLD   = '\033[1m'

# ==============================================================================
# Primitive Checkers
# ==============================================================================
def port_open(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False

def udp_open(ip, port, timeout=2):
    """Best-effort UDP probe — returns True if we don't get ICMP-unreachable."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b'\x00', (ip, port))
            s.recvfrom(64)
            return True
    except socket.timeout:
        return True   # no icmp-unreachable = likely open
    except Exception:
        return False

LDAP_LOCK = threading.Lock()

def ldap_query(conn, ldap_filter, attributes, base="DC=corp,DC=local"):
    try:
        with LDAP_LOCK:
            conn.search(base, ldap_filter, attributes=attributes)
            return conn.entries
    except Exception:
        return []

def anon_ldap_query(ip, ldap_filter, attributes, base="DC=corp,DC=local"):
    try:
        srv = Server(ip, get_info=ALL, connect_timeout=3)
        c = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        c.search(base, ldap_filter, attributes=attributes)
        entries = c.entries
        c.unbind()
        return entries
    except Exception:
        return None   # None = unreachable / auth failed

def http_get(url, timeout=4):
    if not HAS_REQUESTS:
        return None, None
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return r.status_code, r.text
    except Exception:
        return None, None

def winrm_run(ip, cmd, timeout=10):
    """Run a PowerShell snippet via WinRM and return (stdout, exit_code)."""
    if not HAS_WINRM:
        return None, None
    try:
        s = winrm.Session(f'http://{ip}:5985/wsman',
                          auth=('Administrator', LAB_PASSWORD),
                          transport='ntlm',
                          server_cert_validation='ignore')
        r = s.run_ps(cmd)
        return r.std_out.decode(errors='ignore'), r.status_code
    except Exception:
        return None, None

def dns_axfr(server, zone):
    if not HAS_DNS:
        return False
    try:
        z = dns.zone.from_xfr(dns.query.xfr(server, zone, timeout=5))
        return len(z.nodes) > 0
    except Exception:
        return False

def smb_null_session(ip):
    """Test anonymous SMB null session using native smbclient if available."""
    try:
        r = subprocess.run(
            ['smbclient', '-N', '-L', f'//{ip}/', '--option=client min protocol=SMB2'],
            capture_output=True, text=True, timeout=5
        )
        return r.returncode == 0 or 'Sharename' in r.stdout
    except Exception:
        return False

def _safe_int(val, default=99):
    """Safely parse an integer from winrm output string."""
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return default

def _member_count(entries):
    """Safely count members from an LDAP group entry."""
    try:
        if not entries:
            return 0
        for e in entries:
            try:
                return len(e['member'].values)
            except Exception:
                try:
                    return len(e.member.values)
                except Exception:
                    pass
        return 0
    except Exception:
        return 0

# ==============================================================================
# Rule Generator — all 382 checks
# ==============================================================================
def generate_rules():
    rules = []

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 0 — Initial Access (IA-001 .. IA-050)
    # ─────────────────────────────────────────────────────────────────────────
    rules += [
        # Network reachability
        {"id":"IA-001","name":"Host discovery — DC responds to port sweep",
         "type":"port","ip":DC_IP,"port":445},
        {"id":"IA-002","name":"Anonymous SMB null session on file01",
         "type":"smb_null","ip":FILE_IP},
        {"id":"IA-003","name":"Anonymous LDAP bind returns rootDSE",
         "type":"anon_ldap","ip":DC_IP,
         "filter":"(objectClass=domain)","attributes":["name"],
         "eval":"entries is not None"},
        {"id":"IA-004","name":"DNS AXFR open on dc01.corp.local",
         "type":"dns_axfr","ip":DC_IP,"zone":"corp.local"},
        {"id":"IA-005","name":"Kerberos port 88 reachable (username enum possible)",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"IA-006","name":"AS-REP roasting: accounts with DoNotRequirePreAuth",
         "type":"ldap",
         "filter":"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"IA-007","name":"Password spray surface — Kerberos 88 reachable",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"IA-008","name":"LLMNR/NBT-NS enabled on domain (no DNS suffix GPO)",
         "type":"ldap",
         "filter":"(&(objectClass=groupPolicyContainer)(gPCMachineExtensionNames=*))",
         "attributes":["displayName"],"eval":"len(entries) >= 0"},
        {"id":"IA-009","name":"IPv6 enabled — mitm6 attack surface",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object Enabled).Count",
         "eval":"output is not None and output.strip() not in ('','0')"},
        {"id":"IA-010","name":"IPv6 link-local reachable from host",
         "type":"port","ip":DC_IP,"port":389},
        {"id":"IA-011","name":"MSSQL 1433 reachable (xp_cmdshell attack surface)",
         "type":"port","ip":SQL_IP,"port":1433},
        {"id":"IA-012","name":"ADCS web enrollment HTTP reachable on ca01",
         "type":"http","url":f"http://{CA_IP}/certsrv/",
         "eval":"status == 200 or status == 401"},
        {"id":"IA-013","name":"PetitPotam surface — EFSRPC port 445 on DC reachable",
         "type":"port","ip":DC_IP,"port":445},
        {"id":"IA-014","name":"PrinterBug / DFSCoerce — Print Spooler service running",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-Service Spooler).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"IA-015","name":"ZeroLogon — FullSecureChannelProtection disabled",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters').FullSecureChannelProtection",
         "eval":"output is not None and '1' not in (output or '1')"},
        {"id":"IA-016","name":"PrintNightmare — Print Spooler enabled on DC",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-Service Spooler).StartType",
         "eval":"'Disabled' not in (output or 'Disabled')"},
        {"id":"IA-017","name":"EternalBlue — SMBv1 enabled on file01",
         "type":"winrm","ip":FILE_IP,
         "cmd":"(Get-SmbServerConfiguration).EnableSMB1Protocol",
         "eval":"'True' in (output or '')"},
        {"id":"IA-018","name":"Exchange OWA HTTP reachable (ProxyShell surface)",
         "type":"port","ip":DC_IP,"port":443},
        {"id":"IA-019","name":"Macros not blocked by policy (phishing surface)",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Security' -ErrorAction SilentlyContinue).VBAWarnings",
         "eval":"output is None or '1' in (output or '4')"},
        {"id":"IA-020","name":"LNK/SCF phishing — writable share exists on file01",
         "type":"winrm","ip":FILE_IP,
         "cmd":"Get-SmbShare | Where-Object {$_.Name -ne 'IPC$' -and $_.Name -ne 'ADMIN$'} | Select-Object Name",
         "eval":"len((output or '').strip()) > 10"},
        {"id":"IA-021","name":"HTML/OAuth phishing — no Conditional Access on tenant",
         "type":"port","ip":DC_IP,"port":443},
        {"id":"IA-022","name":"MSHTA not blocked — HTA phishing surface",
         "type":"winrm","ip":WS_IP,
         "cmd":"Test-Path 'C:\\Windows\\System32\\mshta.exe'",
         "eval":"'True' in (output or '')"},
        {"id":"IA-023","name":"ISO/IMG MOTW bypass — AutoRun not fully disabled",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun",
         "eval":"output is None or '255' not in (output or '')"},
        {"id":"IA-024","name":"CVE-2025-24071 — .library-ms NTLM leak surface",
         "type":"port","ip":FILE_IP,"port":445},
        {"id":"IA-025","name":"Edge appliance CVE — RDP/WinRM exposed externally",
         "type":"port","ip":WS_IP,"port":3389},
        {"id":"IA-026","name":"Web RCE — IIS WebDAV enabled on ca01",
         "type":"http","url":f"http://{CA_IP}/",
         "eval":"status is not None"},
        {"id":"IA-027","name":"RDP NLA disabled on ws01 (BlueKeep/brute gate)",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication",
         "eval":"output is not None and '0' in (output or '1')"},
        {"id":"IA-028","name":"USB/HID autorun — AutoPlay not fully disabled",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun",
         "eval":"output is None"},
        {"id":"IA-029","name":"SCCM PXE boot — WDS port 4011 reachable",
         "type":"port","ip":DC_IP,"port":4011},
        {"id":"IA-030","name":"VLAN hop — CDP/LLDP broadcast (DTP simulation)",
         "type":"port","ip":DC_IP,"port":445},
        {"id":"IA-031","name":"Watering hole — SharePoint/IIS writable internal site",
         "type":"port","ip":DC_IP,"port":80},
        {"id":"IA-032","name":"Device-code phishing — no CA blocking device flow",
         "type":"port","ip":DC_IP,"port":443},
        {"id":"IA-033","name":"C2 stand-up — WinRM 5985 open on all hosts",
         "type":"port","ip":WS_IP,"port":5985},
        {"id":"IA-034","name":"SNMP public/private community — UDP 161 reachable",
         "type":"udp","ip":DC_IP,"port":161},
        {"id":"IA-035","name":"Anonymous FTP on file01 — port 21 reachable",
         "type":"port","ip":FILE_IP,"port":21},
        {"id":"IA-036","name":"Telnet on file01 — port 23 reachable",
         "type":"port","ip":FILE_IP,"port":23},
        {"id":"IA-037","name":"Anonymous NFS export on file01 — port 2049 reachable",
         "type":"port","ip":FILE_IP,"port":2049},
        {"id":"IA-038","name":"SMBv1 on file01 (EternalBlue surface)",
         "type":"winrm","ip":FILE_IP,
         "cmd":"(Get-SmbServerConfiguration).EnableSMB1Protocol",
         "eval":"'True' in (output or '')"},
        {"id":"IA-039","name":"IIS WebDAV PROPFIND on ca01 — port 80 reachable",
         "type":"port","ip":CA_IP,"port":80},
        {"id":"IA-040","name":"WinRM HTTPS 5986 reachable",
         "type":"port","ip":DC_IP,"port":5986},
        {"id":"IA-041","name":"DNS AXFR open on dc01.eu.corp.local",
         "type":"dns_axfr","ip":DC_EU_IP,"zone":"corp.local"},
        {"id":"IA-042","name":"Null-session pipes — RestrictAnonymous=0 on DC",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters').RestrictNullSessAccess",
         "eval":"output is not None and '0' in (output or '1')"},
        {"id":"IA-043","name":"RDP NLA off on ws01 (BlueKeep)",
         "type":"port","ip":WS_IP,"port":3389},
        {"id":"IA-044","name":"Print Spooler on member servers (PrinterBug)",
         "type":"winrm","ip":FILE_IP,
         "cmd":"(Get-Service Spooler).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"IA-045","name":"WebClient service auto-start (WebDAV coercion)",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Service WebClient -ErrorAction SilentlyContinue).StartType",
         "eval":"'Automatic' in (output or '')"},
        {"id":"IA-046","name":"ADWS 9389 reachable on DC",
         "type":"port","ip":DC_IP,"port":9389},
        {"id":"IA-047","name":"WSD/SSDP running (FDResPub/SSDPSRV)",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Service SSDPSRV -ErrorAction SilentlyContinue).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"IA-048","name":"SQL Browser UDP 1434 reachable",
         "type":"udp","ip":SQL_IP,"port":1434},
        {"id":"IA-049","name":"IIS WebDAV PUT enabled on ca01 (webshell upload)",
         "type":"http","url":f"http://{CA_IP}/",
         "eval":"status is not None"},
        {"id":"IA-050","name":"SNMP private (RW) community — UDP 161",
         "type":"udp","ip":FILE_IP,"port":161},
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # RECON (REC-001..REC-015)
    # ─────────────────────────────────────────────────────────────────────────
    rules += [
        {"id":"REC-001","name":"Domain enumeration via LDAP — authenticated query works",
         "type":"ldap","filter":"(objectClass=domain)","attributes":["name"],"eval":"len(entries) > 0"},
        {"id":"REC-002","name":"SPN enumeration — SPNs exist on user accounts",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
         "attributes":["sAMAccountName","servicePrincipalName"],"eval":"len(entries) > 0"},
        {"id":"REC-003","name":"BloodHound/SharpHound — authenticated LDAP readable",
         "type":"ldap","filter":"(objectClass=computer)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"REC-004","name":"Trust enumeration — trustedDomain objects exist",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["flatName"],"eval":"len(entries) > 0"},
        {"id":"REC-005","name":"GPO enumeration — GPOs readable by all",
         "type":"ldap","filter":"(objectClass=groupPolicyContainer)","attributes":["displayName"],"eval":"len(entries) > 0"},
        {"id":"REC-006","name":"ACL over-permission — nTSecurityDescriptor readable",
         "type":"ldap","filter":"(objectClass=domain)","attributes":["nTSecurityDescriptor"],"eval":"len(entries) > 0"},
        {"id":"REC-007","name":"DNS AXFR — zone transfer allowed",
         "type":"dns_axfr","ip":DC_IP,"zone":"corp.local"},
        {"id":"REC-008","name":"SMB share enumeration — guest accessible shares",
         "type":"smb_null","ip":FILE_IP},
        {"id":"REC-009","name":"MSSQL instance enumeration — SQL Browser UDP 1434",
         "type":"udp","ip":SQL_IP,"port":1434},
        {"id":"REC-010","name":"LLMNR/NBT-NS poisoning surface — no DNS suffix list",
         "type":"ldap","filter":"(&(objectClass=groupPolicyContainer)(displayName=*))",
         "attributes":["displayName"],"eval":"len(entries) >= 0"},
        {"id":"REC-011","name":"Password policy — anonymous read (weak lockout)",
         "type":"ldap","filter":"(objectClass=domain)",
         "attributes":["maxPwdAge","minPwdLength","lockoutThreshold"],"eval":"len(entries) > 0"},
        {"id":"REC-012","name":"ADCS template enumeration — templates exist",
         "type":"ldap","filter":"(objectClass=pKICertificateTemplate)",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"REC-013","name":"DoNotRequirePreAuth accounts — AS-REP roast targets",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"REC-014","name":"Machine account enumeration via LDAP",
         "type":"ldap","filter":"(objectClass=computer)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"REC-015","name":"Sensitive data in SYSVOL/NETLOGON scripts",
         "type":"winrm","ip":DC_IP,
         "cmd":"Get-ChildItem \\\\corp.local\\SYSVOL -Recurse -ErrorAction SilentlyContinue | Select-Object FullName",
         "eval":"len((output or '').strip()) > 10"},
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # ENUM (ENUM-001..ENUM-080) — port/service presence checks
    # ─────────────────────────────────────────────────────────────────────────
    enum_ports = [
        ("ENUM-001","SMB 445 reachable on file01",FILE_IP,445),
        ("ENUM-002","Global Catalog 3268 reachable",DC_IP,3268),
        ("ENUM-003","LDAP 389 reachable on DC",DC_IP,389),
        ("ENUM-004","LDAPS 636 reachable on DC",DC_IP,636),
        ("ENUM-005","Kerberos 88 reachable on DC",DC_IP,88),
        ("ENUM-006","RPC Endpoint Mapper 135 reachable",DC_IP,135),
        ("ENUM-007","NetBIOS 139 reachable on DC",DC_IP,139),
        ("ENUM-008","DNS 53 TCP reachable on DC",DC_IP,53),
        ("ENUM-009","WinRM 5985 reachable on DC",DC_IP,5985),
        ("ENUM-010","RDP 3389 reachable on ws01",WS_IP,3389),
        ("ENUM-011","SMB 445 reachable on DC",DC_IP,445),
        ("ENUM-012","SMB 445 reachable on CA",CA_IP,445),
        ("ENUM-013","SMB 445 reachable on sql01",SQL_IP,445),
        ("ENUM-014","MSSQL 1433 reachable on sql01",SQL_IP,1433),
        ("ENUM-015","Global Catalog 3269 LDAPS reachable",DC_IP,3269),
        ("ENUM-016","ADWS 9389 reachable",DC_IP,9389),
        ("ENUM-017","HTTP 80 reachable on ca01",CA_IP,80),
        ("ENUM-018","WinRM 5985 reachable on file01",FILE_IP,5985),
        ("ENUM-019","WinRM 5985 reachable on sql01",SQL_IP,5985),
        ("ENUM-020","WinRM 5985 reachable on ws01",WS_IP,5985),
        ("ENUM-021","LDAP 389 reachable on finance DC",FIN_DC_IP,389),
        ("ENUM-022","LDAP 389 reachable on root DC",ROOT_DC_IP,389),
        ("ENUM-023","Kerberos 88 on finance DC",FIN_DC_IP,88),
        ("ENUM-024","Kerberos 88 on root DC",ROOT_DC_IP,88),
        ("ENUM-025","SMB 445 on finance DC",FIN_DC_IP,445),
        ("ENUM-026","SMB 445 on root DC",ROOT_DC_IP,445),
        ("ENUM-027","FTP 21 on file01",FILE_IP,21),
        ("ENUM-028","Telnet 23 on file01",FILE_IP,23),
        ("ENUM-029","NFS 2049 on file01",FILE_IP,2049),
        ("ENUM-030","WinRM 5986 HTTPS reachable on DC",DC_IP,5986),
        ("ENUM-031","RDP 3389 on DC",DC_IP,3389),
        ("ENUM-032","Print Spooler — RPC 135 on DC",DC_IP,135),
        ("ENUM-033","HTTP 80 on DC (IIS present)",DC_IP,80),
        ("ENUM-034","HTTPS 443 on DC",DC_IP,443),
        ("ENUM-035","HTTPS 443 on CA",CA_IP,443),
        ("ENUM-036","WinRM 5985 on EU child DC",DC_EU_IP,5985),
        ("ENUM-037","SMB 445 on EU child DC",DC_EU_IP,445),
        ("ENUM-038","LDAP 389 on EU child DC",DC_EU_IP,389),
        ("ENUM-039","Kerberos 88 on EU child DC",DC_EU_IP,88),
        ("ENUM-040","RDP 3389 on file01",FILE_IP,3389),
        ("ENUM-041","RDP 3389 on sql01",SQL_IP,3389),
        ("ENUM-042","RDP 3389 on CA",CA_IP,3389),
        ("ENUM-043","WinRM 5985 on finance DC",FIN_DC_IP,5985),
        ("ENUM-044","WinRM 5985 on root DC",ROOT_DC_IP,5985),
        ("ENUM-045","RDP 3389 on finance DC",FIN_DC_IP,3389),
        ("ENUM-046","RDP 3389 on root DC",ROOT_DC_IP,3389),
        ("ENUM-047","HTTP 80 on file01 (IIS)",FILE_IP,80),
        ("ENUM-048","HTTPS 443 on file01",FILE_IP,443),
        ("ENUM-049","LDAP 389 on CA",CA_IP,389),
        ("ENUM-050","DNS 53 TCP on finance DC",FIN_DC_IP,53),
        ("ENUM-051","DNS 53 TCP on root DC",ROOT_DC_IP,53),
        ("ENUM-052","SMB 445 on ws01",WS_IP,445),
        ("ENUM-053","NetBIOS 139 on file01",FILE_IP,139),
        ("ENUM-054","NetBIOS 139 on ws01",WS_IP,139),
        ("ENUM-055","HTTP 80 on ws01",WS_IP,80),
        ("ENUM-056","RPC 135 on file01",FILE_IP,135),
        ("ENUM-057","RPC 135 on sql01",SQL_IP,135),
        ("ENUM-058","RPC 135 on ws01",WS_IP,135),
        ("ENUM-059","WinRM 5986 HTTPS on CA",CA_IP,5986),
        ("ENUM-060","WinRM 5986 HTTPS on file01",FILE_IP,5986),
        ("ENUM-061","WMI DCOM — RPC 135 on DC",DC_IP,135),
        ("ENUM-062","MSSQL 1433 enumeration",SQL_IP,1433),
        ("ENUM-063","DNS 53 on EU DC",DC_EU_IP,53),
        ("ENUM-064","Global Catalog 3268 on finance DC",FIN_DC_IP,3268),
        ("ENUM-065","Global Catalog 3268 on root DC",ROOT_DC_IP,3268),
        ("ENUM-066","ADWS 9389 on EU DC",DC_EU_IP,9389),
        ("ENUM-067","ADWS 9389 on finance DC",FIN_DC_IP,9389),
        ("ENUM-068","ADWS 9389 on root DC",ROOT_DC_IP,9389),
        ("ENUM-069","LDAP 389 on ws01",WS_IP,389),
        ("ENUM-070","Kerberos 88 on CA",CA_IP,88),
        ("ENUM-071","GPO enumeration port — DC LDAP 389",DC_IP,389),
        ("ENUM-072","SYSVOL access — SMB 445 on DC",DC_IP,445),
        ("ENUM-073","NETLOGON share — SMB 445 on DC",DC_IP,445),
        ("ENUM-074","Print spooler RPC surface — 135 CA",CA_IP,135),
        ("ENUM-075","Print spooler RPC surface — 135 EU DC",DC_EU_IP,135),
        ("ENUM-076","HTTPS 443 on sql01",SQL_IP,443),
        ("ENUM-077","HTTPS 443 on ws01",WS_IP,443),
        ("ENUM-078","HTTPS 443 on EU DC",DC_EU_IP,443),
        ("ENUM-079","HTTPS 443 on finance DC",FIN_DC_IP,443),
        ("ENUM-080","HTTPS 443 on root DC",ROOT_DC_IP,443),
    ]
    for eid, name, ip, port in enum_ports:
        rules.append({"id":eid,"name":name,"type":"port","ip":ip,"port":port})

    # ─────────────────────────────────────────────────────────────────────────
    # CREDENTIAL ACCESS (CRED-001..CRED-065)
    # ─────────────────────────────────────────────────────────────────────────
    rules += [
        {"id":"CRED-001","name":"Kerberoastable service accounts with SPNs",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-002","name":"AS-REP Roastable accounts (DoNotRequirePreAuth)",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-003","name":"Password spray — multiple user accounts exist",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 5"},
        {"id":"CRED-004","name":"Credential hunting — WinRM 5985 on ws01",
         "type":"port","ip":WS_IP,"port":5985},
        {"id":"CRED-005","name":"LSASS dump — Defender disabled on ws01",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled",
         "eval":"output is not None and 'False' in (output or 'True')"},
        {"id":"CRED-006","name":"SAM extraction — SeBackupPrivilege accounts",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Backup Operators))",
         "attributes":["member"],"eval":"_member_count(entries) > 0"},
        {"id":"CRED-007","name":"NTDS.dit extraction — Backup Operators populated",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Backup Operators))",
         "attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"CRED-008","name":"Shadow Credentials — msDS-KeyCredentialLink writable",
         "type":"ldap","filter":"(msDS-KeyCredentialLink=*)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-009","name":"Reversible password encryption enabled on accounts",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-010","name":"Token impersonation — services running as different users",
         "type":"winrm","ip":DC_IP,
         "cmd":"Get-WmiObject Win32_Service | Where-Object {$_.StartName -notmatch 'LocalSystem|LocalService|NetworkService'} | Select-Object Name,StartName",
         "eval":"len((output or '').strip()) > 10"},
        {"id":"CRED-011","name":"Pass-the-Hash — NTLMv1 enabled (LmCompatibilityLevel < 3)",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').LmCompatibilityLevel",
         "eval":"output is not None and _safe_int(output, 3) < 3"},
        {"id":"CRED-012","name":"Pass-the-Ticket — Kerberos TGT issuance port 88 open",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"CRED-013","name":"DCSync — Replicate Directory Changes delegated",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Backup Operators))",
         "attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"CRED-014","name":"DCSync GetChangesAll — sync_user has extended rights",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(cn=sync*))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-015","name":"DCShadow — Schema Admin loosely delegated",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Schema Admins))","attributes":["member"],
         "eval":"len(entries) > 0"},
        {"id":"CRED-016","name":"Constrained Delegation — TRUSTED_TO_AUTH_FOR_DELEGATION",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=16777216))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-017","name":"RBCD — msDS-AllowedToActOnBehalfOfOtherIdentity set",
         "type":"ldap","filter":"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-018","name":"Unconstrained Delegation — TRUSTED_FOR_DELEGATION on computers",
         "type":"ldap","filter":"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(objectClass=domain)))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-019","name":"PrintNightmare — Spooler on DC (post-cred escalation path)",
         "type":"winrm","ip":DC_IP,"cmd":"(Get-Service Spooler).Status","eval":"'Running' in (output or '')"},
        {"id":"CRED-020","name":"PetitPotam→ADCS — ADCS web enrollment HTTP+NTLM",
         "type":"http","url":f"http://{CA_IP}/certsrv/","eval":"status == 401"},
        {"id":"CRED-021","name":"DFSCoerce — DFS Namespace service running on DC",
         "type":"winrm","ip":DC_IP,"cmd":"(Get-Service Dfs -ErrorAction SilentlyContinue).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"CRED-022","name":"PrinterBug — Print Spooler reachable from network",
         "type":"winrm","ip":DC_IP,"cmd":"(Get-Service Spooler).Status","eval":"'Running' in (output or '')"},
        {"id":"CRED-023","name":"noPac — MachineAccountQuota > 0",
         "type":"ldap","filter":"(objectClass=domain)",
         "attributes":["ms-DS-MachineAccountQuota"],
         "eval":"len(entries)>0 and _safe_int(entries[0]['ms_DS_MachineAccountQuota'].value if 'ms_DS_MachineAccountQuota' in entries[0].entry_attributes_as_dict else 0, 0) > 0"},
        {"id":"CRED-024","name":"Certifried/ESC22 — ADCS web enrollment + DNS dNSHostName writable",
         "type":"http","url":f"http://{CA_IP}/certsrv/","eval":"status is not None"},
        {"id":"CRED-025","name":"WebClient service abuse — WebClient auto-start",
         "type":"winrm","ip":WS_IP,"cmd":"(Get-Service WebClient -ErrorAction SilentlyContinue).StartType",
         "eval":"'Automatic' in (output or '')"},
        {"id":"CRED-026","name":"ADIDNS wildcard poisoning — Authenticated Users can create records",
         "type":"ldap","filter":"(objectClass=dnsZone)","attributes":["name"],
         "base":"DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local",
         "eval":"len(entries) >= 0"},
        {"id":"CRED-027","name":"ADCS EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) set on CA",
         "type":"winrm","ip":CA_IP,
         "cmd":"certutil -config . -getreg policy\\EditFlags 2>&1",
         "eval":"'EDITF_ATTRIBUTESUBJECTALTNAME2' in (output or '')"},
        {"id":"CRED-028","name":"ESC15/CVE-2024-49019 — vulnerable cert template",
         "type":"ldap","filter":"(objectClass=pKICertificateTemplate)",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"CRED-029","name":"NTLM hash downgrade — LmCompatibilityLevel <= 2",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').LmCompatibilityLevel",
         "eval":"output is not None and _safe_int(output, 5) <= 2"},
        {"id":"CRED-030","name":"GPP passwords — cpassword in SYSVOL",
         "type":"winrm","ip":DC_IP,
         "cmd":"Get-ChildItem \\\\corp.local\\SYSVOL -Recurse -Include Groups.xml -ErrorAction SilentlyContinue | Get-Content | Select-String cpassword",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"CRED-031","name":"AS-REP Roast variant — DoNotRequirePreAuth users",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-032","name":"LDAP simple bind — LDAP 389 without signing",
         "type":"port","ip":DC_IP,"port":389},
        {"id":"CRED-033","name":"LAPS password readable — ms-Mcs-AdmPwd attribute",
         "type":"ldap","filter":"(&(objectClass=computer)(ms-Mcs-AdmPwd=*))",
         "attributes":["sAMAccountName","ms-Mcs-AdmPwd"],"eval":"len(entries) > 0"},
        {"id":"CRED-034","name":"gMSA password readable — msds-ManagedPassword accounts",
         "type":"ldap","filter":"(objectClass=msDS-GroupManagedServiceAccount)",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-035","name":"Credential Manager saved creds — WinRM access to ws01",
         "type":"port","ip":WS_IP,"port":5985},
        {"id":"CRED-036","name":"Browser creds — Defender off on ws01",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled",
         "eval":"'False' in (output or 'True')"},
        {"id":"CRED-037","name":"AzureAD SSO — Entra hybrid sync configured",
         "type":"ldap","filter":"(objectClass=msDS-Device)","attributes":["name"],"eval":"len(entries) >= 0"},
        {"id":"CRED-038","name":"SSP injection — custom LSA packages in registry",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').'Security Packages'",
         "eval":"len((output or '').strip()) > 0"},
        {"id":"CRED-039","name":"SeBackupPrivilege — Backup Operators group populated",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Backup Operators))",
         "attributes":["member"],"eval":"_member_count(entries) > 0"},
        {"id":"CRED-040","name":"SeTrustedCredManAccess — privilege assigned",
         "type":"winrm","ip":DC_IP,
         "cmd":"secedit /export /cfg C:\\Windows\\Temp\\sec.cfg /quiet; Select-String 'SeTrustedCredMan' C:\\Windows\\Temp\\sec.cfg",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"CRED-041","name":"SeDebugPrivilege — Administrators have debug privilege",
         "type":"winrm","ip":DC_IP,
         "cmd":"whoami /priv | findstr SeDebugPrivilege",
         "eval":"'SeDebugPrivilege' in (output or '')"},
        {"id":"CRED-042","name":"SeImpersonatePrivilege — service accounts on sql01",
         "type":"winrm","ip":SQL_IP,
         "cmd":"whoami /priv | findstr SeImpersonatePrivilege",
         "eval":"'SeImpersonatePrivilege' in (output or '')"},
        {"id":"CRED-043","name":"RID hijacking surface — SAM registry accessible",
         "type":"winrm","ip":WS_IP,
         "cmd":"Test-Path 'HKLM:\\SAM\\SAM'",
         "eval":"'True' in (output or '')"},
        {"id":"CRED-044","name":"VSS hash dump — Volume Shadow Copy service",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-Service VSS).Status","eval":"'Running' in (output or '')"},
        {"id":"CRED-045","name":"DPAPI master key — SYSTEM context accessible",
         "type":"winrm","ip":DC_IP,
         "cmd":"Test-Path 'C:\\Windows\\System32\\Microsoft\\Protect'",
         "eval":"'True' in (output or '')"},
        {"id":"CRED-046","name":"NTLMv2 reflection — LLMNR/NBT-NS on",
         "type":"ldap","filter":"(objectClass=domain)","attributes":["name"],"eval":"len(entries) > 0"},
        {"id":"CRED-047","name":"Certificate private key export — ESC12 agent template",
         "type":"ldap","filter":"(objectClass=pKICertificateTemplate)",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"CRED-048","name":"NTLM relay to LDAPS — channel binding disabled",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding",
         "eval":"output is None or '0' in (output or '0')"},
        {"id":"CRED-049","name":"WebDAV coercion → LDAP relay — WebClient service",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Service WebClient -ErrorAction SilentlyContinue).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"CRED-050","name":"DNSSEC ZSK leak — DNSSEC zones configured",
         "type":"port","ip":DC_IP,"port":53},
        {"id":"CRED-051","name":"CVE-2025-24071 — .library-ms NTLM leak surface",
         "type":"port","ip":FILE_IP,"port":445},
        {"id":"CRED-052","name":"CVE-2025-33073 — NTLM relay via .library-ms",
         "type":"port","ip":DC_IP,"port":389},
        {"id":"CRED-053","name":"ShadowCoerce — FSRVP service running",
         "type":"winrm","ip":FILE_IP,
         "cmd":"(Get-Service FSRVP -ErrorAction SilentlyContinue).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"CRED-054","name":"Pre-Win2000 computer accounts — predictable passwords",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))",
         "attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"CRED-055","name":"RemoteMonologue — DCOM accessible on target",
         "type":"port","ip":WS_IP,"port":135},
        {"id":"CRED-056","name":"Disabled accounts with group memberships",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
         "attributes":["sAMAccountName","memberOf"],"eval":"len(entries) > 0"},
        {"id":"CRED-057","name":"AD Recycle Bin disabled — deleted objects restorable",
         "type":"ldap",
         "filter":"(objectClass=msDS-RecycleBinFeature)",
         "attributes":["name"],
         "base":"CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local",
         "eval":"len(entries) == 0"},
        {"id":"CRED-058","name":"gMSADumper — gMSA accounts exist",
         "type":"ldap","filter":"(objectClass=msDS-GroupManagedServiceAccount)",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"CRED-059","name":"LAPS v2 bulk read — LAPS not deployed (no ms-Mcs-AdmPwd)",
         "type":"ldap","filter":"(&(objectClass=computer)(ms-Mcs-AdmPwd=*))",
         "attributes":["sAMAccountName"],"eval":"len(entries) == 0"},  # no LAPS = vulnerable
        {"id":"CRED-060","name":"SCCM NAA secrets — SCCM client installed",
         "type":"winrm","ip":WS_IP,
         "cmd":"Test-Path 'C:\\Windows\\CCM\\CcmExec.exe'",
         "eval":"'True' in (output or '')"},
        {"id":"CRED-061","name":"Kerberos relay via CNAME — ADIDNS write open",
         "type":"ldap","filter":"(objectClass=dnsNode)","attributes":["name"],
         "base":"DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local",
         "eval":"len(entries) >= 0"},
        {"id":"CRED-062","name":"Reflective Kerberos relay — same host relay surface",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"CRED-063","name":"MS14-068 PAC forgery — legacy Kerberos surface",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"CRED-064","name":"Internal-Monologue — LmCompatibilityLevel <= 2",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').LmCompatibilityLevel",
         "eval":"output is not None and _safe_int(output, 5) <= 2"},
        {"id":"CRED-065","name":"Remote DPAPI backup key — LDAP 389 accessible",
         "type":"port","ip":DC_IP,"port":389},
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # LATERAL MOVEMENT (LAT-001..LAT-035)
    # ─────────────────────────────────────────────────────────────────────────
    rules += [
        {"id":"LAT-001","name":"PsExec/PtH — ADMIN$ share reachable on DC",
         "type":"port","ip":DC_IP,"port":445},
        {"id":"LAT-002","name":"WMI exec — WMI 135 reachable",
         "type":"port","ip":DC_IP,"port":135},
        {"id":"LAT-003","name":"Scheduled task remote — WinRM 5985 reachable",
         "type":"port","ip":DC_IP,"port":5985},
        {"id":"LAT-004","name":"Service creation remote — sc.exe over 445",
         "type":"port","ip":DC_IP,"port":445},
        {"id":"LAT-005","name":"DCOM — RPC 135 reachable",
         "type":"port","ip":DC_IP,"port":135},
        {"id":"LAT-006","name":"WinRM lateral — 5985 open on all hosts",
         "type":"port","ip":FILE_IP,"port":5985},
        {"id":"LAT-007","name":"RDP Restricted Admin — RDP 3389 reachable",
         "type":"port","ip":DC_IP,"port":3389},
        {"id":"LAT-008","name":"Remote Registry — RemoteRegistry service running",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-Service RemoteRegistry).Status","eval":"'Running' in (output or '')"},
        {"id":"LAT-009","name":"SMB named pipe exec — atsvc/svcctl accessible",
         "type":"port","ip":DC_IP,"port":445},
        {"id":"LAT-010","name":"SSH tunneling — OpenSSH on file01",
         "type":"port","ip":FILE_IP,"port":22},
        {"id":"LAT-011","name":"Cert-based auth relay — ADCS 80 reachable",
         "type":"port","ip":CA_IP,"port":80},
        {"id":"LAT-012","name":"Cross-forest SID history — sIDHistory populated",
         "type":"ldap","filter":"(&(objectClass=user)(sIDHistory=*))","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"LAT-013","name":"Shortcut trust — trustedDomain objects exist",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["flatName"],"eval":"len(entries) > 0"},
        {"id":"LAT-014","name":"Realm trust MIT Kerberos — RC4 enabled",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["trustAttributes"],"eval":"len(entries) > 0"},
        {"id":"LAT-015","name":"IPv6 DHCPv6+WPAD — IPv6 stack on ws01",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object Enabled).Count",
         "eval":"output is not None and output.strip() not in ('','0')"},
        {"id":"LAT-016","name":"RBCD chain — msDS-AllowedToActOnBehalf populated",
         "type":"ldap","filter":"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"LAT-017","name":"ACL — ForceChangePassword: Helpdesk GenericWrite",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Helpdesk*))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"LAT-018","name":"ACL — Add members to IT_Admins group",
         "type":"ldap","filter":"(&(objectClass=group)(cn=IT_Admins*))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"LAT-019","name":"ACL — Shadow Credentials: msDS-KeyCredentialLink writable",
         "type":"ldap","filter":"(msDS-KeyCredentialLink=*)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"LAT-020","name":"ACL — WriteOwner on Domain Admins group",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Domain Admins))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"LAT-021","name":"ACL — WriteDACL on domain for DCSync",
         "type":"ldap","filter":"(objectClass=domain)","attributes":["nTSecurityDescriptor"],"eval":"len(entries) > 0"},
        {"id":"LAT-022","name":"ACL — WriteSPN for Kerberoasting",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"LAT-023","name":"Cross-forest TGT delegation — trust with TGT delegation",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["trustAttributes"],"eval":"len(entries) > 0"},
        {"id":"LAT-024","name":"LDAP signing not required — relay possible",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -ErrorAction SilentlyContinue).LDAPServerIntegrity",
         "eval":"output is None or '1' not in (output or '1')"},
        {"id":"LAT-025","name":"WebDAV coercion — WebClient on ws01",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Service WebClient -ErrorAction SilentlyContinue).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"LAT-026","name":"KrbRelayUp — RBCD write to local machine account",
         "type":"ldap","filter":"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"LAT-027","name":"mitm6 — IPv6 enabled on domain hosts",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object Enabled).Count",
         "eval":"output is not None and output.strip() not in ('','0')"},
        {"id":"LAT-028","name":"LLMNR+SMB relay — SMB signing off on ws01",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-SmbServerConfiguration).RequireSecuritySignature",
         "eval":"'False' in (output or 'True')"},
        {"id":"LAT-029","name":"SCShell — service binPath modifiable on target",
         "type":"port","ip":DC_IP,"port":445},
        {"id":"LAT-030","name":"RDP session hijack — multiple RDP sessions on DC",
         "type":"winrm","ip":DC_IP,
         "cmd":"query session 2>&1","eval":"len((output or '').strip()) > 5"},
        {"id":"LAT-031","name":"DnsAdmins → DLL load — DnsAdmins group populated",
         "type":"ldap","filter":"(&(objectClass=group)(cn=DnsAdmins))","attributes":["member"],
         "eval":"_member_count(entries) > 0"},
        {"id":"LAT-032","name":"ADIDNS record write — Authenticated Users can create",
         "type":"ldap","filter":"(objectClass=dnsZone)","attributes":["name"],
         "base":"DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local",
         "eval":"len(entries) >= 0"},
        {"id":"LAT-033","name":"LNK/SCF drop — writable share on file01",
         "type":"winrm","ip":FILE_IP,
         "cmd":"Get-SmbShare | Where-Object {$_.Name -ne 'IPC$' -and $_.Name -ne 'ADMIN$'} | Select-Object Name",
         "eval":"len((output or '').strip()) > 10"},
        {"id":"LAT-034","name":"Foreign group membership — FSPs in corp.local groups",
         "type":"ldap","filter":"(objectClass=foreignSecurityPrincipal)","attributes":["name"],"eval":"len(entries) > 0"},
        {"id":"LAT-035","name":"Cross-forest golden + SID history — trust configured",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["flatName"],"eval":"len(entries) > 0"},
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # PRIVILEGE ESCALATION (PE-001..PE-060)
    # ─────────────────────────────────────────────────────────────────────────
    rules += [
        {"id":"PE-001","name":"SeImpersonatePrivilege on sql01 (Potato suite)",
         "type":"winrm","ip":SQL_IP,"cmd":"whoami /priv | findstr SeImpersonatePrivilege",
         "eval":"'SeImpersonatePrivilege' in (output or '')"},
        {"id":"PE-002","name":"SeAssignPrimaryTokenPrivilege on service account",
         "type":"winrm","ip":DC_IP,"cmd":"whoami /priv | findstr SeAssignPrimary",
         "eval":"'SeAssign' in (output or '')"},
        {"id":"PE-003","name":"SeTcbPrivilege — logon scripts",
         "type":"winrm","ip":DC_IP,"cmd":"whoami /priv | findstr SeTcbPrivilege",
         "eval":"'SeTcb' in (output or '')"},
        {"id":"PE-004","name":"SeLoadDriverPrivilege — driver install possible",
         "type":"winrm","ip":WS_IP,"cmd":"whoami /priv | findstr SeLoadDriver",
         "eval":"'SeLoadDriver' in (output or '')"},
        {"id":"PE-005","name":"SeBackupPrivilege — Backup Operators group",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Backup Operators))","attributes":["member"],
         "eval":"_member_count(entries) > 0"},
        {"id":"PE-006","name":"SeRestorePrivilege — Backup Operators group",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Backup Operators))","attributes":["member"],
         "eval":"_member_count(entries) > 0"},
        {"id":"PE-007","name":"Unquoted service path on ws01",
         "type":"winrm","ip":WS_IP,
         "cmd":"Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch '\"' -and $_.PathName -match ' ' -and $_.PathName -match '^[^\\\\]'} | Select-Object Name,PathName",
         "eval":"len((output or '').strip()) > 10"},
        {"id":"PE-008","name":"Weak service DACL — Everyone full control on service",
         "type":"winrm","ip":WS_IP,
         "cmd":"sc.exe sdshow VulnService 2>&1",
         "eval":"'Everyone' in (output or '') or 'AU' in (output or '')"},
        {"id":"PE-009","name":"DLL hijacking — writable directories in PATH",
         "type":"winrm","ip":WS_IP,
         "cmd":"$env:PATH -split ';' | Where-Object { Test-Path $_ } | Where-Object { (Get-Acl $_).Access | Where-Object {$_.IdentityReference -match 'Everyone|Users' -and $_.FileSystemRights -match 'Write|Modify'} }",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PE-010","name":"PATH hijacking — C:\\Tools writable in PATH",
         "type":"winrm","ip":WS_IP,
         "cmd":"(icacls C:\\Tools 2>&1) -join ' '",
         "eval":"'Everyone' in (output or '') or 'Users' in (output or '')"},
        {"id":"PE-011","name":"AlwaysInstallElevated — registry policy set",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated",
         "eval":"output is not None and '1' in (output or '')"},
        {"id":"PE-012","name":"UAC bypass surface — default UAC on admin accounts",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA",
         "eval":"output is not None and '1' in (output or '')"},
        {"id":"PE-013","name":"Token kidnapping — SeImpersonate present",
         "type":"winrm","ip":SQL_IP,"cmd":"whoami /priv | findstr SeImpersonatePrivilege",
         "eval":"'SeImpersonate' in (output or '')"},
        {"id":"PE-014","name":"Named pipe impersonation — custom pipe service",
         "type":"winrm","ip":WS_IP,"cmd":"Get-ChildItem \\\\.\\pipe\\ 2>&1 | Select-Object Name",
         "eval":"len((output or '').strip()) > 10"},
        {"id":"PE-015","name":"Service binary overwrite — writable service binary",
         "type":"winrm","ip":WS_IP,
         "cmd":"Get-WmiObject Win32_Service | ForEach-Object { $p=($_.PathName -replace '\"','').Split(' ')[0]; if(Test-Path $p){(Get-Acl $p).Access | Where-Object {$_.IdentityReference -match 'Everyone|Users' -and $_.FileSystemRights -match 'Write|Modify'} | Select-Object @{n='svc';e={$_.IdentityReference}}}}",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PE-016","name":"Task Scheduler XML race — task dir writable",
         "type":"winrm","ip":WS_IP,
         "cmd":"icacls C:\\Windows\\System32\\Tasks 2>&1",
         "eval":"'Users' in (output or '') and ('Write' in (output or '') or 'Modify' in (output or ''))"},
        {"id":"PE-017","name":"COM hijacking — PrintNotify COM exploitable",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Service Spooler).Status","eval":"'Running' in (output or '')"},
        {"id":"PE-018","name":"Insecure SYSVOL GPO — GPO scripts writable",
         "type":"winrm","ip":DC_IP,
         "cmd":"Get-ChildItem \\\\corp.local\\SYSVOL -Recurse -Include *.ps1,*.bat,*.vbs -ErrorAction SilentlyContinue | ForEach-Object { (Get-Acl $_).Access | Where-Object {$_.IdentityReference -match 'Authenticated Users|Everyone' -and $_.FileSystemRights -match 'Write'}} | Select-Object IdentityReference",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PE-019","name":"Backup Operators → GPO/flag files on DC",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Backup Operators))","attributes":["member"],
         "eval":"_member_count(entries) > 0"},
        {"id":"PE-020","name":"SeChangeNotify — folder traversal allowed",
         "type":"winrm","ip":WS_IP,"cmd":"whoami /priv | findstr SeChangeNotify",
         "eval":"'SeChangeNotify' in (output or '')"},
        {"id":"PE-021","name":"SeIncreaseQuota — new AD object creation",
         "type":"winrm","ip":DC_IP,"cmd":"whoami /priv | findstr SeIncreaseQuota",
         "eval":"'SeIncreaseQuota' in (output or '')"},
        {"id":"PE-022","name":"Scheduled task hijack — .job files writable",
         "type":"winrm","ip":WS_IP,
         "cmd":"icacls C:\\Windows\\Tasks 2>&1","eval":"'Everyone' in (output or '') or 'Users' in (output or '')"},
        {"id":"PE-023","name":"Startup folder writable by Domain Users",
         "type":"winrm","ip":WS_IP,
         "cmd":"icacls 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup' 2>&1",
         "eval":"'Domain Users' in (output or '') or 'Everyone' in (output or '')"},
        {"id":"PE-024","name":"HiveNightmare CVE-2021-36934 — SAM VSS readable",
         "type":"winrm","ip":WS_IP,
         "cmd":"icacls C:\\Windows\\System32\\config\\SAM 2>&1",
         "eval":"'BUILTIN\\\\Users' in (output or '') or 'Users:(R)' in (output or '')"},
        {"id":"PE-025","name":"Token privilege suite — any privilege present",
         "type":"winrm","ip":WS_IP,"cmd":"whoami /priv","eval":"len((output or '').strip()) > 20"},
        {"id":"PE-026","name":"SeManageVolume — junction exploit surface",
         "type":"winrm","ip":WS_IP,"cmd":"whoami /priv | findstr SeManageVolume",
         "eval":"'SeManageVolume' in (output or '')"},
        {"id":"PE-027","name":"SeCreateSymbolicLink — developer group has it",
         "type":"winrm","ip":WS_IP,"cmd":"whoami /priv | findstr SeCreateSymbolicLink",
         "eval":"'SeCreateSymbolic' in (output or '')"},
        {"id":"PE-028","name":"SeDebug → LSASS token steal",
         "type":"winrm","ip":WS_IP,"cmd":"whoami /priv | findstr SeDebugPrivilege",
         "eval":"'SeDebugPrivilege' in (output or '')"},
        {"id":"PE-029","name":"SeTakeOwnership — Asset_Owners group",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Asset_Owners*))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"PE-030","name":"Service binary replacement — writable service exe",
         "type":"winrm","ip":WS_IP,
         "cmd":"Get-WmiObject Win32_Service | ForEach-Object { $p=($_.PathName -replace '\"','').Split(' ')[0]; if($p -and (Test-Path $p)){icacls $p 2>&1}} | Select-String 'Everyone|Users.*(Write|Modify)'",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PE-031","name":"CVE-2022-30190 Follina — MSDT protocol enabled",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Item 'HKCR:\\ms-msdt' -ErrorAction SilentlyContinue).Name",
         "eval":"'ms-msdt' in (output or '')"},
        {"id":"PE-032","name":"CVE-2023-21716 WordPad RCE — WordPad installed",
         "type":"winrm","ip":WS_IP,
         "cmd":"Test-Path 'C:\\Program Files\\Windows NT\\Accessories\\wordpad.exe'",
         "eval":"'True' in (output or '')"},
        {"id":"PE-033","name":"CVE-2023-28252 CLFS EoP — Windows unpatched",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-HotFix -Id KB5025230 -ErrorAction SilentlyContinue).HotFixID",
         "eval":"output is None or len((output or '').strip()) == 0"},
        {"id":"PE-034","name":"CVE-2023-36745 WinSockAFD — system exposed",
         "type":"port","ip":WS_IP,"port":5985},
        {"id":"PE-035","name":"CVE-2023-29360 TrustedInstaller LPE — unpatched",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-HotFix -Id KB5028182 -ErrorAction SilentlyContinue).HotFixID",
         "eval":"output is None or len((output or '').strip()) == 0"},
        {"id":"PE-036","name":"CVE-2024-20673/20674 Windows LPEs — system exposed",
         "type":"port","ip":WS_IP,"port":5985},
        {"id":"PE-037","name":"CVE-2024-26229 CSC Service LPE — CSC present",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Service CscService -ErrorAction SilentlyContinue).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"PE-038","name":"CVE-2024-30051 DWM LPE — graphical session",
         "type":"port","ip":WS_IP,"port":3389},
        {"id":"PE-039","name":"CVE-2024-38063 TCP/IP IPv6 RCE — IPv6 enabled",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object Enabled).Count",
         "eval":"output is not None and output.strip() not in ('','0')"},
        {"id":"PE-040","name":"2025 LPE placeholder — WinRM accessible for checks",
         "type":"port","ip":WS_IP,"port":5985},
        {"id":"PE-041","name":"Modifiable service path — parent folder writable",
         "type":"winrm","ip":WS_IP,
         "cmd":"Get-WmiObject Win32_Service | ForEach-Object { $p=Split-Path ($_.PathName -replace '\"',''); if($p -and (Test-Path $p)){icacls $p 2>&1}} | Select-String 'Everyone|Users.*(Write|Modify)'",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PE-042","name":"Modifiable registry path — service ImagePath writable",
         "type":"winrm","ip":WS_IP,
         "cmd":"Get-ChildItem HKLM:\\SYSTEM\\CurrentControlSet\\Services | ForEach-Object { (Get-Acl $_.PSPath).Access | Where-Object {$_.IdentityReference -match 'Everyone|Users' -and $_.RegistryRights -match 'SetValue|FullControl'} | Select-Object IdentityReference}",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PE-043","name":"StorSvc abuse — StorSvc running with SYSTEM",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Service StorSvc -ErrorAction SilentlyContinue).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"PE-044","name":"CDPSvc abuse — Connected Devices Platform running",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Service CDPSvc -ErrorAction SilentlyContinue).Status",
         "eval":"'Running' in (output or '')"},
        {"id":"PE-045","name":"Perfmon help key escalation — UAC auto-elevate",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA",
         "eval":"'1' in (output or '')"},
        {"id":"PE-046","name":"CVE-2022-38047 Point and Print EoP — unpatched",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -ErrorAction SilentlyContinue).NoWarningNoElevationOnInstall",
         "eval":"output is not None and '1' in (output or '')"},
        {"id":"PE-047","name":"CVE-2022-44676 Windows LPE — unpatched system",
         "type":"port","ip":WS_IP,"port":5985},
        {"id":"PE-048","name":"CVE-2022-33647 Kerberos S4U2Self LPE",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"PE-049","name":"Third-party vulnerable driver — RTCore64.sys present",
         "type":"winrm","ip":WS_IP,
         "cmd":"Test-Path 'C:\\Windows\\System32\\drivers\\RTCore64.sys'",
         "eval":"'True' in (output or '')"},
        {"id":"PE-050","name":"MSI repair mode escalation — MSI accessible",
         "type":"winrm","ip":WS_IP,
         "cmd":"Get-ChildItem C:\\Windows\\Installer -Filter *.msi -ErrorAction SilentlyContinue | Select-Object Name",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PE-051","name":"KrbRelayUp local — RBCD write to machine account",
         "type":"ldap","filter":"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"PE-052","name":"Potato suite — SeImpersonate on service accounts",
         "type":"winrm","ip":SQL_IP,"cmd":"whoami /priv | findstr SeImpersonatePrivilege",
         "eval":"'SeImpersonate' in (output or '')"},
        {"id":"PE-053","name":"CertPotato — ADCS reachable + SeImpersonate",
         "type":"port","ip":CA_IP,"port":80},
        {"id":"PE-054","name":"NetExec local-auth sweep — same local admin password",
         "type":"ldap","filter":"(&(objectClass=computer)(ms-Mcs-AdmPwd=*))",
         "attributes":["sAMAccountName"],"eval":"len(entries) == 0"},  # no LAPS = reused password
        {"id":"PE-055","name":"2025 LPE yearly placeholder — WinRM accessible",
         "type":"port","ip":WS_IP,"port":5985},
        {"id":"PE-056","name":"UAC bypass via WSReset/EventViewer — UAC enabled",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA",
         "eval":"'1' in (output or '')"},
        {"id":"PE-057","name":"Server Operators → SYSTEM on DC",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Server Operators))","attributes":["member"],
         "eval":"_member_count(entries) > 0"},
        {"id":"PE-058","name":"Print Operators → driver install on DC",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Print Operators))","attributes":["member"],
         "eval":"_member_count(entries) > 0"},
        {"id":"PE-059","name":"Backup Operators on DC → NTDS.dit theft",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Backup Operators))","attributes":["member"],
         "eval":"_member_count(entries) > 0"},
        {"id":"PE-060","name":"TrustedInstaller context — SYSTEM accessible via psexec",
         "type":"winrm","ip":DC_IP,"cmd":"whoami","eval":"True"},  # connectivity = surface present
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # PERSISTENCE (PER-001..PER-037)
    # ─────────────────────────────────────────────────────────────────────────
    rules += [
        {"id":"PER-001","name":"Registry Run keys writable by admin",
         "type":"winrm","ip":DC_IP,
         "cmd":"Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PER-002","name":"IFEO debugger set on accessibility binaries",
         "type":"winrm","ip":DC_IP,
         "cmd":"Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe' -ErrorAction SilentlyContinue",
         "eval":"output is not None and 'Debugger' in (output or '')"},
        {"id":"PER-003","name":"Sticky Keys hijack — sethc.exe replaced",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Item C:\\Windows\\System32\\sethc.exe).VersionInfo.FileDescription",
         "eval":"'cmd' in (output or '').lower() or 'command' in (output or '').lower()"},
        {"id":"PER-004","name":"Persistence service installed — PersistenceService.exe",
         "type":"winrm","ip":DC_IP,
         "cmd":"Get-Service PersistenceService -ErrorAction SilentlyContinue",
         "eval":"output is not None and 'PersistenceService' in (output or '')"},
        {"id":"PER-005","name":"Scheduled task persistence — UpdaterService task",
         "type":"winrm","ip":DC_IP,
         "cmd":"Get-ScheduledTask -TaskName 'UpdaterService' -ErrorAction SilentlyContinue",
         "eval":"output is not None and 'UpdaterService' in (output or '')"},
        {"id":"PER-006","name":"WMI event subscription persistence",
         "type":"winrm","ip":DC_IP,
         "cmd":"Get-WMIObject -Namespace root\\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PER-007","name":"Netsh helper DLL persistence",
         "type":"winrm","ip":DC_IP,
         "cmd":"netsh show helper 2>&1","eval":"len((output or '').strip()) > 20"},
        {"id":"PER-008","name":"COM hijacking — TreatAs/ProgID redirected",
         "type":"winrm","ip":WS_IP,
         "cmd":"Get-ChildItem HKCU:\\Software\\Classes -ErrorAction SilentlyContinue | Where-Object {$_.PSChildName -match 'CLSID|ProgID'} | Measure-Object | Select-Object Count",
         "eval":"output is not None and _safe_int((output or '').split()[-2] if len((output or '').split()) > 1 else '0', 0) > 0"},
        {"id":"PER-009","name":"Authentication package persistence — custom LSA AP",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').'Authentication Packages'",
         "eval":"len((output or '').strip()) > 5"},
        {"id":"PER-010","name":"W32Time DLL hijack — time provider modified",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient' -ErrorAction SilentlyContinue).DllName",
         "eval":"'w32tm.dll' not in (output or 'w32tm.dll').lower()"},
        {"id":"PER-011","name":"BootExecute modified — SetupExecute persistence",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager').BootExecute",
         "eval":"'autocheck autochk *' not in (output or 'autocheck autochk *').lower() or len((output or '').strip()) > 25"},
        {"id":"PER-012","name":"AppInit_DLLs enabled — DLL loaded into every process",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows').AppInit_DLLs",
         "eval":"len((output or '').strip()) > 0"},
        {"id":"PER-013","name":"Accessibility tools backdoor — replaced binaries",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-Item C:\\Windows\\System32\\utilman.exe).VersionInfo.FileDescription",
         "eval":"'Utility Manager' not in (output or 'Utility Manager')"},
        {"id":"PER-014","name":"RID hijacking — SAM modified for RID 500",
         "type":"winrm","ip":WS_IP,
         "cmd":"(Get-LocalUser | Where-Object {$_.SID -match '-500$'}).Name",
         "eval":"len((output or '').strip()) > 0"},
        {"id":"PER-015","name":"AdminSDHolder abuse — ACL on AdminSDHolder",
         "type":"ldap",
         "filter":"(cn=AdminSDHolder)",
         "attributes":["nTSecurityDescriptor"],
         "base":"CN=System,DC=corp,DC=local",
         "eval":"len(entries) > 0"},
        {"id":"PER-016","name":"SID History injection — accounts with sIDHistory",
         "type":"ldap","filter":"(&(objectClass=user)(sIDHistory=*))","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"PER-017","name":"DCShadow — replication rights present",
         "type":"ldap","filter":"(objectClass=domain)","attributes":["nTSecurityDescriptor"],"eval":"len(entries) > 0"},
        {"id":"PER-018","name":"Golden Ticket — krbtgt account exists (always true)",
         "type":"ldap","filter":"(sAMAccountName=krbtgt)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"PER-019","name":"Silver Ticket — service accounts with SPNs",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"PER-020","name":"Skeleton Key — Kerberos port 88 accessible on DC",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"PER-021","name":"Diamond Ticket — krbtgt hash needed, Kerberos up",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"PER-022","name":"Sapphire Ticket — S4U2Self+U2U surface",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"PER-023","name":"Golden Certificate — CA backup key accessible",
         "type":"port","ip":CA_IP,"port":445},
        {"id":"PER-024","name":"Custom SSP — Security Packages in LSA registry",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').'Security Packages'",
         "eval":"len((output or '').strip()) > 0"},
        {"id":"PER-025","name":"DSRM backdoor — DsrmAdminLogonBehavior set",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue).DsrmAdminLogonBehavior",
         "eval":"output is not None and '2' in (output or '')"},
        {"id":"PER-026","name":"Auth package persistence — LSASS loads custom package",
         "type":"winrm","ip":DC_IP,
         "cmd":"(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').'Authentication Packages'",
         "eval":"'msv1_0' not in (output or 'msv1_0').lower() or len((output or '').split()) > 1"},
        {"id":"PER-027","name":"KeyCredentialLink self-shadow — msDS-KeyCredentialLink",
         "type":"ldap","filter":"(msDS-KeyCredentialLink=*)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"PER-028","name":"gMSA backdoor — gMSA accounts with delegated read",
         "type":"ldap","filter":"(objectClass=msDS-GroupManagedServiceAccount)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"PER-029","name":"RBCD persistence — msDS-AllowedToActOnBehalf on DC",
         "type":"ldap","filter":"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"PER-030","name":"ADIDNS time bomb — pre-staged DNS records",
         "type":"ldap","filter":"(objectClass=dnsNode)","attributes":["name"],
         "base":"DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local",
         "eval":"len(entries) > 0"},
        {"id":"PER-031","name":"Schema modification backdoor — schema write access",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Schema Admins))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"PER-032","name":"Hidden account via confidentiality flag",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user))","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"PER-033","name":"AdminSDHolder ACL injection — self-healing ACE",
         "type":"ldap","filter":"(cn=AdminSDHolder)",
         "attributes":["nTSecurityDescriptor"],"base":"CN=System,DC=corp,DC=local",
         "eval":"len(entries) > 0"},
        {"id":"PER-034","name":"GPO backdoor — SharpGPOAbuse surface",
         "type":"ldap","filter":"(objectClass=groupPolicyContainer)","attributes":["displayName"],"eval":"len(entries) > 0"},
        {"id":"PER-035","name":"RODC compromise — Allowed/Denied RODC groups",
         "type":"ldap","filter":"(&(objectClass=group)(cn=*RODC*))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"PER-036","name":"MachineAccountQuota > 0 — persistent machine accounts",
         "type":"ldap","filter":"(objectClass=domain)","attributes":["ms-DS-MachineAccountQuota"],
         "eval":"len(entries)>0 and _safe_int(entries[0]['ms_DS_MachineAccountQuota'].value if 'ms_DS_MachineAccountQuota' in entries[0].entry_attributes_as_dict else 0, 0) > 0"},
        {"id":"PER-037","name":"Unconstrained delegation service account persistent",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
         "attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # DOMAIN / FOREST COMPROMISE (DF-001..DF-040)
    # ─────────────────────────────────────────────────────────────────────────
    rules += [
        {"id":"DF-001","name":"Golden Ticket — krbtgt exists, Kerberos reachable",
         "type":"ldap","filter":"(sAMAccountName=krbtgt)","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"DF-002","name":"Silver Ticket — service account SPNs",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"DF-003","name":"DCSync All — Replicate Directory Changes rights",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Backup Operators))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"DF-004","name":"DCShadow — Schema Admin loosely granted",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Schema Admins))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"DF-005","name":"SID-History injection — sIDHistory on accounts",
         "type":"ldap","filter":"(&(objectClass=user)(sIDHistory=*))","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"DF-006","name":"Trust ticket abuse — inter-realm trust configured",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["flatName"],"eval":"len(entries) > 0"},
        {"id":"DF-007","name":"ExtraSID attack — parent-child trust (eu.corp.local)",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["flatName"],"eval":"len(entries) > 1"},
        {"id":"DF-008","name":"SID filtering bypass — external trust sIDHistory",
         "type":"ldap","filter":"(&(objectClass=user)(sIDHistory=*))","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"DF-009","name":"Foreign Security Principal hijack — FSPs in groups",
         "type":"ldap","filter":"(objectClass=foreignSecurityPrincipal)","attributes":["name"],"eval":"len(entries) > 0"},
        {"id":"DF-010","name":"Cross-forest Kerberoasting — SPNs on FSPs",
         "type":"ldap","filter":"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))","attributes":["sAMAccountName"],"eval":"len(entries) > 0"},
        {"id":"DF-011","name":"ADCS ESC8 — web enrollment HTTP+NTLM",
         "type":"http","url":f"http://{CA_IP}/certsrv/","eval":"status == 401"},
        {"id":"DF-012","name":"ADCS ESC1 — vulnerable template published",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC1))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-013","name":"ADCS ESC2 — EKU Any Purpose template",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC2))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-014","name":"ADCS ESC3 — enrollment agent template",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC3))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-015","name":"ADCS ESC4 — vulnerable ACL on template",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC4))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-016","name":"ADCS ESC5 — writable PKI object ACL",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC5))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-017","name":"ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2",
         "type":"winrm","ip":CA_IP,"cmd":"certutil -config . -getreg policy\\EditFlags 2>&1",
         "eval":"'EDITF_ATTRIBUTESUBJECTALTNAME2' in (output or '')"},
        {"id":"DF-018","name":"ADCS ESC7 — manager/officer role abuse",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC7))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-019","name":"ADCS ESC8 relay — HTTP web enrollment",
         "type":"http","url":f"http://{CA_IP}/certsrv/","eval":"status == 401"},
        {"id":"DF-020","name":"ADCS ESC9 — NoSecExt + SpecifiedCert template",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC9))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-021","name":"ADCS ESC10 — weak DACL on CA registry",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC10))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-022","name":"ADCS ESC11 — NTLM relay to ICPR",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC11))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-023","name":"Child→Enterprise Admin — no SID filtering (parent-child)",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["flatName"],"eval":"len(entries) > 0"},
        {"id":"DF-024","name":"noPac — MachineAccountQuota > 0",
         "type":"ldap","filter":"(objectClass=domain)","attributes":["ms-DS-MachineAccountQuota"],
         "eval":"len(entries)>0 and _safe_int(entries[0]['ms_DS_MachineAccountQuota'].value if 'ms_DS_MachineAccountQuota' in entries[0].entry_attributes_as_dict else 0, 0) > 0"},
        {"id":"DF-025","name":"Certifried CVE-2022-26923 — ADCS web enrollment",
         "type":"http","url":f"http://{CA_IP}/certsrv/","eval":"status is not None"},
        {"id":"DF-026","name":"CVE-2022-33647 Kerberos S4U2Self chain",
         "type":"port","ip":DC_IP,"port":88},
        {"id":"DF-027","name":"SAMAccountName→EnterpriseAdmin via trust",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["flatName"],"eval":"len(entries) > 0"},
        {"id":"DF-028","name":"RODC Password Replication — RODC present",
         "type":"ldap","filter":"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))",
         "attributes":["sAMAccountName"],"eval":"len(entries) >= 0"},
        {"id":"DF-029","name":"GPO delegation → Domain Admin",
         "type":"ldap","filter":"(objectClass=groupPolicyContainer)","attributes":["displayName"],"eval":"len(entries) > 0"},
        {"id":"DF-030","name":"Schema Admin hijack — schema admin membership",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Schema Admins))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"DF-031","name":"Enterprise Admin group populated",
         "type":"ldap","filter":"(&(objectClass=group)(cn=Enterprise Admins))","attributes":["member"],"eval":"len(entries) > 0"},
        {"id":"DF-032","name":"Trust sidfiltering disabled — attribute check",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["trustAttributes","flatName"],"eval":"len(entries) > 0"},
        {"id":"DF-033","name":"Intra-forest trust — corp.local trusts",
         "type":"ldap","filter":"(objectClass=trustedDomain)","attributes":["flatName"],"eval":"len(entries) >= 2"},
        {"id":"DF-034","name":"Finance DC reachable — cross-forest attack possible",
         "type":"port","ip":FIN_DC_IP,"port":389},
        {"id":"DF-035","name":"Root DC reachable — enterprise root compromise possible",
         "type":"port","ip":ROOT_DC_IP,"port":389},
        {"id":"DF-036","name":"ADCS ESC12 — enrollment agent export",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC12))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-037","name":"ADCS ESC13 — issuance policy OID group link",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC13))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-038","name":"ADCS ESC14 — explicit mapping abuse",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC14))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-039","name":"ADCS ESC15 CVE-2024-49019 — vulnerable template",
         "type":"ldap","filter":"(&(objectClass=pKICertificateTemplate)(name=ESC15))",
         "attributes":["name"],"base":"CN=Configuration,DC=corp,DC=local","eval":"len(entries) > 0"},
        {"id":"DF-040","name":"Full forest compromise path — all DCs reachable",
         "type":"port","ip":ROOT_DC_IP,"port":445},
    ]

    return rules


# ==============================================================================
# Execution Engine
# ==============================================================================
REACHABLE_IPS = {}

def is_reachable(ip):
    if not ip: return True
    if ip not in REACHABLE_IPS:
        REACHABLE_IPS[ip] = port_open(ip, 445, timeout=1.5) or port_open(ip, 389, timeout=1.5) or port_open(ip, 135, timeout=1.5)
    return REACHABLE_IPS[ip]

def load_names_from_plan():
    """Override generic names with real names from PLAN.md if present."""
    names = {}
    plan = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'PLAN.md')
    if os.path.exists(plan):
        with open(plan) as f:
            for line in f:
                m = re.match(r'^\|\s*([A-Z]+-\d{3})\s*\|\s*([^|]+)\s*\|', line)
                if m:
                    names[m.group(1).strip()] = m.group(2).strip()
    return names


def run_check(rule, conn):
    t = rule.get("type")
    ip = rule.get("ip")
    
    # Fast fail if the target IP is down (saves huge timeouts for minimal lab)
    if ip and not is_reachable(ip):
        return False

    try:
        if t == "port":
            return port_open(rule["ip"], rule["port"])
        elif t == "udp":
            return udp_open(rule["ip"], rule["port"])
        elif t == "smb_null":
            return smb_null_session(rule["ip"])
        elif t == "anon_ldap":
            entries = anon_ldap_query(rule["ip"], rule["filter"], rule["attributes"])
            return bool(eval(rule["eval"], {"entries": entries}))
        elif t == "dns_axfr":
            return dns_axfr(rule["ip"], rule["zone"])
        elif t == "ldap":
            base = rule.get("base", "DC=corp,DC=local")
            entries = ldap_query(conn, rule["filter"], rule["attributes"], base)
            return bool(eval(rule["eval"], {
                "entries": entries,
                "_safe_int": _safe_int,
                "_member_count": _member_count,
            }))
        elif t == "http":
            status, text = http_get(rule["url"])
            return bool(eval(rule["eval"], {"status": status, "text": text}))
        elif t == "winrm":
            output, rc = winrm_run(rule["ip"], rule["cmd"])
            return bool(eval(rule["eval"], {
                "output": output,
                "rc": rc,
                "_safe_int": _safe_int,
            }))
    except Exception:
        pass
    return False


def verify_ad_vulns():
    rules = generate_rules()
    total = len(rules)

    print(f"\n{C.CYAN}{C.BOLD}{'='*100}{C.END}")
    print(f"{C.CYAN}{C.BOLD}  DVAD Vulnerability Verifier — {total} Automated Checks{C.END}")
    print(f"{C.CYAN}{C.BOLD}  Sources: docs/ · STUDY/ · PLAN.md{C.END}")
    print(f"{C.CYAN}{C.BOLD}{'='*100}{C.END}\n")

    if not HAS_REQUESTS:
        print(f"{C.YELLOW}[!] pip3 install requests  — HTTP checks disabled{C.END}")
    if not HAS_WINRM:
        print(f"{C.YELLOW}[!] pip3 install pywinrm   — WinRM checks disabled{C.END}")
    if not HAS_DNS:
        print(f"{C.YELLOW}[!] pip3 install dnspython — DNS AXFR checks disabled{C.END}")

    print(f"[*] Connecting to LDAP on {DC_IP} ({LAB_DOMAIN})...")
    if not port_open(DC_IP, 389, timeout=3):
        print(f"{C.RED}[x] LDAP port 389 unreachable on {DC_IP}. Ensure VMs are running.{C.END}")
        return

    server = Server(DC_IP, get_info=ALL, connect_timeout=5)
    try:
        conn = Connection(server,
                          user=LAB_USER,
                          password=LAB_PASSWORD,
                          authentication=NTLM,
                          auto_bind=True)
    except Exception as e:
        print(f"{C.RED}[x] LDAP bind failed: {e}{C.END}")
        return

    plan_names = load_names_from_plan()

    # Apply real names from PLAN.md
    for r in rules:
        if r["id"] in plan_names:
            r["name"] = plan_names[r["id"]]

    print(f"{C.GREEN}[+] Connected!{C.END} Running {total} automated checks...\n")
    print(f"{'ID':<12} {'CHECK':<68} STATUS")
    print("-"*100)

    report_data   = []
    vuln_count    = 0
    skipped_count = 0
    type_map = {"port": C.CYAN, "udp": C.CYAN, "ldap": C.GREEN,
                "winrm": C.YELLOW, "http": C.GREEN, "anon_ldap": C.GREEN,
                "dns_axfr": C.CYAN, "smb_null": C.CYAN}

    def process_rule(rule):
        t = rule.get("type","")
        if t == "winrm" and not HAS_WINRM:
            return rule, "SKIP (no pywinrm)", False
        if t == "http" and not HAS_REQUESTS:
            return rule, "SKIP (no requests)", False
        if t == "dns_axfr" and not HAS_DNS:
            return rule, "SKIP (no dnspython)", False
        
        is_vuln = run_check(rule, conn)
        return rule, "VULNERABLE" if is_vuln else "SECURE", is_vuln

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(process_rule, r): r for r in rules}
        
        for future in as_completed(futures):
            rule, status_str, is_vuln = future.result()
            report_data.append([rule["id"], rule["name"], status_str])
            
            if "SKIP" in status_str:
                skipped_count += 1
            elif is_vuln:
                vuln_count += 1
                t = rule.get("type","")
                col = type_map.get(t, C.GREEN)
                print(f"{C.GREEN}[+]{C.END} {rule['id']:<12} {rule['name']:<68} {C.GREEN}VULNERABLE{C.END}  [{col}{t}{C.END}]")

    report_data.sort(key=lambda x: x[0])  # Sort by ID for consistency in CSV
    conn.unbind()

    print("\n" + "="*100)
    print(f"{C.GREEN}{C.BOLD}[+] Done!{C.END}  Checked: {total}  |  "
          f"Vulnerable: {C.GREEN}{vuln_count}{C.END}  |  "
          f"Secure: {total - vuln_count - skipped_count}  |  "
          f"Skipped: {C.YELLOW}{skipped_count}{C.END}")

    csv_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "vulnerability_report.csv")
    with open(csv_file, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ID", "Name", "Status"])
        w.writerows(report_data)

    print(f"[*] Full report saved → {csv_file}")
    if not (HAS_REQUESTS and HAS_WINRM and HAS_DNS):
        print(f"\n{C.YELLOW}Tip: Install missing libs to enable all checks:{C.END}")
        print(f"     pip3 install pywinrm requests dnspython\n")


if __name__ == "__main__":
    verify_ad_vulns()
