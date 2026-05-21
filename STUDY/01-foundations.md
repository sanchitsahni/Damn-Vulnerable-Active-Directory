# 01 — Foundations: Networking, Protocols, and the Wire

You cannot exploit what you cannot see. Every attack in this book moves bits across a network, and most defensive controls live somewhere on the path those bits travel. Before we talk about Active Directory, Kerberos, or certificate templates, we need a working mental model of how a packet leaves your laptop, finds a domain controller, exchanges authentication, and comes back.

This chapter is the longest in the book that has nothing to do with Active Directory. Read it anyway. Every later chapter assumes you can answer questions like:

- Why does `nmap -sS` produce different results than `nmap -sT` for a firewalled host?
- What's the difference between a broadcast and a multicast at the Ethernet layer, and why does it matter for LLMNR poisoning?
- Why does `dig @10.10.0.10 corp.local AXFR` work or fail, and what would you see on the wire either way?
- What's the byte structure of an SMB negotiate request, and which fields does an attacker control?

If you can already answer those, skim. If you can't, this is where to slow down.

---

## 1.1 (Concept) Why we start with networking

Every Active Directory attack we will study reduces to one of three primitives:

1. **Read something off the wire** that should have been confidential (NetNTLMv2 hashes, Kerberos AS-REP encrypted blobs, anonymous LDAP attributes).
2. **Inject something onto the wire** that the target trusts (poisoned LLMNR responses, mitm6 DHCPv6 advertisements, forged TGS tickets).
3. **Relay something on the wire** to a different endpoint than it was intended for (NTLM relay, Kerberos delegation abuse).

To do any of these intentionally, you have to know which protocol carries which information, what the legitimate sequence looks like, and which fields the recipient validates versus accepts blindly. That is what this chapter teaches.

The DVAD lab is built on a flat IPv4 segment with three forests, each on its own subnet:

```
+--------------------------------------------------------------+
|  10.10.0.0/21   dvad-ctf bridge      corp.local              |
|                  10.10.0.10  dc01.corp.local                 |
|                  10.10.0.11  dc01.eu.corp.local              |
|                  10.10.0.12  ca01.corp.local  (ADCS)         |
|                  10.10.0.13  file01.corp.local               |
|                  10.10.0.14  sql01.corp.local                |
|                  10.10.0.100 ws01.corp.local                 |
|                                                              |
|  10.20.0.0/24   dvad-finance bridge   finance.local          |
|                  10.20.0.10  dc01.finance.local              |
|                                                              |
|  10.30.0.0/24   dvad-root bridge      root.corp              |
|                  10.30.0.10  dc01.root.corp                  |
+--------------------------------------------------------------+
```

Bridges are Linux bridges (`brctl` / `ip link`) created by `qemu/network/setup-network.sh`. Hosts get static DHCP leases from a project-local dnsmasq running under `/tmp/dvad-dnsmasq/`. Your Kali (or Parrot/BlackArch/Ubuntu-with-tools) attacker box typically sits on `10.10.0.1` — the host machine — and reaches all three subnets through routing the host kernel performs between the bridges.

Open three terminals when you work through this chapter. One for commands on the attacker host, one for `tcpdump` on the bridge interface, one for notes.

---

## 1.2 (Concept) The four-layer mental model

Textbooks teach OSI's seven layers. In practice, when you are writing attack tooling against a Windows network, you use four:

```
+----------------------------------------------+
|  Layer 4: Application                        |
|   SMB, LDAP, Kerberos, HTTP, DNS, MS-RPC     |
+----------------------------------------------+
|  Layer 3: Transport                          |
|   TCP, UDP                                   |
+----------------------------------------------+
|  Layer 2: Internet                           |
|   IPv4, IPv6, ICMP                           |
+----------------------------------------------+
|  Layer 1: Link                               |
|   Ethernet, ARP                              |
+----------------------------------------------+
```

(We collapse OSI's physical and data-link into one layer because Wireshark does too. We collapse session, presentation, and application into one because nobody on a Windows network draws the line between TLS-as-session and SMB-as-application.)

A user typing `\\dc01\sysvol` in Explorer causes, in order:

1. Application code converts the UNC path into an SMB connection request.
2. Windows resolves `dc01` to an IP via DNS, then LLMNR, then NBT-NS (in that order, with timeouts).
3. The TCP layer opens a connection to 445/tcp on the resolved IP.
4. The IP layer routes the SYN packet to the correct gateway (or directly if same subnet).
5. The link layer ARPs for the gateway's MAC, then emits an Ethernet frame.

Every layer above can fail because of every layer below. An LLMNR-poisoning attack succeeds because (2) fell through to LLMNR, and the attacker emitted a multicast Ethernet frame at (5) that beat the real responder. A Kerberoasting request fails when your `KRB5CCNAME` points to a ticket the application can't read — pure layer-4 confusion.

When debugging, ask yourself which layer is suspect, and use the tool that operates at that layer:

```
ip link / ip addr     Layer 1
arp / ip neigh        Layer 1↔2 boundary
ping / tcptraceroute  Layer 2
ss / netstat / nmap   Layer 3
tcpdump / wireshark   Any layer
```

---

## 1.3 The link layer in detail

Ethernet is, for our purposes, three things:

- **Source MAC** (6 bytes) — the sender's interface address.
- **Destination MAC** (6 bytes) — broadcast (`ff:ff:ff:ff:ff:ff`), a specific MAC, or a multicast MAC.
- **EtherType** (2 bytes) — 0x0800 for IPv4, 0x86DD for IPv6, 0x0806 for ARP.

For attacks, the important behaviours are:

- **Switches forward unicast frames only to the destination port.** Sniffing a switched network from the wrong port shows you only broadcast and multicast traffic by default. (This is why you almost always need to be the same broadcast domain as the target for L2 attacks.)
- **Broadcasts are heard by every host on the segment.** ARP requests, DHCP discovers, NBT-NS queries all use broadcast.
- **Multicasts are heard by hosts that subscribed.** LLMNR sends to `224.0.0.252` (IPv4) which maps to MAC `01:00:5e:00:00:fc`; mDNS sends to `224.0.0.251` mapped to `01:00:5e:00:00:fb`; IPv6 ND/DHCPv6 use other multicast groups.

DVAD's bridges are exactly the kind of layer-2 segment that LLMNR + mitm6 attacks rely on.

### Inspecting your own MAC and ARP table

```bash
ip link show dvad-ctf                # the bridge
ip neigh show dev dvad-ctf           # MAC↔IP cache for that interface
ip route show table all              # what gets sent where
```

The `ip neigh` table is populated by passive ARP traffic. Entries can be `REACHABLE`, `STALE`, `DELAY`, `FAILED`. A stale entry will trigger a fresh ARP request before being used.

### ARP step by step

When 10.10.0.100 (ws01) wants to send a packet to 10.10.0.10 (dc01) and the kernel doesn't have a MAC for 10.10.0.10:

1. ws01 broadcasts: "Who has 10.10.0.10? Tell 10.10.0.100." Ethernet destination is `ff:ff:ff:ff:ff:ff`; ARP opcode is `request` (1).
2. Every host on the segment receives the frame. Only the one with IP 10.10.0.10 responds.
3. dc01 unicasts: "10.10.0.10 is at 52:54:00:aa:bb:cc." ARP opcode is `reply` (2). The Ethernet destination here is ws01's MAC.
4. ws01 caches the mapping and proceeds.

The vulnerability built into ARP: there is no authentication. **Anyone on the segment can answer for any IP.** That is the foundation of ARP spoofing, which we won't lean on heavily in DVAD because LLMNR and DHCPv6 are quieter and more reliable, but you should know it exists.

### Watching ARP traffic

```bash
sudo tcpdump -i dvad-ctf -nn arp
# typical output:
# 14:01:00.123 ARP, Request who-has 10.10.0.10 tell 10.10.0.100, length 28
# 14:01:00.124 ARP, Reply 10.10.0.10 is-at 52:54:00:aa:bb:cc, length 28
```

If you see ARP requests for IPs that don't exist (`who-has 10.10.0.99`), some host is trying to reach a phantom — possibly a typo. That's interesting at the recon stage and the attack stage; we'll come back to it.

---

## 1.4 The internet layer: IPv4 and IPv6

Active Directory uses both, and attackers exploit both. We'll cover IPv4 in this section and devote §1.10 to IPv6 because the mitm6 attack class deserves its own treatment.

### IPv4 header anatomy

A canonical IPv4 header is 20 bytes (with optional options up to 60 bytes total). The fields that matter to attackers:

- **TTL (Time To Live).** Decremented at each hop. The OS picks a default — Windows uses 128, Linux uses 64, Cisco IOS uses 255. You can OS-fingerprint by inspecting received TTLs: if you see TTL=125 from `10.10.0.10`, the host is 3 hops away with default 128, almost certainly Windows. Tools like `p0f` automate this.
- **Protocol.** 1=ICMP, 6=TCP, 17=UDP, 50=ESP, 47=GRE, 89=OSPF. The protocol number tells the receiver which higher-layer parser to invoke.
- **Total Length.** Combined with IHL gives the payload boundary; bugs in length handling have produced CVEs for decades (think Ping of Death, but modern stacks have largely closed those).
- **Flags + Fragment Offset.** Used to fragment large packets. Fragmentation can be used to evade poorly-configured IDS — split a malicious payload across two fragments so signature matching on the first fails. Modern Suricata reassembles before inspecting.
- **Source/Destination Address.** 32 bits each.

For DVAD work you rarely care about anything but source/destination, TTL (for OS fingerprinting), and total length (when crafting packets manually with Scapy).

### Addressing and CIDR

`10.10.0.0/21` is shorthand for `10.10.0.0` with a /21 prefix — 21 bits of network, 11 bits of host, so `2^11 - 2 = 2046` usable hosts. The lab uses /21 for the corp subnet because we want room for hostile additions (rogue computer accounts via MachineAccountQuota will get a DHCP lease, for example) and /24 for the smaller forests.

Quick reference of common CIDR sizes:

| Prefix | Hosts (usable) | Mask |
|---|---|---|
| /30 | 2 | 255.255.255.252 |
| /29 | 6 | 255.255.255.248 |
| /28 | 14 | 255.255.255.240 |
| /27 | 30 | 255.255.255.224 |
| /26 | 62 | 255.255.255.192 |
| /25 | 126 | 255.255.255.128 |
| /24 | 254 | 255.255.255.0 |
| /23 | 510 | 255.255.254.0 |
| /22 | 1022 | 255.255.252.0 |
| /21 | 2046 | 255.255.248.0 |
| /20 | 4094 | 255.255.240.0 |
| /16 | 65534 | 255.255.0.0 |

Knowing /21 = 2046 hosts in your head saves you ten seconds every time you set up a scan.

### Special address ranges

| Range | Purpose |
|---|---|
| 0.0.0.0/8 | "This network" — source-only |
| 10.0.0.0/8 | RFC1918 private |
| 100.64.0.0/10 | Carrier-grade NAT |
| 127.0.0.0/8 | Loopback |
| 169.254.0.0/16 | Link-local (APIPA) |
| 172.16.0.0/12 | RFC1918 private |
| 192.0.0.0/24 | Protocol assignments |
| 192.0.2.0/24 | Documentation |
| 192.168.0.0/16 | RFC1918 private |
| 198.18.0.0/15 | Benchmark testing |
| 224.0.0.0/4 | Multicast |
| 240.0.0.0/4 | Reserved |
| 255.255.255.255/32 | Limited broadcast |

`169.254.x.x` is what you see when DHCP fails — APIPA. If a victim host on DVAD shows up with a 169.254 address, your dnsmasq probably isn't running.

### Routing

Each host has a routing table. View yours:

```bash
ip route
# example:
# default via 10.10.0.1 dev wlan0
# 10.10.0.0/21 dev dvad-ctf proto kernel scope link src 10.10.0.1
# 10.20.0.0/24 dev dvad-finance proto kernel scope link src 10.20.0.1
# 10.30.0.0/24 dev dvad-root proto kernel scope link src 10.30.0.1
```

`default via 10.10.0.1` means anything not matching a more specific route goes to the gateway at `10.10.0.1`. The kernel matches longest prefix first, so a `/24` route beats a `/16` route to the same destination.

When you add a new bridge to DVAD's host, the kernel auto-installs an on-link route for that bridge's subnet. Cross-bridge traffic between forests uses the host's routing table — that's why your attacker box can reach `10.30.0.10` even though it sits on the `dvad-ctf` bridge.

---

## 1.5 The transport layer: TCP and UDP

### UDP — fire and forget

UDP is an 8-byte header on top of the IP payload — source port, destination port, length, checksum. No connection, no retransmission, no ordering guarantees. The application is responsible for whatever reliability semantics it needs. DNS, DHCP, LLMNR, NBT-NS, mDNS, SNMP, NTP, Syslog all run on UDP.

When you spoof a UDP response (LLMNR poisoning is the canonical example), you don't have to coordinate any state — you just emit a packet whose source IP and port match what the victim expects, and whose destination is the victim. If the victim is listening on the right port and you beat the real responder, you win.

### TCP — stateful and reliable

TCP is 20 bytes minimum, with optional options up to 60 total. TCP flags (one bit each): `URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN` are the original six; later additions include `ECE`, `CWR`, and `NS` (ECN-Nonce). For attacks, the meaningful ones are:

- **SYN** — request a new connection.
- **ACK** — acknowledge receipt up to the ack-number.
- **FIN** — graceful close.
- **RST** — abrupt close. Sent when traffic arrives for no socket.

### Three-way handshake

```
Client                                   Server
  |  SYN, seq=X                            |
  |--------------------------------------->|
  |                              SYN+ACK, seq=Y, ack=X+1
  |<---------------------------------------|
  |  ACK, seq=X+1, ack=Y+1                |
  |--------------------------------------->|
  Connection established
```

`nmap -sS` (SYN scan) exploits this by sending only the first SYN and watching for a SYN+ACK (port open), RST+ACK (port closed), or no response (filtered). It never completes the handshake, so most application-layer servers see nothing — only IDS that monitor incomplete handshakes.

`nmap -sT` (connect scan) actually completes the handshake using the OS socket API. The application sees a connection. Logs are written. SYN scans are quieter but require root because they craft raw packets.

### TCP states an attacker cares about

```
LISTEN  -- server waiting for SYN
SYN_SENT -- client sent SYN, waiting for SYN+ACK
SYN_RECV -- server got SYN, sent SYN+ACK, waiting for ACK
ESTABLISHED -- both sides handshaked
FIN_WAIT_1 / FIN_WAIT_2 / TIME_WAIT -- closing
CLOSE_WAIT -- got FIN, waiting for application to close
LAST_ACK -- sent final FIN, waiting for ack
CLOSED -- no connection
```

Use `ss -tan state ESTABLISHED` to list every established TCP connection on your attacker box. After running a long-lived attack like `ntlmrelayx` you want to see what sockets it's holding.

### Why TCP matters for AD

Most AD protocols ride TCP. Kerberos is famously dual-stack — UDP/88 if the request fits in one MTU, TCP/88 otherwise. With PAC included, TGTs almost always exceed UDP, so in practice you'll see TCP/88. SMB is TCP/445. LDAP is TCP/389 (LDAPS on 636). LDAP-GC is TCP/3268 / 3269. WinRM is TCP/5985 / 5986. MS-RPC over named pipes runs through SMB on 445; MS-RPC over TCP uses ephemeral ports negotiated through the endpoint mapper on 135.

When a firewall blocks "AD ports," it usually blocks SMB, LDAP, Kerberos, RPC, and the GC ports. Sometimes you find one open and others closed, which constrains your toolset. NetExec, for instance, has separate `smb`, `ldap`, `winrm`, and `mssql` subcommands that each tolerate different blockages.

---

## 1.6 (Mechanics) Ports you must memorize

AD makes very heavy use of a small number of ports. Memorize this table cold.

| Port | Protocol | Purpose | Notes |
|---|---|---|---|
| 53 | tcp/udp | DNS | UDP for queries < 512 bytes; TCP for large or AXFR |
| 88 | tcp/udp | Kerberos | UDP fails over to TCP for big tickets |
| 123 | udp | NTP | Time skew > 5 min breaks Kerberos |
| 135 | tcp | MS-RPC endpoint mapper | Negotiates dynamic high port |
| 137 | udp | NetBIOS Name Service (NBT-NS) | Legacy, poisonable |
| 138 | udp | NetBIOS Datagram | Rarely interesting |
| 139 | tcp | NetBIOS Session Service / SMB1-over-NBT | Legacy SMB transport |
| 389 | tcp/udp | LDAP | Plain or with StartTLS |
| 445 | tcp | SMB direct | SMB2/3 over TCP; the modern path |
| 464 | tcp/udp | Kerberos password change / set | Used by `kpasswd` and AD |
| 593 | tcp | MS-RPC over HTTP | Tunnelled RPC |
| 636 | tcp | LDAPS | LDAP over TLS |
| 1433 | tcp | MSSQL | DVAD's sql01 |
| 1434 | udp | MSSQL Browser | Reveals instance names |
| 2179 | tcp | Hyper-V VMConnect | Sometimes exposed |
| 3268 | tcp | Global Catalog LDAP | Forest-wide queries |
| 3269 | tcp | Global Catalog LDAPS | TLS version |
| 3389 | tcp | RDP | Lateral movement |
| 5355 | udp | LLMNR | The poisoning target |
| 5357 | tcp | WSDAPI | Web Services Discovery |
| 5985 | tcp | WinRM HTTP | Remote PowerShell, default |
| 5986 | tcp | WinRM HTTPS | TLS-wrapped WinRM |
| 9389 | tcp | AD Web Services | PowerShell `ActiveDirectory` module |
| 47001 | tcp | WinRM listener service | Sometimes used by HTTP.sys |
| 49152-65535 | tcp | Dynamic RPC | Negotiated through 135 |

For a DC, expect open: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, and a handful of dynamic RPC ports above 49152. For an ADCS host like ca01, expect additionally 80 (certsrv HTTP enrollment), and possibly 443.

When `nmap` shows you these in expected configuration, you have confirmed "this is a domain controller" without ever sending an LDAP query.

---

## 1.7 ICMP, ping, and traceroute

ICMP is its own protocol number (1), not TCP or UDP. It carries control messages: echo request/reply, destination unreachable, time exceeded, redirect, source quench (deprecated), parameter problem, timestamp, address mask.

For attacks:

- **Echo request/reply (ping)** can confirm host liveness when ICMP isn't blocked. Many corp firewalls block ping; nmap's `-Pn` skips host discovery and assumes the host is up.
- **Destination unreachable (type 3)** comes back when a port is closed (`code 3`, port unreachable) for UDP scans, or when a router has no route (`code 0`, network unreachable). `nmap -sU` infers UDP port state from the absence or presence of these.
- **Time exceeded (type 11)** is what makes `traceroute` work. Each probe is sent with successively larger TTL; routers along the path decrement TTL to 0 and emit a type-11 ICMP, revealing the path.
- **Redirect (type 5)** asks the host to use a better gateway. Historically used in MITM attacks but most OSes now reject redirects by default.

```bash
ping -c 4 10.10.0.10                    # echo request
sudo traceroute -I 10.10.0.10           # ICMP-based path
sudo nmap -PE -PP -PM 10.10.0.0/24      # echo + timestamp + address-mask hosts discovery
```

If ICMP is filtered, `nmap -sn -PS 80,443,445 10.10.0.0/24` uses TCP SYN to common ports as a liveness check.

---

## 1.8 DNS in depth

DNS deserves its own section because *every AD attack involves DNS somewhere*. The Kerberos client locates the KDC via SRV records; SMB resolves hostnames via DNS first; certificate enrollment validates the CA's name; relay attacks coerce SMB authentication using DNS names; and so on.

### Record types you must know

| Type | Purpose | Example |
|---|---|---|
| A | IPv4 address | `dc01.corp.local. A 10.10.0.10` |
| AAAA | IPv6 address | `dc01.corp.local. AAAA fe80::1` |
| PTR | Reverse lookup | `10.0.10.10.in-addr.arpa. PTR dc01.corp.local.` |
| CNAME | Alias | `kdc.corp.local. CNAME dc01.corp.local.` |
| NS | Nameserver | `corp.local. NS dc01.corp.local.` |
| SOA | Start of authority | metadata about the zone |
| MX | Mail exchanger | rare in lab |
| TXT | Free-form text | SPF, DKIM, ownership proofs |
| SRV | Service location | `_ldap._tcp.dc._msdcs.corp.local.` |
| TLSA | DANE binding | rare |
| CAA | Cert authority authorisation | rare |

The one with the most leverage in AD is **SRV**. Windows uses SRV records to locate domain controllers, global catalogs, Kerberos KDCs, password change servers, and more.

### SRV record format

```
_service._proto.name.   TTL   IN   SRV   priority weight port target.
```

Common AD SRV records:

```
_ldap._tcp.dc._msdcs.corp.local.    -> dc01.corp.local
_kerberos._tcp.dc._msdcs.corp.local. -> dc01.corp.local
_gc._tcp.corp.local.                 -> dc01.corp.local
_kpasswd._udp.corp.local.            -> dc01.corp.local
_ldap._tcp.Default-First-Site-Name._sites.corp.local.  -> dc01.corp.local
```

A Windows client booting on a new network looks up `_ldap._tcp.dc._msdcs.<domain>` to find a DC. If you control DNS for that domain, you control which DC the client uses — which is how the rogue-DC variants of DCShadow work.

### DNS query path

```
client          stub resolver       recursive resolver       authoritative
  |--------query "dc01.corp.local"-->|                              |
  |                                  |-- query upstream ----------> |
  |                                  |  (or recurse from root)      |
  |                                  |<-- answer ---- 10.10.0.10 -- |
  |<-- answer 10.10.0.10 ------------|                              |
```

Inside DVAD, dnsmasq plays the recursive + authoritative role for the lab zones. Hosts are configured to point at dnsmasq via DHCP option 6. When a Windows host wants to resolve a name not in dnsmasq's zone, dnsmasq forwards to the host machine's upstream resolver.

### Dig usage

```bash
dig @10.10.0.10 corp.local SOA            # who owns the zone
dig @10.10.0.10 dc01.corp.local A          # forward lookup
dig @10.10.0.10 -x 10.10.0.10              # reverse
dig @10.10.0.10 corp.local AXFR            # zone transfer (often allowed in lab)
dig @10.10.0.10 _ldap._tcp.dc._msdcs.corp.local SRV  # find DC
dig @10.10.0.10 corp.local ANY +noall +answer
dig @10.10.0.10 NS corp.local              # list nameservers
```

`AXFR` (full zone transfer) is the recon gold mine when allowed. It dumps every record in the zone — every host, every service, every alias. Modern DNS servers restrict AXFR to designated secondary servers; DVAD intentionally leaves it open.

`dig +trace +nodnssec corp.local` walks the resolution path from the root and shows each delegation step. Useful when something resolves but you don't know who's authoritative.

### Negative caching

When dig returns an `NXDOMAIN`, the resolver caches it for the SOA's `minimum-ttl` (or `negttl`, depending on the resolver). This matters for poisoning attacks: if a host caches "no answer" for the name you want to spoof, your poisoning attempt fails until cache expiry.

LLMNR has the same issue — once Windows has cached a successful resolution, future lookups don't fall back, so your Responder catches nothing. The window opens again when the cache entry expires (typically a few seconds for LLMNR).

### Authoritative vs recursive

Authoritative servers hold the actual records for a zone. Recursive resolvers hold no records but follow delegations. A typical Windows DC runs both: authoritative for `corp.local` and recursive for everything else.

### DNSSEC

You will encounter DNSSEC in defended enterprises, never in DVAD. The short version: zones are signed by RRSIG records, validated up to root using DS records. An attacker who can MITM DNS without DNSSEC can spoof; with DNSSEC and a validating resolver, the spoof fails validation.

### REC-001..REC-015 — DNS-based recon

PLAN.md catalogues DNS-driven recon flags REC-001 through REC-015. Walk-through for each:

#### REC-001 — host discovery via PTR sweep

```bash
for i in $(seq 1 254); do
  dig @10.10.0.10 -x 10.10.0.$i +short
done | grep -v '^$'
```

This populates a list of every host with a forward+reverse record. Faster than ARP sweep and works across subnets you can route to.

#### REC-002 — zone transfer

```bash
dig @10.10.0.10 corp.local AXFR > corp.zone
wc -l corp.zone
grep -E '\bA\s' corp.zone | awk '{print $1, $5}'
```

Captures the whole forward zone. Look for hosts not on your standard list — staging servers, scanners, jump boxes. Repeat for `_msdcs.corp.local`, `eu.corp.local`, `finance.local`, `root.corp`.

#### REC-003 — SRV enumeration

```bash
for s in _ldap _kerberos _kpasswd _gc _kerberos-master _ldap._tcp.dc._msdcs _ldap._tcp.gc._msdcs; do
  dig @10.10.0.10 ${s}.corp.local SRV +short
done
```

#### REC-004 — name servers

```bash
dig @10.10.0.10 corp.local NS +short
dig @10.10.0.10 finance.local NS +short
dig @10.10.0.10 root.corp NS +short
```

If you can resolve all three from the corp DC, the forest topology is exposed even without authentication.

#### REC-005 — reverse zone delegation

```bash
dig @10.10.0.10 0.10.10.in-addr.arpa NS
```

Tells you which server is authoritative for the reverse zone — usually the same DC, sometimes delegated.

#### REC-006 — DNS aging and tombstones

If aging is enabled, stale records age out. You can sometimes find records for decommissioned servers if aging is disabled, hinting at infrastructure history.

#### REC-007 — wildcard records

```bash
dig @10.10.0.10 random$(date +%s).corp.local
```

If anything other than NXDOMAIN comes back, a wildcard A or CNAME is in play. Lab usually doesn't have one, but real environments often do for legacy reasons.

#### REC-008 — DNSSEC posture

```bash
dig @10.10.0.10 corp.local DNSKEY +short
dig @10.10.0.10 corp.local DS +short
```

#### REC-009 — DNS over TCP

If UDP/53 is blocked or filtered, try TCP/53:

```bash
dig +tcp @10.10.0.10 corp.local SOA
```

#### REC-010 — DNS dynamic update

If dynamic updates are allowed without authentication, you can register your own records:

```bash
nsupdate
> server 10.10.0.10
> update add evil.corp.local 60 A 10.10.0.99
> send
```

This is the kind of thing DVAD permits at points to enable certain coercion paths.

#### REC-011 — TXT records

```bash
dig @10.10.0.10 corp.local TXT +short
dig @10.10.0.10 _ldap._tcp.corp.local TXT +short
```

Sometimes contains version strings, ownership tags, or hints.

#### REC-012 — CNAME chains

Follow them with `dig +nocname` to see the underlying A records, or `dig +trace` to see each step.

#### REC-013 — Trusts hinted via DNS

The presence of authoritative records for `finance.local` on a corp DC suggests a conditional forwarder or zone transfer arrangement — often a sign that a trust exists.

#### REC-014 — KDC discovery

```bash
dig @10.10.0.10 _kerberos._tcp.dc._msdcs.corp.local SRV +short
dig @10.10.0.10 _kerberos._udp.corp.local SRV +short
```

#### REC-015 — Sites and subnets

```bash
dig @10.10.0.10 _ldap._tcp.Default-First-Site-Name._sites.corp.local SRV +short
dig @10.10.0.10 _ldap._tcp.eu-site._sites.eu.corp.local SRV +short  # if eu-site exists
```

Site naming sometimes leaks geography.

---

## 1.9 LLMNR, NBT-NS, mDNS in detail

These are the three protocols Windows falls back to when DNS fails. They are the attacker's friend.

### LLMNR (Link-Local Multicast Name Resolution, RFC 4795)

When a Windows host can't resolve a name via DNS, it emits an LLMNR query to multicast `224.0.0.252:5355` (IPv4) or `ff02::1:3:5355` (IPv6). Any host on the segment can answer. The first answer wins.

LLMNR query packet (UDP/5355 multicast):

```
DNS header
  TXID  ResponseFlag=0  QDCOUNT=1  ANCOUNT=0  NSCOUNT=0  ARCOUNT=0
Question
  QNAME=<the typoed name>   QTYPE=A   QCLASS=IN
```

Responder's job: see the query, craft a response with `ResponseFlag=1`, same TXID, an answer pointing to the attacker's IP, and unicast it back to the source. Done.

```bash
sudo responder -I dvad-ctf -wrf -v
```

Flags:
- `-w` enable WPAD server
- `-r` enable WINS (NetBIOS suffix 0x1c/0x1b/etc.)
- `-f` fingerprint host versions
- `-v` verbose

Once the victim authenticates to the attacker's SMB or HTTP listener, the NetNTLMv2 challenge–response goes into `/usr/share/responder/logs/`.

### NBT-NS (NetBIOS Name Service, RFC 1002)

Older, broadcast-based. UDP/137. Queries by 16-byte NetBIOS name (15 chars + 1 suffix byte indicating service type). Suffix `0x00` is workstation, `0x20` is server, `0x1c` is domain controller group, `0x1b` is PDC.

Windows falls back to NBT-NS only if `EnableLMHOSTS` is non-zero and the SMB1 / NetBIOS-over-TCPIP transport is bound to the interface. Disabling NetBIOS over TCP/IP on the interface kills NBT-NS at the source.

### mDNS (Multicast DNS, RFC 6762)

Apple-flavoured. Uses `224.0.0.251:5353` for IPv4. Windows since 10 1703 has an mDNS responder service. Same poison-it-with-Responder principle.

### Why these poison so easily

There's no authentication. The protocol is "ask the multicast group; trust the first response." On a segment with no rogue responder, you get your real DNS-derived answer through some other path; on a segment with a rogue responder, you get whatever the rogue says.

### Defending

The remediations are:

1. Disable LLMNR via GPO: `Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution = Enabled`.
2. Disable NetBIOS over TCP/IP per interface: `Network Connections → adapter → IPv4 Properties → Advanced → WINS → NetBIOS setting = Disable`.
3. Disable mDNS: `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0`.

Modern Windows (11 22H2+, Server 2025) disables LLMNR by default; older releases (and DVAD's hosts) leave it on.

---

## 1.10 IPv6 and mitm6

IPv6 deserves its own treatment because most Windows networks have it enabled "for IPv4 fallback" without configuring it, and `mitm6` exploits exactly that gap.

### IPv6 address fundamentals

IPv6 addresses are 128 bits, written as eight 16-bit groups separated by colons:

```
fe80:0000:0000:0000:5054:00ff:feaa:bbcc
```

Leading zeros may be omitted in each group, and a single contiguous run of all-zero groups may be replaced by `::`:

```
fe80::5054:ff:feaa:bbcc
```

Common prefixes:

| Prefix | Type | Purpose |
|---|---|---|
| `::1/128` | Loopback | Like 127.0.0.1 |
| `fe80::/10` | Link-local | Auto-assigned, only valid on segment |
| `fc00::/7` | Unique local | RFC 4193 private |
| `2000::/3` | Global unicast | Public Internet |
| `ff00::/8` | Multicast | |
| `ff02::1` | All-nodes link-local | Like broadcast |
| `ff02::2` | All-routers link-local | |
| `ff02::1:2` | DHCPv6 servers | mitm6's target |

### SLAAC and DHCPv6

IPv6 has two address auto-configuration mechanisms:

- **SLAAC (Stateless Address Autoconfiguration)** — host learns a /64 prefix from a Router Advertisement, generates an interface ID (EUI-64 or randomized), combines them, performs DAD, uses the address. No DHCP server needed.
- **DHCPv6** — like DHCPv4. Server hands out addresses, DNS, etc.

Windows defaults: if it sees both, DHCPv6 settings win for DNS resolver assignment even when SLAAC provided the address. **That is the bug `mitm6` exploits.**

### How mitm6 works

```
attacker                                       victim (Windows host)
   |                                              |
   |                                  --- DHCPv6 SOLICIT  multicast ff02::1:2
   |                                                                       |
   |<-------- multicast packet received from victim -----------------------|
   |                                                                       |
   |--- DHCPv6 ADVERTISE: I am DHCPv6 server, here's a /64 + DNS = me ---->|
   |                                                                       |
   |                                       (some time later)               |
   |                                                                       |
   |--- DHCPv6 REQUEST relayed back, REPLY confirming ------------------>  |
   |                                                                       |
   |  victim now has IPv6 address + DNS resolver = attacker                |
   |                                                                       |
   |<--- victim queries attacker for "wpad" or other corp services ---------|
   |                                                                       |
   |--- attacker answers, often pointing to an HTTP NTLM challenge --------|
   |                                                                       |
   |  HTTP NTLM auth → relay to LDAPS on a real DC → RBCD on victim$       |
```

```bash
sudo mitm6 -d corp.local -i dvad-ctf
```

mitm6 needs to be paired with `ntlmrelayx`:

```bash
sudo ntlmrelayx.py -wh attacker.corp.local -t ldaps://dc01.corp.local --delegate-access -smb2support
```

`-wh attacker.corp.local` instructs ntlmrelayx to serve WPAD pointing at itself; `--delegate-access` tells it that on successful LDAPS auth, modify the victim's `msDS-AllowedToActOnBehalfOfOtherIdentity` to grant a controlled computer account RBCD over the victim. Net result: you get a Kerberos S4U2Proxy ticket as Administrator to the victim host.

This entire chain runs unauthenticated. **You need zero credentials to start.** That's why mitm6 is one of the highest-value initial-access primitives in DVAD ([Flag: IA-012]).

### Defending mitm6

- Disable IPv6 on interfaces where it isn't needed.
- Set `DhcpV6Enabled` policies to prefer SLAAC and ignore DHCPv6 DNS.
- RA Guard on switches drops unauthorised RAs.
- Filter DHCPv6 from non-server ports.

DVAD leaves IPv6 enabled and ignores all of the above to keep mitm6 exploitable.

---

## 1.11 DHCP for IPv4

DHCPv4 is broadcast-based and stateful. Four-message conjugation:

```
DISCOVER  -- client broadcasts "anyone got an address?"
OFFER     -- server replies with a candidate
REQUEST   -- client says "yes, that one"
ACK       -- server confirms
```

Within DVAD, the project-local dnsmasq under `/tmp/dvad-dnsmasq/` answers DHCP for all three bridges, using the static-lease configuration from `qemu/network/setup-network.sh`. The same MAC-to-IP mapping appears in `qemu/vm-create.sh` — that's why those two files must stay in sync, per CLAUDE.md.

DHCP options carry more than just the address:

| Option | Name | Purpose |
|---|---|---|
| 1 | Subnet Mask | |
| 3 | Router | Default gateway |
| 6 | DNS Servers | |
| 15 | Domain Name | |
| 42 | NTP Servers | |
| 51 | Lease Time | |
| 53 | Message Type | DISCOVER/OFFER/etc. |
| 66 | TFTP Server Name | Used in PXE |
| 67 | Bootfile Name | |
| 119 | Domain Search List | |
| 252 | WPAD URL | Proxy auto-config |

A rogue DHCP server can hand out a malicious gateway, DNS resolver, or WPAD URL. On DVAD this is rarely the cleanest attack — mitm6 against IPv6 is easier and bypasses the wired DHCP that's already authoritative.

---

## 1.12 (Mechanics) Packet capture

You cannot debug an attack you can't see. Get good at `tcpdump` and Wireshark.

### tcpdump basics

```bash
sudo tcpdump -i dvad-ctf -nn                       # all traffic on bridge
sudo tcpdump -i dvad-ctf -nn host 10.10.0.10       # to/from one host
sudo tcpdump -i dvad-ctf -nn port 88               # Kerberos
sudo tcpdump -i dvad-ctf -nn -X port 5355          # LLMNR with payload hex
sudo tcpdump -i dvad-ctf -nn -w capture.pcap       # write to file
```

Filter expressions follow BPF syntax. Combine with `and`, `or`, `not`:

```bash
sudo tcpdump -i dvad-ctf -nn 'port (88 or 389 or 445 or 636 or 5985) and host 10.10.0.10'
sudo tcpdump -i dvad-ctf -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0'  # SYNs only
sudo tcpdump -i dvad-ctf -nn 'udp[8:2] = 0x0000 and port 5355'   # LLMNR queries (TXID 0x0000)
```

### Wireshark display filters

Different syntax. Some essentials:

```
ip.addr == 10.10.0.10
tcp.port == 445
kerberos
ldap.requestName
smb2.cmd == 5         # SMB2 SESSION_SETUP
http.authorization
```

Wireshark dissectors decode each protocol; expand the tree to see fields. For Kerberos especially, the dissection turns binary ASN.1 into readable named fields. Indispensable.

### Capturing on a bridge

The Linux bridge `dvad-ctf` is a virtual switch. Capturing on it shows you all traffic flowing through, but unicast frames between two specific bridge ports are not duplicated to your capture unless you make your interface promiscuous and the kernel decides to mirror them. For DVAD this works because the host runs the bridge, but on a real switched LAN you'd need port mirroring (SPAN port) or attacking inline.

```bash
sudo ip link set dvad-ctf promisc on
```

### Capturing on a specific VM's interface

Each VM has a tap interface like `vm-dc01`, `vm-file01` (set in `qemu/vm-create.sh`). You can capture on the tap to see only that VM's traffic:

```bash
sudo tcpdump -i vm-dc01 -nn
```

Useful when you want to confirm "did dc01 actually emit a Kerberos AS-REQ to my attacker?" without other noise.

### pcapng vs pcap

`tcpdump` writes classic pcap; Wireshark prefers pcapng (carries metadata about capture file, interfaces, comments). Convert with `editcap`:

```bash
editcap -F pcapng input.pcap output.pcapng
```

For pure binary analysis (e.g., extracting a Kerberos AS-REP for offline AS-REP roast), classic pcap is fine.

---

## 1.13 (Mechanics) Port scanning

Nmap is the workhorse. Memorize a small set of patterns:

### Liveness

```bash
sudo nmap -sn 10.10.0.0/21                          # ARP + ICMP for same-subnet
sudo nmap -sn -PE -PP -PM 10.10.0.0/24               # ICMP types
sudo nmap -sn -PS 22,80,443,445 10.10.0.0/24         # TCP SYN ping
sudo nmap -sn -PA 80 10.10.0.0/24                   # TCP ACK ping
```

### Service identification

```bash
sudo nmap -sV --version-intensity 5 -p 53,88,135,139,389,445,464,593,636,3268,3269,5985 10.10.0.10
```

`-sV` performs the handshake and runs probes (signatures from `/usr/share/nmap/nmap-service-probes`) to identify the service.

### Script scans (NSE)

NSE runs Lua scripts for additional probing.

```bash
sudo nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='corp.local',userdb=users.txt 10.10.0.10
sudo nmap -p 445 --script smb-os-discovery 10.10.0.10
sudo nmap -p 389 --script ldap-rootdse 10.10.0.10
sudo nmap -p 389 --script ldap-search --script-args 'ldap.username=,ldap.password=' 10.10.0.10
sudo nmap -p 445 --script smb-vuln-* 10.10.0.0/21
sudo nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 10.10.0.100
sudo nmap -p 80,443 --script http-enum,http-title 10.10.0.12
```

### Aggressive

```bash
sudo nmap -A -p- --min-rate 1000 10.10.0.10 -oA dc01-full
```

`-A` is `-sV -O -sC --traceroute`. Loud but informative. For DVAD where stealth isn't required, fine.

### UDP

```bash
sudo nmap -sU -p 53,88,123,137,138,161,389,500,1434,4500,5353,5355 10.10.0.10
```

UDP scanning is slow because the only signal is ICMP unreachable. Increase `--min-rate` cautiously.

### Output formats

```bash
-oN normal
-oG greppable (deprecated but useful)
-oX XML  (machine-readable)
-oA all  (writes -oN, -oG, -oX with the given prefix)
```

Always `-oA` your serious scans. You will need to reference them weeks later.

### Timing

`nmap -T0..T5`. T3 is default. T4 is "aggressive" — good for labs. T5 sacrifices reliability for speed; avoid unless time-boxed.

### Ranges and target lists

```bash
nmap 10.10.0.1-50                    # range
nmap -iL hosts.txt                    # list from file
nmap 10.10.0.0/21 --exclude 10.10.0.1 # exclude attacker IP
```

---

## 1.14 (Concept) HTTP, TLS, and certificate basics for ADCS

You don't need to be a webdev, but ADCS web enrollment runs over HTTP/HTTPS, and so does the certsrv coercion path in ESC8. So a brief tour.

### HTTP request anatomy

```
GET /certsrv/ HTTP/1.1
Host: ca01.corp.local
User-Agent: Mozilla/5.0
Accept: text/html
Authorization: NTLM TlRMTVNTUAABAAAA...
```

The Authorization header is where Windows speaks NTLM or Negotiate. NTLM authentication over HTTP is a three-message exchange tunnelled in the Authorization header. When you read `ntlmrelayx` output that says "Got authentication for alice", that's a base64 NTLM message it has parsed out of the Authorization header.

### NTLM-over-HTTP three-message flow

```
client -> server :  GET /certsrv/         (no auth)
server -> client :  401, WWW-Authenticate: NTLM
client -> server :  GET /certsrv/  Authorization: NTLM (Type 1 / Negotiate)
server -> client :  401  WWW-Authenticate: NTLM (Type 2 / Challenge)
client -> server :  GET /certsrv/  Authorization: NTLM (Type 3 / Authenticate)
server -> client :  200 OK
```

The interesting object is the Type 3 message — it contains the client's response to the server's challenge, computed as HMAC-MD5 of NT hash and challenge. This is what crackers extract.

### TLS

TLS wraps a TCP connection in encryption + integrity using a session key derived from a key-exchange. Versions: 1.0, 1.1 (both deprecated), 1.2 (still widespread), 1.3 (current).

For attacks in DVAD you mainly care about:

- **What cert does the server present?** — `openssl s_client -connect dc01.corp.local:636 -showcerts` gives you the chain. Useful to inspect the CA's cert (ADCS hands out the CA's own cert as the root of the chain).
- **Is channel binding (EPA) enforced?** — when enforced, the channel-binding token (CBT) carried in the SASL bind ties the LDAP authentication to the TLS channel. NTLM relay to LDAPS fails. When not enforced, relay works.

You'll see plenty of openssl commands in the ADCS chapter (06). For now, recognise that TLS isn't a magic safety blanket — attackers still relay through it when channel binding is off.

---

## 1.15 (Mechanics) Working with raw sockets and Scapy

Sometimes you need to craft a packet that no off-the-shelf tool emits. Scapy is the Python library for that.

```python
from scapy.all import *

# Send a custom DHCPv6 ADVERTISE
pkt = (IPv6(src='fe80::1', dst='ff02::1:2')
       /UDP(sport=547, dport=546)
       /...)  # DHCPv6 fields
send(pkt, iface='dvad-ctf')
```

You will not write a lot of scapy for this lab — the tools cover the standard attacks — but knowing it exists keeps you out of corners. For example: if your LLMNR poisoning isn't catching because the victim's resolver cache hasn't expired, you can scapy a query with the exact name to seed the cache.

```python
from scapy.all import *

q = IP(src='10.10.0.99', dst='224.0.0.252')/UDP(sport=5355,dport=5355)/DNS(rd=1, qd=DNSQR(qname='nonexistent', qtype='A'))
send(q, iface='dvad-ctf')
```

Or — if you want to manually validate a custom Kerberos PA-PAC-OPTIONS field — you can use `impacket.krb5` to craft an AS-REQ at the ASN.1 level.

This is bonus skill. You can pass DVAD without ever writing a scapy line.

---

## 1.16 (Concept) The OSI model where AD lives

Putting it together, here's where the AD-relevant protocols live:

```
+--------------------------------------------------------------+
|  L7  Application                                            |
|   Kerberos (TGT/TGS), NTLM (over HTTP, SMB, LDAP), LDAP,    |
|   SMB2/3, MS-RPC, DNS, DHCP, HTTP, ADWS                     |
+--------------------------------------------------------------+
|  L6  Presentation                                            |
|   ASN.1 (Kerberos), NDR (RPC), DER/PEM (certs), UTF-16LE    |
+--------------------------------------------------------------+
|  L5  Session                                                 |
|   SMB session setup, RPC binding, SASL                       |
+--------------------------------------------------------------+
|  L4  Transport                                               |
|   TCP/UDP                                                    |
+--------------------------------------------------------------+
|  L3  Network                                                 |
|   IPv4 / IPv6 / ICMP                                         |
+--------------------------------------------------------------+
|  L2  Data link                                               |
|   Ethernet / ARP / NDP                                       |
+--------------------------------------------------------------+
|  L1  Physical                                                |
|   Wire, fiber, RF (Wi-Fi)                                    |
+--------------------------------------------------------------+
```

Attacks happen at every layer. ARP spoof at L2. mitm6 at L3. SYN scanning at L4. NTLM relay at L7. Kerberos PAC forgery is L6 / L7. Knowing which layer your attack lives at tells you which countermeasure breaks it.

---

## 1.17 The MS-RPC primer

MS-RPC is the bedrock of Windows administration protocols. Many attacks (DCSync via MS-DRSR, coercion via MS-EFSR/MS-DFSNM/MS-RPRN, machine account password change via MS-NRPC-derived ZeroLogon) bottom out at RPC.

### Transports

- **Named pipes over SMB** — port 445. Pipe paths like `\PIPE\samr`, `\PIPE\lsarpc`, `\PIPE\netlogon`, `\PIPE\drsuapi`, `\PIPE\efsrpc`, `\PIPE\spoolss`.
- **TCP** — endpoint mapper at 135, then dynamic ports.
- **HTTP** — RPC over HTTP at 593.

### Interfaces

Each MS-* spec defines one or more RPC interfaces, identified by a UUID. Examples:

- MS-DRSR (DCSync): UUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2`
- MS-EFSR (PetitPotam): UUID `c681d488-d850-11d0-8c52-00c04fd90f7e`
- MS-RPRN (PrinterBug): UUID `12345678-1234-abcd-ef00-0123456789ab`
- MS-DFSNM (DFSCoerce): UUID `4fc742e0-4a10-11cf-8273-00aa004ae673`
- MS-NRPC (ZeroLogon, Netlogon): UUID `12345678-1234-abcd-ef00-01234567cffb`

### Binding

```
client → SMB pipe → bind PDU specifying interface UUID + version
server → bind_ack or bind_nak
client → request PDU with opnum (operation number)
server → response PDU
```

The opnum maps to a specific function in the IDL. For example, MS-EFSR opnum 0 is `EfsRpcOpenFileRaw` — the function PetitPotam abuses to coerce authentication.

### Why this matters

When you read "PetitPotam abuses MS-EFSR EfsRpcOpenFileRaw to coerce SMB authentication," the structure is:

1. Client opens SMB connection to victim 445.
2. Opens `\PIPE\efsrpc` (or `\PIPE\lsarpc` if the EFS RPC is rebound there).
3. RPC bind to MS-EFSR UUID.
4. Calls opnum 0 (`EfsRpcOpenFileRaw`) with a UNC path pointing to the attacker (e.g., `\\attacker\share\file`).
5. Victim's RPC server, running as SYSTEM, opens the path, which causes SMB to authenticate to `\\attacker` using the victim's machine account.
6. Attacker captures or relays that authentication.

This is the wire. Every coercion technique we cover (Chapter 9, 10) follows the same shape with a different opnum.

---

## 1.18 Time and clocks

Active Directory is a clock-dependent system. Kerberos rejects tickets whose authenticator timestamp is more than 5 minutes off the KDC's clock (by default). If your attacker box has a clock skew of 10 minutes, every Kerberos operation will fail with `KRB_AP_ERR_SKEW`.

### Setting your clock to match the DC

```bash
sudo ntpdate 10.10.0.10
# or:
sudo rdate -n 10.10.0.10
# or with chrony:
sudo chronyd -q 'server 10.10.0.10 iburst'
```

### Configuring permanent sync

```bash
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd
```

Then ensure the upstream NTP source is the DC or a peer the DC trusts. If your laptop syncs to `pool.ntp.org` but the DC runs its own internal NTP server with no upstream sync, the DC's clock can drift; one of you will end up out of sync.

### Diagnosing skew

```bash
ntpdate -q 10.10.0.10
# returns: offset N.NNN sec
```

If `|N| > 300`, Kerberos is broken until you fix it.

### Why Kerberos cares about time

The AS-REQ carries a `pa-enc-timestamp` PA-data — an encrypted timestamp the client uses to prove it knows the password before the KDC issues a TGT. The KDC checks the timestamp falls within the allowed skew. The AP-REQ similarly carries an `authenticator` containing a timestamp the service checks.

Without this, you could replay an old AS-REQ and the KDC would happily issue a fresh TGT. With it, replays are rejected because the timestamp is older than tolerance.

---

## 1.19 (Concept) Endianness, encoding, ASN.1, NDR

You will run into these in every protocol parser. Brief tour:

- **Endianness.** Network byte order is big-endian. Most modern x86 machines are little-endian. Kerberos / LDAP fields use ASN.1 DER which is its own byte order convention; you don't generally worry about it unless you're writing a parser.
- **UTF-16-LE.** Windows internal string encoding. The NT hash is `MD4(UTF-16-LE(password))`. If you type the password as ASCII into a hash calculator that uses UTF-8, you get the wrong hash.
- **ASN.1 DER.** Kerberos messages are ASN.1 sequences encoded in DER. A Kerberos AS-REQ starts with the bytes `6A 81 ??` — that's an application-tag 10 (AS-REQ).
- **NDR (Network Data Representation).** RPC marshaling. You'll see references to NDR when reading MS-* specs.

Tools that decode for you:

```bash
openssl asn1parse -in keytab.pem -i             # decode ASN.1 DER
impacket-rpcdump 10.10.0.10                     # list RPC endpoints
```

---

## 1.20 (Mechanics) Building your attacker box

A workable attacker box for DVAD:

```bash
# Base packages
sudo apt update
sudo apt install -y python3-pip pipx git tmux jq curl wget tcpdump wireshark \
                    nmap ldap-utils dnsutils netcat-openbsd openssl \
                    impacket-scripts crackmapexec nbtscan responder \
                    enum4linux-ng smbclient samba-common

# pipx tools (clean isolated installs)
pipx install netexec
pipx install certipy-ad
pipx install bloodhound
pipx install bloodyAD
pipx install mitm6

# Go-based tools
go install github.com/ropnop/kerbrute@latest

# Build-from-source
git clone https://github.com/fortra/impacket /opt/impacket && pip install -e /opt/impacket
git clone https://github.com/SpecterOps/SharpHound /opt/SharpHound  # for Windows compile
git clone https://github.com/Hackndo/lsassy /opt/lsassy
git clone https://github.com/topotam/PetitPotam /opt/PetitPotam
git clone https://github.com/Wh04m1001/DFSCoerce /opt/DFSCoerce
git clone https://github.com/leechristensen/SpoolSample /opt/SpoolSample

# Wordlists
sudo apt install -y wordlists seclists
# rockyou.txt at /usr/share/wordlists/rockyou.txt
# SecLists at /usr/share/SecLists/
```

Add hostnames to `/etc/hosts` so you don't depend on dnsmasq for every name resolution:

```
10.10.0.10  dc01.corp.local dc01 corp.local
10.10.0.11  dc01.eu.corp.local
10.10.0.12  ca01.corp.local ca01
10.10.0.13  file01.corp.local file01
10.10.0.14  sql01.corp.local sql01
10.10.0.100 ws01.corp.local ws01
10.20.0.10  dc01.finance.local finance.local
10.30.0.10  dc01.root.corp root.corp
```

Add a `KRB5_CONFIG` template at `~/krb5.conf`:

```ini
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_kdc = false
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d

[realms]
    CORP.LOCAL = {
        kdc = 10.10.0.10
        admin_server = 10.10.0.10
    }
    EU.CORP.LOCAL = {
        kdc = 10.10.0.11
        admin_server = 10.10.0.11
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
    corp.local = CORP.LOCAL
    .eu.corp.local = EU.CORP.LOCAL
    eu.corp.local = EU.CORP.LOCAL
    .finance.local = FINANCE.LOCAL
    finance.local = FINANCE.LOCAL
    .root.corp = ROOT.CORP
    root.corp = ROOT.CORP
```

`export KRB5_CONFIG=~/krb5.conf` (or copy to `/etc/krb5.conf`). With this in place, Kerberos-aware tools auto-discover KDCs and routes for cross-realm tickets.

---

## 1.21 (Mechanics) Common networking gotchas

These will burn you if you don't know them:

- **MTU.** Default Ethernet MTU is 1500. Some QEMU bridges default to 1500 - 8 = 1492 or even smaller. A TCP connection that works for handshake but stalls on first data packet is often MTU. `ping -M do -s 1472 10.10.0.10` tests path MTU.
- **Reverse path filtering.** Linux drops packets whose source IP isn't reachable via the interface they arrived on. If you set up routing weirdly between bridges, RPF may discard. `sudo sysctl net.ipv4.conf.all.rp_filter=0` for testing.
- **Conntrack timeouts.** NetFilter's conntrack table holds connection state. For long-lived TCP sockets behind NAT, default timeouts may close them. Mainly bites you when relaying tickets through long-running ntlmrelayx with SOCKS.
- **IPv6 disabled at boot.** `sysctl net.ipv6.conf.all.disable_ipv6` returning 1 means mitm6 can't even bind to its socket. Re-enable: `sudo sysctl net.ipv6.conf.all.disable_ipv6=0`.
- **DNS caching at the resolver.** systemd-resolved caches. `sudo resolvectl flush-caches`. `nscd` (rare on modern desktops) similarly. If you change `/etc/hosts` and lookups don't update, suspect the cache.
- **Port conflicts on attacker box.** Responder wants 53, 80, 88, 110, 135, 137, 139, 389, 443, 445, 5355. If your box runs a local DNS or web server, Responder fails silently on some of those services. Check: `sudo ss -lntu | grep -E ':(53|80|445|5355)'`.

---

## 1.22 The shape of an end-to-end recon session

Here is what your first 30 minutes on a new DVAD instance should look like:

```bash
mkdir -p ~/dvad-engagement/{recon,pcap,loot,notes}
cd ~/dvad-engagement

# 1. Identify your interface
ip addr show | grep -A2 -E 'dvad|enp|eth|wlan'

# 2. Initial liveness sweep on all three bridges (5 min)
for net in 10.10.0.0/21 10.20.0.0/24 10.30.0.0/24; do
  sudo nmap -sn $net -oA recon/live-${net//\//-}
done

# 3. Service scan on suspected DCs
for ip in 10.10.0.10 10.10.0.11 10.20.0.10 10.30.0.10; do
  sudo nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 $ip -oA recon/dc-$ip &
done; wait

# 4. Catch any straggler hosts
sudo nmap -sS -p- --min-rate 1000 10.10.0.0/24 -oA recon/all-10.10.0.0-24

# 5. DNS recon
for d in corp.local eu.corp.local finance.local root.corp; do
  dig @10.10.0.10 $d SOA >> recon/dns.txt
  dig @10.10.0.10 $d AXFR >> recon/dns.txt
  dig @10.10.0.10 _ldap._tcp.dc._msdcs.$d SRV >> recon/dns.txt
  dig @10.10.0.10 _kerberos._tcp.$d SRV >> recon/dns.txt
done

# 6. Anonymous LDAP
ldapsearch -x -H ldap://10.10.0.10 -s base namingcontexts > recon/ldap-rootdse.txt
ldapsearch -x -H ldap://10.10.0.10 -b 'DC=corp,DC=local' '(objectClass=user)' samAccountName -LLL > recon/users.txt

# 7. Anonymous SMB
nxc smb 10.10.0.10 -u '' -p '' --shares > recon/smb-anon.txt
enum4linux-ng -A 10.10.0.10 > recon/enum4linux.txt

# 8. Start a packet capture for the rest of the session
sudo tcpdump -i dvad-ctf -nn -w pcap/session-$(date +%H%M).pcap &
```

This baseline takes about 10 minutes to run, produces ~50MB of output, and gives you the recon foundation to plan everything else.

---

## Lab exercises

### Exercise 1.A — Build the network map

Run a host discovery sweep across all three subnets. For each responding host, record IP, hostname (via PTR lookup), OS guess (from TTL or nmap -O), and open ports from the 14 standard AD ports. Produce a single CSV.

```bash
nmap -sn 10.10.0.0/21 10.20.0.0/24 10.30.0.0/24 -oG hosts.gnmap
awk '/Up$/ {print $2}' hosts.gnmap > live.txt
for ip in $(cat live.txt); do
  hostname=$(dig @10.10.0.10 -x $ip +short)
  ttl=$(ping -c1 -W1 $ip 2>/dev/null | awk -F'ttl=' '/ttl=/{print $2; exit}' | awk '{print $1}')
  ports=$(nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 $ip -oG - | grep -oE '[0-9]+/open[^,]*')
  echo "$ip,$hostname,$ttl,$ports"
done > network-map.csv
```

### Exercise 1.B — Spot LLMNR in a pcap

Capture five minutes of traffic on the corp bridge. Open the pcap in Wireshark, filter `llmnr`, and identify any queries. For each query, identify the source host and the queried name.

```bash
sudo timeout 300 tcpdump -i dvad-ctf -nn -w llmnr-sweep.pcap udp port 5355 or udp port 137
wireshark llmnr-sweep.pcap   # filter: llmnr || nbns
```

Bonus: what's the relationship between the queried name and any nearby A records for similar names? Are these typos? Cached? Service lookups?

### Exercise 1.C — Trace a DNS resolution

From a Windows host, resolve `dc01.corp.local`. Capture the traffic on the bridge. Identify which protocols were used, in what order. (Hint: it depends on whether the cache is warm; flush it first.)

```cmd
ipconfig /flushdns
nslookup dc01.corp.local
```

Bridge-side:

```bash
sudo tcpdump -i dvad-ctf -nn 'port 53 or port 5355 or port 137 or port 5353'
```

Was there an LLMNR query? An mDNS query? Why or why not?

### Exercise 1.D — Decode a TCP handshake

Capture a single SMB session-setup from your attacker host to dc01. In Wireshark, identify the TCP three-way handshake. For each segment, note the sequence number, ACK number, and flags. Confirm that the third packet's ACK equals the second packet's seq+1.

```bash
sudo tcpdump -i dvad-ctf -nn -s 0 -w smb-session.pcap tcp port 445
# in another terminal
smbclient -L //10.10.0.10 -N
```

### Exercise 1.E — Identify hosts by TTL

Ping each known host and note the received TTL. Group by likely OS:

```bash
for ip in 10.10.0.10 10.10.0.11 10.10.0.12 10.10.0.13 10.10.0.14 10.10.0.100 10.20.0.10 10.30.0.10; do
  ttl=$(ping -c1 -W2 $ip 2>/dev/null | awk -F'ttl=' '/ttl=/{print $2; exit}' | awk '{print $1}')
  echo "$ip TTL=$ttl"
done
```

All should report ~128 (Windows default with 0 hops). If any reports 64, that host is Linux.

### Exercise 1.F — Manually craft an LLMNR poison response

(Advanced, optional.) Without using Responder, use Scapy to emit a single LLMNR response to a query observed on the wire. Confirm with tcpdump that the response was sent. Reflect: what made this trivial? What stops it from being trivial in a properly configured network?

### Exercise 1.G — Trace a Kerberos negotiation

(Requires creds, foreshadows chapter 5.) Authenticate to dc01 using `kinit alice@CORP.LOCAL` after `KRB5_CONFIG=~/krb5.conf`. Capture the AS-REQ/AS-REP on the wire. Open in Wireshark, expand the Kerberos tree. Identify the encryption type, the salt, the principal name, and the realm. You'll come back to this in chapter 5.

---

## Self-check questions

1. Why does Windows fall back to LLMNR after DNS, and not the other way around?
2. What's the difference between a SYN scan and a connect scan from an IDS perspective?
3. Given a host on `10.10.0.10/21`, what's the broadcast address for that subnet?
4. Why does mitm6 prefer DHCPv6 over Router Advertisement spoofing?
5. What's the byte sequence at the start of a Kerberos AS-REQ on the wire? (Hint: ASN.1 application tag.)
6. Why does `tcpdump -i dvad-ctf` show traffic between two VMs even though it's a switched bridge?
7. What happens if your attacker host's clock is 10 minutes off from the DC?
8. Why is UDP DNS limited to 512 bytes in classic RFC 1035, and what mechanism extends it?
9. Which UDP port carries LLMNR and which multicast address does it use?
10. Why is the SRV record more interesting to an attacker than the A record?

---

## References

- **RFC 791** — IPv4.
- **RFC 793** — TCP.
- **RFC 768** — UDP.
- **RFC 1034 + RFC 1035** — DNS concepts and protocol.
- **RFC 2782** — SRV record format.
- **RFC 4795** — LLMNR.
- **RFC 1002** — NetBIOS Name Service.
- **RFC 6762** — Multicast DNS.
- **RFC 4861** — Neighbour Discovery for IPv6.
- **RFC 8415** — DHCPv6.
- **The TCP/IP Guide** by Charles Kozierok — overall reference.
- **Practical Packet Analysis** by Chris Sanders — Wireshark from zero.
- **Network Warrior** by Gary Donahue — operator's view of routing/switching.

Next: [02-windows-internals.md](02-windows-internals.md).
