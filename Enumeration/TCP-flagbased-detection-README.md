# 03 — TCP Flag-Based Scan Detection

> **Lab environment:** Splunk + Windows Firewall logs (`ms:winfirewall`)  
> **MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) — Network Service Discovery | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) — Active Scanning  
> **Purpose:** Educational research — offense vs defense analysis in an authorized lab

---

## What Are TCP Flags?

Every TCP packet carries a set of control bits called **flags**. These flags control the state of a TCP connection — whether it is starting, transferring data, or closing. Attackers manipulate these flags to craft stealth scans that bypass firewalls and avoid detection.

Understanding TCP flags is essential for classifying **what kind of scan** an attacker ran — not just that they scanned.

---

## TCP Flag Reference Table

Flags are stored as a **bitmask** in the TCP header. Each flag occupies one bit:

| Flag | Bit Position | Decimal Value | Hex | Purpose |
|------|-------------|---------------|-----|---------|
| FIN | 0 | 1 | 0x01 | Finish — gracefully close connection |
| SYN | 1 | 2 | 0x02 | Synchronize — initiate connection |
| RST | 2 | 4 | 0x04 | Reset — immediately abort connection |
| PSH | 3 | 8 | 0x08 | Push — send data immediately |
| ACK | 4 | 16 | 0x10 | Acknowledge — confirm received data |
| URG | 5 | 32 | 0x20 | Urgent — prioritize this data |

**How the bitmask works:**  
If SYN + ACK are both set → 2 + 16 = **18 decimal** = `0x12`  
If FIN + PSH + URG are all set → 1 + 8 + 32 = **41 decimal** → this is the Xmas scan signature

---

## Scan Type Classification by Flag Combination

| Scan Type | Nmap Flag | Flags Set | Bitmask | What Attackers Expect |
|-----------|-----------|-----------|---------|----------------------|
| SYN Scan | `-sS` | SYN only | `S` | Open port → SYN-ACK. Closed → RST |
| FIN Scan | `-sF` | FIN only | `F` | Open port → no response. Closed → RST |
| Xmas Scan | `-sX` | FIN+PSH+URG | `FSPU` | Open port → no response. Closed → RST |
| NULL Scan | `-sN` | No flags | `0` | Open port → no response. Closed → RST |
| ACK Scan | `-sA` | ACK only | `A` | Maps firewall rules — not port state |
| UDP Scan | `-sU` | N/A (UDP) | N/A | Open → no response. Closed → ICMP unreachable |

---

## Why Attackers Use Non-SYN Scans

**SYN scans** are the most detected because they are the most common. Sophisticated attackers switch to FIN, NULL, and Xmas scans for these reasons:

- Many stateless firewalls only inspect SYN packets — non-SYN packets pass through unchecked
- Some IDS rules only alert on SYN floods — exotic flag combinations go unnoticed
- Windows and Unix respond differently to unexpected flag combinations — this is used for **OS fingerprinting**
- NULL and FIN scans generate no connection log on many systems — stealth by design

> **Key insight:** FIN, NULL, and Xmas scans only work reliably against **Unix/Linux** targets. Windows ignores the RFC and sends RST for all closed ports regardless of flags — meaning these scans often look like all ports are open on Windows. Attackers know this and use it to fingerprint the OS.

---

## Window Size as a Scanner Fingerprint

Beyond flags, Nmap's **TCP window size** reveals which scan mode was used. This is one of the most reliable passive fingerprinting techniques available to defenders.

### Basic SYN Scan — `nmap -sS`

```
Nmap sends:
├── Flag      = SYN (S)
├── Window    = 1024        ← Nmap hardcoded default
├── TTL       = 64
└── IP ID     = Random
```

**Why 1024?**  
Nmap developers hardcoded this as the default probe window. It is small enough to be a lightweight probe packet, large enough not to look like zero-window manipulation. This value is Nmap's most reliable fingerprint.

### Version / OS Detection Scan — `nmap -sV`, `nmap -O`, `nmap -A`

```
Nmap sends:
├── Flag      = SYN (S)
├── Window    = 64240       ← Linux kernel default
├── TTL       = 64
└── Options   = MSS, SACK, Timestamps
```

**Why 64240?**  
When running version or OS detection, Nmap mimics a real OS TCP stack to make the scan look like legitimate traffic. It uses the Linux kernel's default receive window (64240 bytes). This makes the scan harder to distinguish from a real connection — but the window value still betrays it.

### Window Size Quick Reference

| Window Size | Meaning |
|-------------|---------|
| `1024` | Nmap basic SYN scan (`-sS`) |
| `64240` | Nmap with `-sV`, `-O`, or `-A` (mimics Linux) |
| `65535` | Some OS fingerprinting probes |
| `8192` | Windows default — likely legitimate traffic |
| `0` | Zero-window probe — unusual, worth investigating |

---

## Detection Logic in Splunk

### Step 1 — Extract TCP Flag Fields from Raw Logs

Windows Firewall log format includes flag data, but it must be extracted via regex:

```spl
| rex field=_raw "^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s(?<action>\w+)\s(?<protocol>\w+)\s(?<src_ip>[\d.]+)\s(?<dest_ip>[\d.]+)\s(?<src_port>\d+)\s(?<dest_port>\d+)\s(?<size>\d+)\s(?<tcp_flags>\S+)\s(?<seq_num>\d+)\s(?<ack_num>\d+)\s(?<win_size>\d+)"
```

**Regex pattern explanation:**

| Pattern | Matches |
|---------|---------|
| `^\d{4}-\d{2}-\d{2}` | Date — YYYY-MM-DD at start of line |
| `\d{2}:\d{2}:\d{2}` | Time — HH:MM:SS |
| `\s` | Whitespace separator |
| `\w+` | Action word (ALLOW / DROP) |
| `[\d.]+` | IP address (digits and dots) |
| `\d+` | Port number |
| `\S+` | Non-whitespace — captures flags like `S`, `F`, `FSPU`, `0` |
| `(?<name>...)` | Named capture group → becomes a Splunk field |

---

### Step 2 — Classify Scan Type by Flag + Window Size

```spl
| eval scan_type = case(
    protocol="UDP",                        "UDP Scan (-sU)",
    protocol="TCP" AND tcp_flags="S"
        AND win_size="1024",               "SYN Scan (-sS) Nmap Default",
    protocol="TCP" AND tcp_flags="S"
        AND win_size="64240",              "SYN Scan (-sS) with -sV or -O",
    protocol="TCP" AND tcp_flags="F",      "FIN Scan (-sF)",
    protocol="TCP" AND tcp_flags="FSPU",   "Xmas Scan (-sX)",
    protocol="TCP" AND tcp_flags="0",      "NULL Scan (-sN)",
    protocol="TCP" AND tcp_flags="A",      "ACK Scan (-sA)",
    true(),                                "Unknown"
  )
```

**How `case()` works:**  
Conditions are evaluated top to bottom. The **first match wins** and assigns the label. The `true()` at the end is a catch-all for any flag combination not explicitly listed.

---

### Step 3 — Aggregate and Surface Results

```spl
| stats
    count         AS packets,
    dc(dest_port) AS ports_hit,
    values(dest_port) AS targeted_ports,
    values(win_size)  AS window_sizes
    BY src_ip, dest_ip, scan_type, tcp_flags, protocol
```

**What each stat does:**

| Field | SPL Function | Tells You |
|-------|-------------|-----------|
| `packets` | `count` | Total packets from this source |
| `ports_hit` | `dc(dest_port)` | How many unique ports were probed |
| `targeted_ports` | `values(dest_port)` | Full list of ports — e.g. [80, 443, 445, 3389] |
| `window_sizes` | `values(win_size)` | Confirms Nmap fingerprint |

---

### Full Query — Scan Type Classification for a Specific Source IP

```spl
index=main sourcetype="ms:winfirewall"
| rex field=_raw "^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s(?<action>\w+)\s(?<protocol>\w+)\s(?<src_ip>[\d.]+)\s(?<dest_ip>[\d.]+)\s(?<src_port>\d+)\s(?<dest_port>\d+)\s(?<size>\d+)\s(?<tcp_flags>\S+)\s(?<seq_num>\d+)\s(?<ack_num>\d+)\s(?<win_size>\d+)"
| where src_ip="192.168.1.15"
| eval scan_type = case(
    protocol="UDP",                        "UDP Scan (-sU)",
    protocol="TCP" AND tcp_flags="S"
        AND win_size="1024",               "SYN Scan (-sS) Nmap Default",
    protocol="TCP" AND tcp_flags="S"
        AND win_size="64240",              "SYN Scan (-sS) with -sV or -O",
    protocol="TCP" AND tcp_flags="F",      "FIN Scan (-sF)",
    protocol="TCP" AND tcp_flags="FSPU",   "Xmas Scan (-sX)",
    protocol="TCP" AND tcp_flags="0",      "NULL Scan (-sN)",
    protocol="TCP" AND tcp_flags="A",      "ACK Scan (-sA)",
    true(),                                "Unknown"
  )
| stats
    count         AS packets,
    dc(dest_port) AS ports_hit,
    values(dest_port) AS targeted_ports,
    values(win_size)  AS window_sizes
    BY src_ip, dest_ip, scan_type, tcp_flags, protocol
| sort - packets
| table src_ip, dest_ip, protocol, scan_type,
        tcp_flags, ports_hit, packets, window_sizes, targeted_ports
```

---

## Known Issue — FIN / NULL / Xmas Flags Not Appearing

> **Lab finding:** Running this query only returns SYN-related logs. FIN, NULL, and Xmas scan types show no results.

### Why This Happens

Windows Firewall (`ms:winfirewall`) is a **stateful firewall** that operates at the connection level, not the raw packet level. It logs:

- TCP SYN packets — because they initiate connections that the firewall must decide to allow or drop
- Established connection traffic — ALLOW entries for ongoing sessions

It does **not** log:

- FIN-only packets — Windows TCP stack silently drops or responds to these without the firewall logging them as discrete events
- NULL packets (no flags) — treated as malformed and discarded at the stack level before the firewall sees them
- Xmas packets (FIN+PSH+URG) — same as above — dropped without a firewall log entry being generated

### What This Means for Detection

| Scan Type | Detectable via Windows Firewall Logs? | Why |
|-----------|--------------------------------------|-----|
| SYN Scan | ✅ Yes | Initiates connection — firewall evaluates and logs |
| SYN+ACK | ✅ Yes | Part of established connection flow |
| ACK Scan | ⚠️ Partial | May appear as ALLOW on established connections |
| FIN Scan | ❌ No | Dropped at TCP stack — no firewall log |
| NULL Scan | ❌ No | Malformed packet — discarded silently |
| Xmas Scan | ❌ No | Malformed packet — discarded silently |
| UDP Scan | ⚠️ Partial | Logged only if firewall rule covers that UDP port |

### The Fix — Tools Required for Full Flag Detection

| Tool | How It Detects Flag Scans | Level |
|------|--------------------------|-------|
| **Wireshark** | Full packet capture — sees every raw TCP packet and all flag combinations | Manual / Lab |
| **Suricata** | IDS rules fire on specific flag patterns — e.g. `flags:FPU` for Xmas | Production |
| **Zeek (Bro)** | `conn.log` and `weird.log` capture malformed flag combinations | Production |
| **Sysmon (Event 3)** | Network connection events — richer than Windows Firewall but still connection-level | Production |

**Suricata example rule for Xmas scan:**
```
alert tcp any any -> $HOME_NET any (msg:"XMAS Scan Detected"; flags:FPU; sid:1000001; rev:1;)
```

**Suricata example rule for NULL scan:**
```
alert tcp any any -> $HOME_NET any (msg:"NULL Scan Detected"; flags:0; sid:1000002; rev:1;)
```

---

## OS Behavior Differences — Why It Matters for Attackers

| OS | Response to FIN/NULL/Xmas on CLOSED port | Response on OPEN port |
|----|------------------------------------------|----------------------|
| Linux / Unix | RST (per RFC 793) | No response |
| Windows | RST (always — ignores RFC) | RST (always) |
| BSD / macOS | RST (per RFC 793) | No response |

Windows always sending RST means:
- FIN/NULL/Xmas scans appear to show **all ports open** on Windows targets (no RST received = open)
- Attackers use this inconsistency to **fingerprint the OS** before choosing their exploit
- Defenders on Windows-only environments see fewer FIN/NULL/Xmas scan logs — not because they're not being scanned, but because Windows silently handles them

---

## Connecting the Dots — Full Recon Kill Chain

```
Step 1 → ICMP Ping Sweep        → Identify live hosts
Step 2 → SYN Port Scan          → Find open ports (logged by Windows Firewall)
Step 3 → FIN / NULL / Xmas      → Stealth scan to evade detection (NOT logged)
Step 4 → Service Version Scan   → Identify software versions (window=64240)
Step 5 → OS Detection           → Fingerprint the OS
Step 6 → Targeted Exploit       → Attack the identified service
```

Your Splunk + Windows Firewall setup reliably catches **Steps 1, 2, and 4**. Steps 3 and 5 require Suricata or packet capture.

---

## Limitations Summary

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| Windows Firewall only logs connection-level events | FIN/NULL/Xmas invisible | Deploy Suricata or Zeek |
| No raw packet access in `ms:winfirewall` | Cannot read exact flag bitmask | Use Sysmon Event ID 3 + Wireshark |
| Window size only captured if field exists in log format | May not always fingerprint Nmap | Confirm your log format includes win_size field |
| Distributed scans evade per-IP thresholds | Low-and-slow distributed scans undetected | UEBA / baseline anomaly detection |
| Windows TCP stack behavior masks certain scan types | OS fingerprinting by attacker succeeds | Network-level IDS required |

---

## Tools Referenced

| Tool | Role |
|------|------|
| Splunk | SIEM — SPL queries and flag classification |
| Windows Firewall (`ms:winfirewall`) | Log source — connection-level only |
| Nmap | Attacker tool — all scan types covered here |
| Wireshark | Packet capture — full flag visibility |
| Suricata | IDS — rule-based flag detection in production |
| Zeek / Bro | NSM — protocol analysis and weird log |
| Sysmon (Event ID 3) | Enhanced Windows network connection logging |

---

## References

- [MITRE ATT&CK T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [RFC 793 — TCP Specification](https://datatracker.ietf.org/doc/html/rfc793)
- [Nmap TCP Scan Types](https://nmap.org/book/man-port-scanning-techniques.html)
- [Suricata Rule Writing](https://suricata.readthedocs.io/en/latest/rules/tcp-keywords.html)
- [Zeek conn.log Reference](https://docs.zeek.org/en/master/logs/conn.html)

---

*Part of the [offense-vs-defense](../) lab series.*
