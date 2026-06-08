# 01 — ICMP Reconnaissance Detection

> **Lab environment:** Splunk + Windows Firewall logs (`ms:winfirewall`)  
> **MITRE ATT&CK:** [T1595.001](https://attack.mitre.org/techniques/T1595/001/) — Active Scanning: Scanning IP Blocks  
> **Purpose:** Educational research — offense vs defense analysis in an authorized lab

---

## What Is ICMP Reconnaissance?

ICMP (Internet Control Message Protocol) is a network-layer protocol used to send error messages and operational information. Attackers abuse it to silently map networks before launching further attacks.

Unlike TCP/UDP, ICMP requires no port, no handshake, and often passes through firewalls unchallenged — making it a low-noise first step in any reconnaissance phase.

---

## Indicators of Compromise (IOCs)

| IOC | Description |
|-----|-------------|
| High ICMP Echo Request volume | Flood of ping packets from a single source |
| One source → many destinations | Single IP contacting multiple hosts sequentially |
| Sequential destination addresses | Incrementing IPs suggest automated scanning (e.g. 192.168.1.1 → .2 → .3) |
| Activity outside business hours | Recon at 2 AM is rarely a sysadmin |

---

## Attack Use Cases

| Technique | How ICMP Is Used | ATT&CK Tactic |
|-----------|-----------------|---------------|
| Host Discovery | ICMP Echo Requests to identify live systems | Reconnaissance |
| Network Mapping | Map active hosts and segments | Discovery |
| Traceroute Recon | Discover network paths and intermediate hops | Discovery |
| DoS / DDoS | Flood targets with ICMP packets | Impact |
| Smurf Attack | Amplification via broadcast address (historical) | Impact |
| ICMP Tunneling | Encapsulate data inside ICMP payloads | Exfiltration / C2 |
| Data Exfiltration | Transfer stolen data through ICMP payload field | Exfiltration |
| Command & Control | Malware communicates via ICMP packets | C2 |
| Internal Network Mapping | Enumerate systems post-compromise | Lateral Movement |
| Firewall Testing | Identify filtering rules and reachable hosts | Defense Evasion |

---

## Attacker Perspective

Attackers prefer ICMP recon because:

- Many environments monitor TCP/UDP more closely than ICMP
- ICMP echo requests look like legitimate ping tests
- No TCP handshake means no connection logs on the target
- Works even when most ports are firewalled

**Evasion techniques attackers use:**
- Low-and-slow pings (one request every few minutes)
- Spreading pings across multiple source IPs
- Blending into business hours
- Spoofing source addresses

---

## Detection Logic

### Splunk SPL — ICMP Flood Detection

Detects any source sending more than 20 ICMP packets per minute, with business hours context.

```spl
index=main sourcetype=ms:winfirewall protocol=ICMP
| eval hour=tonumber(strftime(_time,"%H"))
| eval business_hours=if(hour>=8 AND hour<=18,"Yes","No")
| bucket _time span=1m
| stats count as icmp_count values(business_hours) as business_hours by src_ip _time
| where icmp_count > 20
| sort - icmp_count
```

**What each part does:**

| SPL Line | Purpose |
|----------|---------|
| `protocol=ICMP` | Filter to ICMP traffic only |
| `eval hour` | Extract the hour from timestamp |
| `eval business_hours` | Flag whether activity is within 08:00–18:00 |
| `bucket _time span=1m` | Group events into 1-minute windows |
| `stats count` | Count ICMP packets per source per minute |
| `where icmp_count > 20` | Threshold — tune based on your environment |
| `sort - icmp_count` | Highest volume sources at top |

**Tuning the threshold:**  
Start with `> 20`. In noisy environments raise to `> 50`. In quiet environments lower to `> 10`. Always baseline normal ping behavior first before setting thresholds.

---

## False Positive Sources

Before escalating an alert, rule out:

- **Network monitoring tools** — Nagios, PRTG, Zabbix all use ICMP for availability checks
- **IT admin ping sweeps** — Troubleshooting or inventory verification
- **Asset discovery tools** — Scheduled scans from known management systems
- **Backup/DR systems** — Some tools ping nodes before initiating jobs

**Recommended:** Maintain a whitelist of known scanner IPs and exclude them in your SPL with `where src_ip NOT IN ("known_scanner_ip1", "known_scanner_ip2")`.

---

## Limitations of This Detection Approach

- `ms:winfirewall` only logs what Windows Firewall sees — traffic on the same subnet may bypass it
- ICMP type and code fields are not always logged — you cannot distinguish Echo Request (type 8) from Echo Reply (type 0) without deeper logging
- ICMP tunneling and data exfiltration **cannot** be detected from firewall logs alone — requires packet capture (Wireshark) or IDS (Suricata/Zeek) with payload inspection
- Low-and-slow scans (1 ping every few minutes) will not trigger a rate-based threshold rule

---

## Tools Referenced

| Tool | Role |
|------|------|
| Splunk | SIEM — log aggregation and SPL queries |
| Windows Firewall (`ms:winfirewall`) | Log source |
| Wireshark | Packet-level ICMP analysis (not covered here) |
| Suricata / Zeek | IDS for payload inspection and tunneling detection |
| Nmap `-sn` | Attacker tool — ICMP ping sweep |
| hping3 | Attacker tool — custom ICMP packet crafting |

---

## References

- [MITRE ATT&CK T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [MITRE ATT&CK T1018 — Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
- [RFC 792 — ICMP Specification](https://datatracker.ietf.org/doc/html/rfc792)
- [Splunk ms:winfirewall sourcetype docs](https://docs.splunk.com/Documentation)

---

*Part of the [offense-vs-defense](../) lab series.*
