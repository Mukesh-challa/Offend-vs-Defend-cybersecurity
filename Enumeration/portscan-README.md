# 02 — Port Scanning Detection

> **Lab environment:** Splunk + Windows Firewall logs (`ms:winfirewall`, `pfirewall-2`)  
> **MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) — Network Service Discovery  
> **Purpose:** Educational research — offense vs defense analysis in an authorized lab

---

## What Is Port Scanning?

Port scanning is how attackers discover which services are running on a target system before launching an attack. It is almost always the **second step** after ICMP host discovery — once an attacker knows a host is alive, they probe its ports to find an entry point.

Understanding port scanning from both sides — attacker and defender — is a core SOC analyst skill. The same tools used by attackers (Nmap) are used daily by defenders for vulnerability assessment.

---

## Indicators of Compromise (IOCs)

| IOC | Threshold | Notes |
|-----|-----------|-------|
| High port count from single source | 50–100+ ports in short window | Below 20 may be normal admin activity |
| Sequential port probing | Incrementing port numbers | Suggests automated scanner |
| Probing high-value ports | 22, 445, 3389, 5985 | Targeted pre-attack recon |
| High scan rate | Hundreds of ports per second | Typical of Nmap default settings |
| Activity outside business hours | Before 08:00 or after 18:00 | Low-and-slow scans often run overnight |
| Unknown source IP | Not in asset inventory | Internal unknown host is high risk |

---

## Analyst Triage Checklist

Before escalating a port scan alert, an analyst must answer:

**1. Source IP Reputation**
- Is the source internal or external?
- Is it a known authorized vulnerability scanner?
- Is it in the asset inventory or an unknown host?

**2. Number of Ports Scanned**
- 10–20 ports → could be normal service checks
- 50–100+ ports in a short period → suspicious
- Full range (1–65535) → almost certainly automated

**3. Scan Rate**
- Hundreds of ports in seconds → automated tool (Nmap, Masscan)
- One port every few minutes → low-and-slow evasion attempt

**4. Ports Targeted**
- High-value ports (22, 445, 3389, 5985) increase severity
- Random ports suggest broad scanning
- Specific targeted ports suggest a threat actor with prior knowledge

---

## Attacker Perspective

### Common Nmap Scan Types

| Nmap Command | Scan Type | What It Does |
|-------------|-----------|--------------|
| `nmap 192.168.1.12` | Basic TCP scan | Scans top 1000 ports |
| `nmap -sS 192.168.1.12` | SYN stealth scan | Half-open — never completes handshake |
| `nmap -sV 192.168.1.12` | Service/version detection | Identifies software running on open ports |
| `nmap -O 192.168.1.12` | OS detection | Fingerprints the target OS |
| `nmap -A 192.168.1.12` | Aggressive scan | OS + version + scripts + traceroute |
| `nmap -p- 192.168.1.12` | Full TCP port scan | All 65535 ports |
| `nmap -sU 192.168.1.12` | UDP scan | Scans UDP services |
| `nmap -sn 192.168.1.0/24` | Ping sweep | Host discovery across a subnet |
| `nmap -sV -p 3389 192.168.1.12` | RDP enumeration | Targeted RDP version check |

### Attacker Evasion Techniques

**Low-and-Slow Scans**  
Instead of scanning hundreds of ports in seconds, an attacker might probe one port every few minutes, spread activity over hours or days, and deliberately stay below SIEM thresholds. These are the hardest scans to detect with rate-based rules alone.

**Distributed Scans**  
Scanning activity spread across multiple compromised source systems. No single IP exceeds thresholds, but collectively they map the entire network.

**Targeted Scans**  
Rather than scanning all ports, an experienced attacker probes only high-value services — SSH (22), SMB (445), RDP (3389), WinRM (5985), and database ports (1433, 3306). Fewer packets, lower noise, same intelligence.

---

## SMB and RDP Enumeration

Beyond generic port scanning, attackers specifically target:

**SMB Enumeration (port 445)**
```bash
smbclient -L //<windows-ip> -N
```
SMB is a primary target because it enables file share access, lateral movement, and is the pathway for attacks like EternalBlue, PsExec-style execution, and NTLM relay.

**RDP Enumeration (port 3389)**
```bash
nmap -sV -p 3389 192.168.1.12
```
RDP access = interactive desktop session. Attackers enumerate it for brute force, credential spraying, or BlueKeep-style exploitation.

---

## Detection Logic

### Query 1 — Basic Port Scan Detection (Field Extraction Method)

First, create a field extraction in Splunk:  
`Settings → Fields → Field Extractions → Create new field → configure by regex`

```
^(?<date>\S+)\s(?<time>\S+)\s(?<action>\S+)\s(?<protocol>\S+)\s(?<src_ip>\S+)\s(?<dest_ip>\S+)\s(?<src_port>\S+)\s(?<dest_port>\S+)
```

Then detect any source scanning more than 5 unique ports:

```spl
sourcetype=pfirewall-2
| stats dc(dest_port) as unique_ports values(dest_port) as ports by src_ip
| where unique_ports > 5
```

---

### Query 2 — SYN Stealth Scan Detection (Rate-based)

```spl
sourcetype=pfirewall-2
| bucket _time span=1m
| stats dc(dest_port) as unique_ports values(dest_port) as ports by src_ip
```

---

### Query 3 — UDP Scan Detection

```spl
sourcetype=pfirewall-2 protocol=UDP
| bucket _time span=1m
| stats dc(dest_port) as unique_ports values(dest_port) as ports by src_ip
| where unique_ports > 3
```

---

### Query 4 — Full TCP Traffic View

```spl
sourcetype=pfirewall-2 protocol=TCP
| table _time src_ip dest_ip dest_port action
| sort - _time
```

---

### Query 5 — SMB Enumeration Alert

```spl
sourcetype=pfirewall-2 dest_port=445
| stats count by src_ip
```

---

### Query 6 — RDP Enumeration Alert

```spl
sourcetype=pfirewall-2 dest_port=3389
| bucket _time span=1m
| stats count by src_ip
| where count > 5
```

---

### Query 7 — Advanced Risk-Scored Port Scan Detection (ms:winfirewall)

This query extracts fields from raw Windows Firewall logs, scores each scan by targeted ports, and surfaces the highest-risk activity first.

```spl
index=* sourcetype="ms:winfirewall" earliest=-24h
| rex field=_raw "(?P<fw_action>ALLOW|DROP)\s+(?P<fw_proto>TCP|UDP|ICMP)\s+(?P<fw_src_ip>[\d.]+)\s+(?P<fw_dst_ip>[\d.]+)\s+(?P<fw_src_port>\d+)\s+(?P<fw_dst_port>\d+)"
| where isnotnull(fw_src_ip)
| where fw_src_ip!="127.0.0.1" AND fw_dst_ip!="127.0.0.1"
| bin _time span=10m
| stats dc(fw_dst_port) as ports_scanned, values(fw_dst_port) as port_list, values(fw_action) as actions
  by fw_src_ip, fw_dst_ip, _time
| where ports_scanned >= 3
| eval has_winrm=if(mvfind(port_list,"5985")>=0,"yes","no")
| eval has_smb=if(mvfind(port_list,"445")>=0,"yes","no")
| eval has_rdp=if(mvfind(port_list,"3389")>=0,"yes","no")
| eval risk_score=ports_scanned
    + if(has_winrm="yes",10,0)
    + if(has_smb="yes",10,0)
    + if(has_rdp="yes",10,0)
| sort - risk_score
| table _time, fw_src_ip, fw_dst_ip, ports_scanned, port_list, has_winrm, has_smb, has_rdp, risk_score
```

**How the risk score works:**

| Component | Score Added | Reason |
|-----------|-------------|--------|
| `ports_scanned` | +1 per port | Base volume score |
| `has_winrm = yes` | +10 | WinRM = remote code execution path |
| `has_smb = yes` | +10 | SMB = lateral movement, file access |
| `has_rdp = yes` | +10 | RDP = interactive desktop takeover |

A source scanning 5 ports including SMB, RDP, and WinRM scores **35** — immediately prioritised at the top of your investigation queue.

---

### Query 8 — Identifying Activity from a Specific IP

```spl
sourcetype=pfirewall-2 src_ip=192.168.1.10 host="Mukeshchalla"
| table _time src_ip dest_ip src_port dest_port protocol action
| sort - _time
```

Use this to pivot on a suspicious IP and see everything it touched — useful for building a timeline of attacker activity.

---

## Identifying TCP Scan Types via Flags

Windows Firewall logs do not reliably expose TCP flags. To classify scan types (SYN, FIN, NULL, Xmas, ACK), you need one of:

| Tool | What It Provides |
|------|-----------------|
| **Wireshark** | Full packet capture with flag inspection |
| **Suricata** | IDS with rule-based flag detection |
| **Zeek (Bro)** | Protocol-level connection logs |

For environments where tcp_flags are available in logs, see [`../03-tcp-flags/README.md`](../03-tcp-flags/README.md) for full Splunk SPL flag classification logic.

---

## False Positive Sources

| Source | Why It Looks Like an Attack | How to Confirm |
|--------|----------------------------|----------------|
| Vulnerability scanners (Nessus, OpenVAS) | Scans hundreds of ports rapidly | Verify source IP against scanner asset list |
| Network monitoring (PRTG, Nagios, Zabbix) | Polls services repeatedly | Check against monitoring server IPs |
| SNMP polling | Probes UDP 161 across multiple hosts | Check protocol is UDP 161 |
| Admin troubleshooting | Manual nmap or netstat checks | Cross-reference with change tickets |
| Asset discovery tools | Scheduled sweeps of known ranges | Validate against discovery schedules |

**Recommended:** Maintain an exclusion list in your SPL:
```spl
| where fw_src_ip NOT IN ("10.0.0.5","10.0.0.6")
```

---

## Initial Access Methods Detected by Port Scan Follow-up

After port scanning, attackers move to initial access. The ports they find open tell you what attack comes next:

| Port Found Open | Likely Next Attack | Key Windows Event IDs |
|----------------|-------------------|----------------------|
| 445 (SMB) | NTLM relay, PsExec, EternalBlue | 4624, 4625, 5140, 7045 |
| 3389 (RDP) | Brute force, credential spray, BlueKeep | 4624, 4625 |
| 5985 (WinRM) | PowerShell remoting, lateral movement | 4624, PowerShell 4104 |
| 22 (SSH) | Credential brute force | Auth logs |
| 1433 (MSSQL) | SQL injection, credential abuse | SQL Server logs |

---

## Limitations of This Detection Approach

- `ms:winfirewall` and `pfirewall-2` log connection attempts but **not TCP flags** — scan type classification (SYN vs FIN vs Xmas) requires packet capture
- Low-and-slow scans (1 port per minute) will **not trigger** rate-based threshold rules — consider time-window based anomaly detection
- Distributed scans across multiple source IPs **will not** be caught by per-IP thresholds — requires entity analytics or UEBA
- UDP scans are noisier and harder to baseline — tune UDP thresholds carefully per environment
- `rex` field extraction performance degrades on very large log volumes — consider using indexed field extractions for production

---

## Tools Referenced

| Tool | Role |
|------|------|
| Splunk | SIEM — log aggregation and SPL detection |
| Windows Firewall (`ms:winfirewall`, `pfirewall-2`) | Primary log source |
| Nmap | Attacker and defender scanning tool |
| smbclient | SMB enumeration tool |
| Wireshark | Packet capture for TCP flag analysis |
| Suricata / Zeek | IDS/NSM for protocol-level detection |
| Nessus / OpenVAS | Authorized vulnerability scanners (common FP source) |

---

## References

- [MITRE ATT&CK T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [Nmap Documentation](https://nmap.org/docs.html)
- [Windows Firewall Log Format](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/configure-the-windows-firewall-log)

---

*Part of the [offense-vs-defense](../) lab series.*
