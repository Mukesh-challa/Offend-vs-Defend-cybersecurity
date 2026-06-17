# SOC Playbook: DLL Injection Detection, Alert Validation, and Incident Response

## Objective

This playbook provides a structured methodology for detecting, validating, investigating, and responding to potential DLL Injection activity in a Windows environment using Sysmon and Splunk.

---

# Overview

DLL Injection is a form of Process Injection where a process forces another process to load a Dynamic Link Library (DLL). Adversaries use this technique to execute malicious code within the context of legitimate processes, evade security controls, and establish persistence.

## MITRE ATT&CK Mapping

| Technique         | ATT&CK ID |
| ----------------- | --------- |
| Process Injection | T1055     |
| DLL Injection     | T1055.001 |

---

# Detection Sources

## Sysmon

Primary telemetry sources:

### Event ID 1

Process Creation

Purpose:

```text
Identify source process responsible for suspicious activity.
```

---

### Event ID 7

Image Loaded

Purpose:

```text
Monitor DLLs loaded into processes.
```

Key Fields:

```text
Image
ImageLoaded
Signed
SignatureStatus
```

---

### Event ID 8

CreateRemoteThread

Purpose:

```text
Detect remote thread creation between processes.
```

Commonly associated with process injection.

---

### Event ID 10

Process Access

Purpose:

```text
Detect one process obtaining high-privilege access to another process.
```

Key Fields:

```text
SourceImage
TargetImage
GrantedAccess
```

---

# Indicators of Compromise (IOCs)

## Process Access Indicators

Monitor for:

```text
OpenProcess
WriteProcessMemory
CreateRemoteThread
NtCreateThreadEx
QueueUserAPC
```

These behaviors commonly precede process injection.

---

## Suspicious DLL Locations

Investigate DLLs loaded from:

```text
C:\Users\<user>\Downloads\
C:\Users\<user>\AppData\
C:\Windows\Temp\
C:\Temp\
```

Risk increases when DLLs are:

```text
Unsigned
Unknown
Recently created
```

---

## Suspicious Process Relationships

Examples:

```text
winword.exe
 └─ suspicious.exe
      └─ process access to notepad.exe
```

```text
outlook.exe
 └─ powershell.exe
      └─ process access to explorer.exe
```

---

## High-Risk Access Rights

Examples:

```text
0x1FFFFF
0x1F0FFF
```

These access masks often indicate extensive process control capabilities.

---

# Alert Validation Workflow

## Step 1: Verify Alert Accuracy

Review:

```text
Timestamp
Hostname
Source Process
Target Process
User
GrantedAccess
```

Confirm the event is present in Sysmon telemetry.

---

## Step 2: Validate Source Process

Identify:

```text
What process initiated the access?
```

Examples:

### Common Legitimate Sources

```text
Microsoft Defender
CrowdStrike
SentinelOne
Sysmon
Process Explorer
Visual Studio Debugger
```

### Suspicious Sources

```text
Unknown executables
Unsigned binaries
Recently dropped files
```

---

## Step 3: Validate Target Process

Determine whether the target process is high value.

Examples:

```text
lsass.exe
explorer.exe
svchost.exe
winlogon.exe
services.exe
```

Access to critical processes increases investigation priority.

---

## Step 4: Validate DLL Characteristics

Review:

```text
DLL Path
DLL Name
Digital Signature
Creation Time
File Hash
```

Questions:

```text
Is the DLL signed?
Is the DLL expected?
Does the hash exist in threat intelligence sources?
```

---

## Step 5: Validate Process Tree

Review process lineage.

Example:

```text
explorer.exe
 └─ attacker.exe
      └─ Accessing notepad.exe
```

Determine:

```text
How was the process launched?
```

---

# False Positive Analysis

## Common False Positives

### Endpoint Detection and Response Tools

Examples:

```text
Microsoft Defender
CrowdStrike
SentinelOne
Trend Micro
Sophos
```

These tools frequently inspect other processes.

---

### Administrative Tools

Examples:

```text
Process Explorer
Process Hacker
Task Manager
Visual Studio Debugger
```

---

### Backup and Monitoring Agents

Examples:

```text
Veeam
ManageEngine
SolarWinds
```

---

# False Positive Reduction Strategy

## Rule Tuning

Exclude known processes:

```spl
NOT SourceImage="*MsMpEng.exe"
NOT SourceImage="*csagent.exe"
NOT SourceImage="*Sysmon64.exe"
```

---

## Signature Validation

Lower priority when:

```text
Source process signed
Known vendor
Known baseline activity
```

Raise priority when:

```text
Unsigned executable
Unknown publisher
```

---

# Threat Assessment

## Low Severity

Criteria:

```text
Known security software
Known administrative tool
Expected behavior
```

Action:

```text
Document and close
```

---

## Medium Severity

Criteria:

```text
Unknown source process
Suspicious DLL path
No additional malicious activity
```

Action:

```text
Escalate for deeper investigation
```

---

## High Severity

Criteria:

```text
Access to LSASS
Unsigned DLL
CreateRemoteThread activity
Network communication observed
```

Action:

```text
Immediate incident response
```

---

# Incident Response Workflow

## Phase 1: Identification

Collect:

```text
Hostname
Username
Source Process
Target Process
DLL Name
DLL Path
Hash
```

Document findings.

---

## Phase 2: Containment

If malicious activity is confirmed:

### Endpoint Isolation

Examples:

```text
Microsoft Defender Isolation
CrowdStrike Containment
SentinelOne Network Quarantine
```

Objective:

```text
Prevent lateral movement
Prevent further execution
```

---

### Account Containment

If credentials may be exposed:

```text
Disable account
Force password reset
Terminate sessions
```

---

# Phase 3: Investigation

## Process Analysis

Review:

```text
Sysmon Event ID 1
Sysmon Event ID 8
Sysmon Event ID 10
```

Questions:

```text
What process initiated injection?
What process was targeted?
```

---

## Network Analysis

Review:

```text
Sysmon Event ID 3
Firewall Logs
Proxy Logs
DNS Logs
```

Identify:

```text
C2 Communication
External Connections
Data Exfiltration
```

---

## Persistence Analysis

Investigate:

```text
Scheduled Tasks
Registry Run Keys
Services
Startup Folder
WMI Events
```

---

# Phase 4: Eradication

Remove:

```text
Malicious DLLs
Malicious Executables
Persistence Mechanisms
Scheduled Tasks
```

Block:

```text
Hashes
Domains
IPs
```

---

# Phase 5: Recovery

Actions:

```text
Restore affected systems
Reconnect isolated hosts
Re-enable accounts
Validate business operations
```

Monitor closely for recurrence.

---

# Splunk Detection Queries

## Suspicious Process Access

```spl
index=sysmon EventCode=10
| table _time SourceImage TargetImage GrantedAccess
```

---

## High Privilege Process Access

```spl
index=sysmon EventCode=10
GrantedAccess="0x1FFFFF"
| table _time SourceImage TargetImage GrantedAccess
```

---

## DLL Loaded from User-Writable Directories

```spl
index=sysmon EventCode=7
(ImageLoaded="*\\AppData\\*" OR
 ImageLoaded="*\\Temp\\*" OR
 ImageLoaded="*\\Downloads\\*")
| table _time Image ImageLoaded
```

---

## CreateRemoteThread Detection

```spl
index=sysmon EventCode=8
| table _time SourceImage TargetImage StartAddress
```

---

# Analyst Decision Matrix

| Question                          | Action                |
| --------------------------------- | --------------------- |
| Known security tool?              | Close as benign       |
| Signed DLL from trusted location? | Validate and document |
| Unsigned DLL loaded?              | Investigate           |
| High-risk process accessed?       | Escalate              |
| Remote thread created?            | High Severity         |
| Network activity observed?        | Incident Response     |
| Persistence discovered?           | Incident Declaration  |

---

# Final Outcome Classification

## Benign

```text
Legitimate software behavior
Known security tooling
```

Disposition:

```text
Close with documentation
```

---

## Suspicious

```text
Unknown process
Unusual DLL load
Requires additional analysis
```

Disposition:

```text
Escalate to Tier 2
```

---

## Malicious

```text
DLL Injection Confirmed
Credential Theft Indicators
Command-and-Control Activity
Persistence Mechanisms Present
```

Disposition:

```text
Contain
Investigate
Eradicate
Recover
Conduct Lessons Learned Review
```
