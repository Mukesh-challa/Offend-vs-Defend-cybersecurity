# Registry-Based Payload Staging and Execution Detection Using Sysmon and Splunk

## Objective

The objective of this lab was to simulate an adversary storing a payload inside the Windows Registry, retrieving it through PowerShell, and validating whether Sysmon and Splunk could detect the activity through registry modification, process execution, and correlation-based detections.

---

# Attack Overview

Attackers frequently use the Windows Registry to hide payloads, configuration data, or persistence mechanisms. Instead of storing malicious scripts on disk, the payload is stored inside a registry value and later retrieved and executed by a scripting engine such as PowerShell.

This technique reduces disk artifacts and may evade traditional file-based detections.

MITRE ATT&CK Techniques:

* T1112 – Modify Registry
* T1059.001 – PowerShell
* T1027 – Obfuscated/Encoded Files and Information
* T1055 – Process Injection (related payload delivery technique)
* T1547.001 – Registry Run Keys / Startup Folder (persistence variant)

---

# Lab Environment

Operating System:

* Windows 10/11

Monitoring Tools:

* Sysmon
* Splunk Universal Forwarder
* Splunk Enterprise

Sysmon Events Monitored:

* Event ID 1 (Process Creation)
* Event ID 3 (Network Connection)
* Event ID 12 (Registry Key Creation/Deletion)
* Event ID 13 (Registry Value Modification)
* Event ID 14 (Registry Rename)

---

# Attack Simulation

## Step 1 – Create Registry Key

PowerShell:

```powershell
New-Item -Path "HKCU:\Software\TestLab" -Force
```

Expected Sysmon Event:

* Event ID 12
* Registry Key Created

Registry Path:

HKCU\Software\TestLab

---

## Step 2 – Store Payload in Registry

PowerShell:

```powershell
Set-ItemProperty `
-Path "HKCU:\Software\TestLab" `
-Name "Payload" `
-Value 'Write-Host "Registry Injection Test"'
```

Expected Sysmon Event:

* Event ID 13
* Registry Value Set

Registry Value:

Payload

Stored Data:

Write-Host "Registry Injection Test"

---

## Step 3 – Retrieve Payload

PowerShell:

```powershell
(Get-ItemProperty `
-Path "HKCU:\Software\TestLab" `
-Name Payload).Payload
```

Purpose:

Simulates an attacker retrieving a staged payload from the registry.

---

## Step 4 – Execute Payload

PowerShell:

```powershell
$payload = (Get-ItemProperty `
-Path "HKCU:\Software\TestLab" `
-Name Payload).Payload

Invoke-Expression $payload
```

Result:

PowerShell retrieves the payload from the registry and executes it.

---

# Detection Validation

## Sysmon Verification

Verify Registry Events:

```powershell
Get-WinEvent `
-LogName "Microsoft-Windows-Sysmon/Operational" |
Where-Object {$_.Id -in 12,13,14}
```

Observed:

* Event ID 13 generated successfully
* Registry modifications logged by Sysmon

---

# Indicators of Compromise (IOCs)

## Registry IOCs

Registry Key:

HKCU\Software\TestLab

Registry Value:

Payload

TargetObject Examples:

HKU<SID>\Software\TestLab

HKU<SID>\Software\TestLab\Payload

---

## Process IOCs

Process:

powershell.exe

Command Patterns:

Get-ItemProperty

Set-ItemProperty

Invoke-Expression

IEX

---

## Behavioral IOCs

PowerShell modifying registry values

PowerShell reading registry values

PowerShell executing retrieved content

Registry write followed by script execution

---

# Splunk Detection Queries

## Registry Value Modification

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
```

---

## Registry Monitoring for TestLab

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
TargetObject="*TestLab*"
```

---

## Registry Persistence Detection

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
TargetObject="*\\CurrentVersion\\Run*"
```

---

## PowerShell Registry Access

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*Get-ItemProperty*"
```

---

## PowerShell Payload Execution

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*Invoke-Expression*"
```

---

## Combined Registry + Execution Detection

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=13 OR EventCode=1)
```

Investigate hosts where:

* Registry modification occurs
* Followed by PowerShell execution

within a short time window.

---

# Detection Logic

## Rule Name

Registry-Staged PowerShell Execution

## Description

Detect PowerShell execution that is preceded by a registry value modification event.

## Logic

1. Registry value modified
2. Same user executes PowerShell
3. PowerShell reads registry content
4. PowerShell executes retrieved content

## Risk Level

High

Reason:

Attackers frequently use registry-based payload staging to evade disk-based monitoring.

---

# Threat Hunting Queries

## Registry Modifications by PowerShell

```spl
EventCode=13
Image="*powershell.exe"
```

---

## Suspicious Registry Payloads

```spl
EventCode=13
(Details="*powershell*"
OR Details="*Invoke-Expression*"
OR Details="*IEX*")
```

---

## Encoded Payload Storage

```spl
EventCode=13
Details="*FromBase64String*"
```

---

## Registry Activity Followed by Network Activity

```spl
(EventCode=13 OR EventCode=3)
```

Hunt for:

Registry Modification

→ PowerShell Execution

→ Network Connection

---

# Potential False Positives

Administrative scripts

Software installers

Application configuration updates

Legitimate enterprise automation tools

System management platforms

---

# Detection Improvements

1. Monitor all Registry Event IDs (12,13,14)
2. Enable PowerShell Script Block Logging
3. Enable PowerShell Module Logging
4. Correlate Sysmon Process Creation with Registry Events
5. Alert on Invoke-Expression usage
6. Alert on PowerShell reading registry values immediately before execution
7. Baseline normal registry modification behavior

---

# Attack Chain Summary

User Execution
↓
PowerShell.exe
↓
Registry Key Created
(Event ID 12)
↓
Registry Value Written
(Event ID 13)
↓
Payload Stored
↓
PowerShell Reads Registry
↓
Invoke-Expression
↓
Payload Execution
↓
Sysmon Telemetry Generated
↓
Splunk Detection Triggered

---

# Conclusion

The lab successfully demonstrated registry-based payload staging and execution. Sysmon generated Registry Event ID 13 telemetry, and Splunk searches were capable of identifying registry modifications, PowerShell execution, and potential payload retrieval activity. Correlating registry activity with PowerShell execution provides a strong behavioral detection for fileless and registry-based attack techniques.
