# PowerShell Base64 Encoded Command Detection Using Sysmon and Splunk

## Objective

Simulate and detect PowerShell execution using the `-EncodedCommand` parameter and develop a Splunk detection rule based on Sysmon telemetry.

---

## Attack Overview

PowerShell supports execution of Base64-encoded commands through the `-EncodedCommand` parameter. Attackers frequently use this technique to obfuscate malicious commands, evade simple signature-based detections, and execute payloads directly from memory.

### MITRE ATT&CK Mapping

* T1059.001 – PowerShell
* T1027 – Obfuscated Files or Information

---

## Lab Environment

### Components

* Windows 11 Target System
* Sysmon
* Splunk Enterprise
* Splunk Universal Forwarder

### Log Source

Microsoft-Windows-Sysmon/Operational

### Event Monitored

* Sysmon Event ID 1 (Process Creation)

---

## Attack Simulation

### Step 1 – Generate Base64 Encoded PowerShell Command

```powershell
$Command = 'Write-Host "SOC TEST"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$Encoded = [Convert]::ToBase64String($Bytes)
$Encoded
```

Generated Base64 String:

```text
VwByAGkAdABlAC0ASABvAHMAdAAgACIAUwBPAEMAIABUAEUAUwBUACIA
```

### Step 2 – Execute Encoded Command

```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAUwBPAEMAIABUAEUAUwBUACIA
```

### Expected Behavior

The encoded payload is decoded and executed by PowerShell.

Decoded Command:

```powershell
Write-Host "SOC TEST"
```

---

## Telemetry Generated

### Sysmon Event ID 1

Important fields observed:

```text
Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:
"C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe"
-EncodedCommand
VwByAGkAdABlAC0ASABvAHMAdAAgACIAUwBPAEMAIABUAEUAUwBUACIA

User:
Mukeshchalla\mukes

ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### Indicators of Compromise (IOCs)

| Indicator      | Value            |
| -------------- | ---------------- |
| Process        | powershell.exe   |
| Event ID       | 1                |
| Flag           | -EncodedCommand  |
| Encoding Type  | Base64           |
| Parent Process | powershell.exe   |
| User Context   | Interactive User |

---

## Detection Methodology

### Detection Logic

Identify PowerShell process creation events containing:

* `-EncodedCommand`
* `-enc`
* Encoded Base64 payloads

### Detection Rationale

PowerShell encoded commands are commonly associated with:

* Initial Access
* Phishing Payloads
* Malware Execution
* Post-Exploitation Activity
* Defense Evasion

Although administrators may occasionally use encoded commands, the technique is significantly more common in malicious activity than in routine administration.

---

## Splunk Detection Query

### Basic Detection

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| search "CommandLine:" AND "-EncodedCommand"
| table _time host Message
```

### Command Line Extraction

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| rex field=Message "CommandLine:\s(?<cmdline>[^\r\n]+)"
| regex cmdline="(?i).*(-enc|-encodedcommand).*"
| table _time host cmdline
```

### Enhanced Detection

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| rex field=Message "CommandLine:\s(?<cmdline>[^\r\n]+)"
| rex field=Message "ParentImage:\s(?<parent>[^\r\n]+)"
| regex cmdline="(?i).*(-enc|-encodedcommand).*"
| table _time host parent cmdline
```

---

## Investigation Workflow

When an alert triggers:

### Verify Process

Review:

```text
Image
CommandLine
ParentImage
User
ProcessId
```

### Analyze Parent Process

Common suspicious parent processes:

```text
winword.exe
excel.exe
outlook.exe
wscript.exe
cscript.exe
mshta.exe
rundll32.exe
```

### Decode Base64 Payload

Extract the Base64 string and decode it to determine the executed command.

### Review Additional Telemetry

Investigate:

* PowerShell Operational Logs
* Network Connections
* File Creation Events
* Registry Modifications
* Subsequent Process Creation

---

## Detection Strengths

* Low implementation complexity
* High visibility with Sysmon Event ID 1
* Detects common adversary tradecraft
* Easy to correlate with other telemetry

## Detection Limitations

* Legitimate administrative activity may generate false positives
* Does not detect all PowerShell obfuscation techniques
* Requires Sysmon process creation logging

---

## Conclusion

## Parent-Child Process Telemetry Analysis

### Importance

Parent-child process relationships provide critical context during investigations. While PowerShell execution alone may be legitimate, the process that spawned PowerShell often reveals malicious activity.

Sysmon Event ID 1 records both the process and its parent process, enabling analysts to reconstruct the execution chain.

---

### Observed Process Tree

During the simulation, the following process hierarchy was observed:

```text
powershell.exe
└── powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAUwBPAEMAIABUAEUAUwBUACIA
```

### Telemetry Captured

```text
ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:
"C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe"
-EncodedCommand
VwByAGkAdABlAC0ASABvAHMAdAAgACIAUwBPAEMAIABUAEUAUwBUACIA
```

### Analysis

The encoded PowerShell process was launched by another interactive PowerShell session. This behavior is expected during a controlled lab simulation and represents a low-risk execution chain.

---

### Common Parent-Child Relationships

#### Low-Risk Administrative Activity

```text
explorer.exe
└── powershell.exe

cmd.exe
└── powershell.exe

powershell.exe
└── powershell.exe
```

These relationships are frequently observed during legitimate administration and scripting.

---

#### Suspicious Office-Based Execution

```text
WINWORD.EXE
└── powershell.exe

EXCEL.EXE
└── powershell.exe

OUTLOOK.EXE
└── powershell.exe
```

This pattern may indicate:

* Malicious Office macros
* Phishing attachments
* Initial malware execution

---

#### Script Interpreter Execution

```text
wscript.exe
└── powershell.exe

cscript.exe
└── powershell.exe

mshta.exe
└── powershell.exe
```

This pattern may indicate:

* Script-based malware
* Living-off-the-land techniques
* Malware staging activity

---

#### LOLBin-Based Execution

```text
rundll32.exe
└── powershell.exe

regsvr32.exe
└── powershell.exe

installutil.exe
└── powershell.exe
```

This pattern may indicate:

* Defense evasion
* Application whitelisting bypass
* Post-exploitation activity

---

### Splunk Parent-Child Telemetry Extraction

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| rex field=Message "Image:\s(?<Image>[^\r\n]+)"
| rex field=Message "ParentImage:\s(?<ParentImage>[^\r\n]+)"
| rex field=Message "CommandLine:\s(?<CommandLine>[^\r\n]+)"
| table _time ParentImage Image CommandLine
```

---

### High-Fidelity Detection

Detect encoded PowerShell launched from suspicious parent processes:

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| rex field=Message "ParentImage:\s(?<ParentImage>[^\r\n]+)"
| rex field=Message "CommandLine:\s(?<CommandLine>[^\r\n]+)"
| regex CommandLine="(?i).*(-enc|-encodedcommand).*"
| search ParentImage="*winword.exe" OR ParentImage="*excel.exe" OR ParentImage="*outlook.exe" OR ParentImage="*wscript.exe" OR ParentImage="*cscript.exe" OR ParentImage="*mshta.exe" OR ParentImage="*rundll32.exe"
| table _time host ParentImage CommandLine
```

### Detection Value

Parent-child process analysis significantly reduces false positives by focusing on suspicious execution chains rather than PowerShell execution alone. Combining encoded PowerShell detection with anomalous parent processes provides stronger detection coverage against real-world adversary techniques.


This lab successfully demonstrated the detection of Base64-encoded PowerShell execution using Sysmon and Splunk. Sysmon Event ID 1 provided detailed process creation telemetry, allowing detection of PowerShell launched with the `-EncodedCommand` parameter. The resulting detection rule offers an effective method for identifying obfuscated PowerShell activity commonly associated with adversary behavior while providing a foundation for advanced PowerShell threat hunting and detection engineering.
