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
# PowerShell Base64 Encoded Command Detection Playbook

## Objective

Detect, investigate, and validate PowerShell Base64 encoded command execution while minimizing false positives and improving detection fidelity.

---

# Overview

Base64 encoding is a standard data encoding technique used to convert binary data into ASCII text. PowerShell natively supports Base64 encoded command execution through the `-EncodedCommand` parameter.

Because Base64 is commonly used by both legitimate administrators and threat actors, detecting Base64 alone is insufficient. Effective detection requires behavioral correlation.

---

# How PowerShell Executes Base64 Commands

PowerShell leverages built-in .NET functionality:

### Encoding Components

```powershell
[Convert]::ToBase64String()
```

### Decoding Components

```powershell
[Convert]::FromBase64String()
```

### Character Encoding

```powershell
[System.Text.Encoding]::Unicode
```

PowerShell expects commands supplied to `-EncodedCommand` to be encoded using UTF-16 Little Endian (UTF-16LE).

Execution Flow:

```text
Command
    ↓
UTF-16LE Conversion
    ↓
Base64 Encoding
    ↓
PowerShell -EncodedCommand
    ↓
Decode
    ↓
Execute
```

---

# Primary Indicators of Compromise (IOCs)

## IOC 1 – Encoded Command Switches

Common attacker usage:

```text
-EncodedCommand
-enc
-e
```

Example:

```powershell
powershell.exe -enc SQBFAFgA...
```

---

## IOC 2 – Long Base64 Strings

Characteristics:

```regex
[A-Za-z0-9+/]{20,}={0,2}
```

Indicators:

* Long command lines
* High entropy strings
* Base64 padding (=)

---

## IOC 3 – Hidden Execution

Frequently observed switches:

```text
-NoProfile
-NonInteractive
-WindowStyle Hidden
-nop
-noni
-w hidden
```

Example:

```powershell
powershell.exe -nop -w hidden -enc ...
```

---

## IOC 4 – Suspicious Parent Processes

High-risk parents:

```text
WINWORD.EXE
EXCEL.EXE
OUTLOOK.EXE
POWERPNT.EXE
MSHTA.EXE
WSCRIPT.EXE
CSCRIPT.EXE
RUNDLL32.EXE
REGSVR32.EXE
```

Example:

```text
WINWORD.EXE
      ↓
powershell.exe -enc
```

---

## IOC 5 – Network Activity

Indicators:

```powershell
Invoke-WebRequest
Invoke-RestMethod
WebClient.DownloadString
DownloadFile
```

Behavior Chain:

```text
PowerShell EncodedCommand
        ↓
DNS Query
        ↓
HTTP/HTTPS Connection
        ↓
Payload Download
```

---

## IOC 6 – Child Process Creation

Suspicious children:

```text
cmd.exe
schtasks.exe
rundll32.exe
regsvr32.exe
msiexec.exe
net.exe
whoami.exe
nltest.exe
```

Example:

```text
powershell.exe
      ↓
cmd.exe
```

---

## IOC 7 – In-Memory Execution

Common indicators:

```powershell
Invoke-Expression
IEX
Add-Type
Reflection.Assembly
DownloadString
```

Example:

```powershell
IEX (New-Object Net.WebClient).DownloadString(...)
```

---

# Common Attack Scenarios

## Scenario 1 – Payload Download

Execution:

```powershell
powershell.exe -nop -w hidden -enc ...
```

Decoded Payload:

```powershell
IEX (New-Object Net.WebClient).DownloadString(...)
```

Indicators:

* Encoded command
* Hidden execution
* Network activity
* IEX

---

## Scenario 2 – Host Reconnaissance

Decoded Commands:

```powershell
whoami
ipconfig
hostname
net user
nltest
```

Indicators:

* Encoded command
* Enumeration activity

---

## Scenario 3 – Persistence

Decoded Commands:

```powershell
schtasks /create ...
```

Indicators:

* Encoded command
* Scheduled task creation

---

## Scenario 4 – Reverse Shell

Decoded Payload:

```powershell
New-Object System.Net.Sockets.TCPClient(...)
```

Indicators:

* Encoded command
* Outbound connection
* Long-lived session

---

# Legitimate Industry Usage

## Endpoint Management

Examples:

* Microsoft SCCM / MECM
* Microsoft Intune
* Enterprise software deployment tools

Purpose:

* Patch deployment
* Software installation
* Asset inventory

---

## PowerShell Remoting

Examples:

```powershell
Invoke-Command
Enter-PSSession
WinRM
```

Purpose:

* Remote administration

---

## DevOps / CI-CD

Examples:

* Jenkins
* Azure DevOps
* GitHub Actions

Purpose:

* Build automation
* Infrastructure deployment

---

## Cloud Automation

Examples:

* Azure Automation
* AWS Systems Manager

Purpose:

* Configuration management
* Automated remediation

---

## Security Tools

Examples:

* EDR products
* Vulnerability scanners
* Compliance tools

Purpose:

* Endpoint assessment
* Security monitoring

---

# Common False Positives

## SCCM Deployment

```text
ccmexec.exe
      ↓
powershell.exe -EncodedCommand
```

Reason:

Legitimate software deployment.

---

## Intune Management

```text
IntuneManagementExtension.exe
      ↓
powershell.exe -EncodedCommand
```

Reason:

Device management operations.

---

## Administrative Automation

Decoded Payload:

```powershell
Get-Service
Get-Process
Get-WindowsUpdate
```

Reason:

Routine administration.

---

## Backup Software

```text
BackupAgent.exe
      ↓
powershell.exe -EncodedCommand
```

Reason:

Backup orchestration.

---

# False Positive Reduction Strategy

## Method 1 – Decode the Command

Never stop at:

```text
EncodedCommand
```

Decode the payload and inspect content.

Low Risk:

```powershell
Get-Service
```

High Risk:

```powershell
IEX (New-Object Net.WebClient).DownloadString(...)
```

---

## Method 2 – Parent Process Analysis

Investigate:

```text
WINWORD.EXE
EXCEL.EXE
OUTLOOK.EXE
MSHTA.EXE
```

Allowlist:

```text
ccmexec.exe
IntuneManagementExtension.exe
TaniumClient.exe
```

---

## Method 3 – Network Correlation

Correlate:

```text
EncodedCommand
+
Network Connection
```

This significantly improves fidelity.

---

## Method 4 – Command Length Analysis

Typical Administrative Scripts:

```text
100–300 characters
```

Potentially Suspicious:

```text
500+ characters
```

Highly Suspicious:

```text
2000+ characters
```

---

## Method 5 – Suspicious Switch Combination

Example:

```powershell
powershell.exe -nop -noni -w hidden -enc ...
```

Risk Level:

High

---

## Method 6 – Child Process Correlation

Investigate:

```text
powershell.exe
      ↓
cmd.exe

powershell.exe
      ↓
schtasks.exe

powershell.exe
      ↓
rundll32.exe
```

---

# Detection Maturity Model

## Level 1 – Basic

```text
PowerShell + EncodedCommand
```

False Positives:

Very High

---

## Level 2 – Enhanced

```text
EncodedCommand
+
Hidden Window
```

False Positives:

Medium

---

## Level 3 – Behavioral

```text
EncodedCommand
+
Suspicious Parent Process
```

False Positives:

Low

---

## Level 4 – High Fidelity

```text
EncodedCommand
+
Suspicious Parent
+
Network Connection
+
Child Process Creation
```

False Positives:

Very Low

---

# Recommended SOC Detection Logic

```text
PowerShell EncodedCommand
AND
(NoProfile OR Hidden OR NonInteractive)
AND
(Network Activity OR Child Process OR Office Parent)
```

---

# High-Confidence Malicious Chain

```text
WINWORD.EXE
      ↓
powershell.exe -nop -w hidden -enc
      ↓
Outbound HTTP/HTTPS Connection
      ↓
cmd.exe / schtasks.exe / rundll32.exe
```

Confidence Level:

Very High

Recommended Response:

* Isolate host
* Decode payload
* Review network connections
* Investigate child processes
* Collect PowerShell logs
* Review Sysmon telemetry
* Hunt for lateral movement

---

# Key Takeaway

Base64 encoding is not inherently malicious. Effective detection relies on contextual analysis, including parent-child process relationships, decoded script content, network activity, persistence attempts, and suspicious execution parameters. High-fidelity detections should focus on behavioral chains rather than the presence of Base64 alone.



This lab successfully demonstrated the detection of Base64-encoded PowerShell execution using Sysmon and Splunk. Sysmon Event ID 1 provided detailed process creation telemetry, allowing detection of PowerShell launched with the `-EncodedCommand` parameter. The resulting detection rule offers an effective method for identifying obfuscated PowerShell activity commonly associated with adversary behavior while providing a foundation for advanced PowerShell threat hunting and detection engineering.
