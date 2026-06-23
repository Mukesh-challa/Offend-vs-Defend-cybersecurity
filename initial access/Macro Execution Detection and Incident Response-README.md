# SOC Home Lab – Macro Execution Detection and Incident Response

## Objective

The objective of this lab was to simulate the execution of a macro-enabled Microsoft Word document and validate the organization's ability to detect, investigate, contain, and remediate suspicious Office-based process execution using Sysmon and Splunk.

Unlike real-world malicious macro attacks, this exercise used a harmless payload to safely generate telemetry while preserving the attack behavior required for detection engineering.

---

## Lab Environment

### Attacker System

* Kali Linux Virtual Machine

### Target System

* Windows 11 Host

### Monitoring Components

* Sysmon
* Splunk Universal Forwarder
* Splunk Enterprise

---

## Attack Simulation

A Microsoft Word Macro-Enabled Document (.docm) was created to execute a benign process upon opening the document.

### Macro Used

```vb
Sub AutoOpen()

    Shell "notepad.exe", vbNormalFocus

End Sub
```

When the document was opened and macros were enabled, Microsoft Word automatically launched Notepad.

### Process Flow

WINWORD.EXE
└── notepad.exe

This behavior simulates the parent-child process relationship commonly observed during malicious macro-based attacks.

---

## Detection Objectives

The lab focused on detecting:

* Office applications spawning child processes
* Suspicious parent-child process relationships
* Potential macro execution activity
* PowerShell or scripting engine execution from Office applications
* Unauthorized process execution initiated through Office documents

---

## Telemetry Generated

### Sysmon Event ID 1 – Process Creation

Parent Process:

WINWORD.EXE

Child Process:

notepad.exe

Relevant Fields:

* ParentImage
* Image
* CommandLine
* User
* ProcessGuid
* ParentProcessGuid

---

## Splunk Detection Queries

### Office Spawning Child Processes

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
ParentImage="*WINWORD.EXE"
| stats count by Image ParentImage CommandLine
```

### Office Spawning PowerShell

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
ParentImage="*WINWORD.EXE"
Image="*powershell.exe"
```

### Office Spawning Common LOLBins

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
ParentImage="*WINWORD.EXE"
| search Image="*powershell.exe"
OR Image="*cmd.exe"
OR Image="*wscript.exe"
OR Image="*cscript.exe"
OR Image="*mshta.exe"
```

---

## Indicators of Compromise (IOCs)

### Suspicious Parent Processes

* WINWORD.EXE
* EXCEL.EXE
* POWERPNT.EXE
* OUTLOOK.EXE

### Suspicious Child Processes

* powershell.exe
* cmd.exe
* wscript.exe
* cscript.exe
* mshta.exe
* rundll32.exe
* regsvr32.exe

### Suspicious Command Line Indicators

* EncodedCommand
* IEX
* Invoke-Expression
* DownloadString
* Hidden
* Bypass
* Net.WebClient

---

## Alert Validation

Upon alert generation, the following validation steps were performed:

### Step 1 – Identify Running Process

```powershell
Get-Process notepad
```

### Step 2 – Obtain Process Details

```powershell
Get-CimInstance Win32_Process |
Select Name,ProcessId,ParentProcessId
```

### Step 3 – Verify Parent Process

Confirmed the process hierarchy:

WINWORD.EXE
└── notepad.exe

### Step 4 – Review Command Line

```powershell
Get-CimInstance Win32_Process |
Where {$_.Name -eq "notepad.exe"}
```

---

## Incident Response

### Containment

After validating the alert, the child process was terminated.

```powershell
Stop-Process -Name notepad -Force
```

Alternative:

```powershell
taskkill /PID <PID> /F
```

### Verification

```powershell
Get-Process notepad
```

No active process remained after containment.

---

## Persistence Investigation

The following persistence locations were reviewed:

### Registry Run Keys

```powershell
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
```

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
```

### Scheduled Tasks

```powershell
Get-ScheduledTask
```

### Startup Folder

```powershell
shell:startup
```

### Services

```powershell
Get-Service
```

No unauthorized persistence mechanisms were identified.

---

## MITRE ATT&CK Mapping

### Initial Access

T1566.001 – Phishing Attachment

### Execution

T1204 – User Execution

### Command and Scripting Interpreter

T1059 – Command and Scripting Interpreter

### Office Application Execution

T1137 – Office Application Startup

---

## Key Findings

* Sysmon successfully captured process creation events.
* Splunk successfully ingested Sysmon telemetry.
* Parent-child process relationships were clearly visible.
* Detection rules effectively identified Office-spawned processes.
* Incident response procedures successfully contained the activity.
* Persistence checks verified that no unauthorized persistence mechanisms were established.

---

## Conclusion

This lab successfully demonstrated the complete detection and response lifecycle for macro-based execution activity. By using a harmless macro payload, realistic attack telemetry was generated without introducing risk to the environment. The exercise validated Sysmon logging, Splunk detection content, IOC identification, alert triage procedures, process containment, and persistence investigation techniques commonly used by SOC analysts during real-world macro-based intrusion investigations.
