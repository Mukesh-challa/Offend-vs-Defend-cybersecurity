# Simulated C2 Beacon Detection Using Sysmon and Splunk

## Overview

This lab demonstrates how to simulate beacon-like network activity in a home SOC lab and detect the resulting telemetry using Sysmon and Splunk.

The goal was to generate periodic outbound HTTP connections from a Windows host to a Kali Linux system, collect the activity through Sysmon, and build detection logic using Splunk.

---

## Lab Environment

| Component         | Details                    |
| ----------------- | -------------------------- |
| Target Host       | Windows 11                 |
| Monitoring        | Sysmon v15.20              |
| SIEM              | Splunk Enterprise          |
| Log Forwarder     | Splunk Universal Forwarder |
| Simulation Server | Kali Linux                 |
| Kali IP           | 192.168.1.17               |

---

## Attack Simulation Workflow

```text
PowerShell Process
        ↓
HTTP Request
        ↓
Kali HTTP Server
        ↓
Periodic Callback
        ↓
Sysmon Event ID 3
        ↓
Splunk Detection
```

---

## Simulation Setup

### Create Beacon File

Kali Linux:

```bash
mkdir ~/c2lab
cd ~/c2lab

echo "OK" > beacon.txt
```

### Start HTTP Server

```bash
python3 -m http.server 8080
```

Expected Output:

```text
Serving HTTP on 0.0.0.0 port 8080
```

### Validate Service

```bash
curl http://127.0.0.1:8080/beacon.txt
```

Output:

```text
OK
```

---

## PowerShell Beacon Script

```powershell
while ($true)
{
    try
    {
        Invoke-WebRequest `
        -Uri "http://192.168.1.17:8080/beacon.txt" `
        -UseBasicParsing | Out-Null

        Write-Host "Beacon Sent"
    }
    catch
    {
        Write-Host "Failed"
    }

    Start-Sleep -Seconds 30
}
```

---

## Telemetry Generated

### Sysmon Event ID 1

Process Creation

```text
Image:
powershell.exe
```

### Sysmon Event ID 3

Network Connection

```text
Image:
powershell.exe

DestinationIp:
192.168.1.17

DestinationPort:
8080

Protocol:
TCP
```

### PowerShell Event ID 4104

Script Block Logging

```text
Invoke-WebRequest
Start-Sleep
```

---

## Detection Logic

### Detect PowerShell Network Connections

```spl
index=main
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
Image="*powershell.exe"
```

### Identify Destination Systems

```spl
index=main
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
| stats count by Image DestinationIp DestinationPort
| sort -count
```

### Beacon Frequency Analysis

```spl
index=main
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
| bucket _time span=30s
| stats count by _time
```

### PowerShell Script Detection

```spl
index=main
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
("Invoke-WebRequest" OR "Start-Sleep")
```

---

## Correlation Workflow

```text
Event ID 1
PowerShell Started
        ↓
Event ID 4104
Script Executed
        ↓
Event ID 3
Network Connection
        ↓
Destination 192.168.1.17:8080
        ↓
Repeated Connections
        ↓
Beacon-like Activity Detected
```

---

## MITRE ATT&CK Mapping

| Technique                         | ATT&CK ID |
| --------------------------------- | --------- |
| PowerShell                        | T1059.001 |
| Command and Scripting Interpreter | T1059     |
| Application Layer Protocol        | T1071     |

---

## Key Takeaways

* Successfully generated beacon-like network activity.
* Collected network telemetry using Sysmon Event ID 3.
* Correlated PowerShell execution with outbound connections.
* Built Splunk detections for PowerShell-based beaconing.
* Practiced ATT&CK-aligned detection engineering in a home SOC lab.

---

## Conclusion

This lab demonstrated how periodic PowerShell HTTP requests can generate telemetry that resembles beaconing behavior. Using Sysmon and Splunk, it was possible to correlate process creation, script execution, and network activity to identify and investigate the behavior through a defender's perspective.
