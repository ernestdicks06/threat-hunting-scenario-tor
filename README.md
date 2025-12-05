# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ernestdicks06/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some labusers may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of labusers discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.2.exe". Based on the logs returned, at `2025-12-05T09:01:07.9840446Z`, an labuser on the "attack-me-plz-e" device ran the file `tor-browser-windows-x86_64-portable-15.0.2.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "attack-me-plz-e"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.2"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1879" height="253" alt="image" src="https://github.com/user-attachments/assets/8fcb33d8-1685-4bda-bf8a-0dff1f909a73" />


---


### 2. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-12-05T09:18:24.461903Z`. These events began at `2025-12-05T09:01:07.9840446Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName  contains "tor"
| where DeviceName == "attack-me-plz-e"
| where InitiatingProcessAccountName == "labuser"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, SHA256, FileName, FolderPath, Account = InitiatingProcessAccountName

```
<img width="1869" height="583" alt="image" src="https://github.com/user-attachments/assets/024020c0-58e7-4330-90e5-da770f626420" />



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at ` 2025-12-05T14:03:39.8727598Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName  == "attack-me-plz-e"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1871" height="828" alt="image" src="https://github.com/user-attachments/assets/447e886d-6f00-4200-9994-140606f82ee8" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-12-05T14:16:11.0990743Z`, an labuser on the "attack-me-plz-e" device successfully established a connection to the remote IP address `87.106.80.166` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "attack-me-plz-e"
| where InitiatingProcessAccountName != "system"
| where RemotePort in("9050", "9001", "9040", "9030","9051","9150")
| project  Timestamp, DeviceName, InitiatingProcessAccountName,ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1899" height="417" alt="image" src="https://github.com/user-attachments/assets/c313de3f-b863-46dd-8cc6-7141c6e32e6e" />


---

## Chronological Event Timeline 

## 1. Process Execution – TOR Browser Silent Installation

Timestamp: 2025-12-05 09:02:56 AM (Local)
Event: The user “labuser” executed the TOR Browser installer in silent mode, indicating a background, non-interactive installation.
Action: Process creation detected.
Command:

tor-browser-windows-x86_64-portable-15.0.2.exe /S


File Path:
C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe
File Hash (SHA256): c9ea87f9bfe704b83a1c8af80442f41187620729dbc1468147595ab7f1c819d0

## 2. File Activity – TOR Browser Files Created on Desktop

Timestamp: 2025-12-05T09:18:24.461903Z
Event: Multiple TOR-related files were written to the desktop following installation, indicating the extraction/unpacking of the portable TOR Browser.
Action: File write events detected.
Notable File:
tor-shopping-list.txt (created on desktop)
File Path:
C:\Users\labuser\Desktop\…

## 3. Process Execution – TOR Browser Launched

Timestamp: 2025-12-05T14:03:39.8727598Z
Event: User “labuser” launched the TOR Browser. TOR-related processes such as tor.exe and/or firefox.exe were created, confirming the browser opened successfully.
Action: Process creation detected.
Process: tor.exe
File Path:
C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

## 4. Network Connection – TOR Network Relay Connection

Timestamp: 2025-12-05 09:16:11 AM (Local)
Event: The TOR process established an outbound connection to a known TOR relay port, confirming active TOR network usage.
Action: ConnectionSuccess
Remote IP: 87.106.80.166
Remote Port: 9001
Remote URL: https://www.xiavvnvbi7j3ysyy.com


Process: tor.exe
Process Path:
c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe

## 5. Additional TOR Network Connections

A few additional connections were observed over port 443, indicating continued TOR network traffic and circuit establishment.


Event: Additional TOR network connections established by user “labuser” using tor.exe.
Action: Multiple successful outbound connections detected.

---

## Summary

The user "labuser" on the "attack-me-plz-e" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `attack-me-plz-e` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
