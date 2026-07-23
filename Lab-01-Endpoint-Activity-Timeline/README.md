# Lab 01 — Endpoint Activity Timeline

## Overview

This laboratory simulates the investigation of suspicious activity detected on a Windows endpoint.

The SOC received a reduced set of observable events from a workstation. There is no confirmed malware at the beginning of the investigation, so the objective is to reconstruct the activity timeline, identify suspicious behavior, extract indicators, map relevant MITRE ATT&CK techniques and determine an appropriate incident response.

> All artifacts used in this laboratory are training-only. No real malware or malicious infrastructure is involved.

---

## Scenario

**Host:** WS-023  
**User:** j.perez  
**Operating System:** Windows  
**Initial status:** Suspicious activity — malware not confirmed

The investigation begins after the user opens the following file:

`C:\Users\j.perez\Downloads\Factura_1023.xls`

Shortly afterward, several suspicious process, network, file and registry events are observed.

---

## Objectives

- Reconstruct the incident timeline.
- Identify suspicious process relationships.
- Identify Indicators of Compromise (IOCs).
- Identify behavioral Indicators of Attack (IOAs).
- Map observed activity to MITRE ATT&CK.
- Assign an incident severity.
- Define containment and investigation actions.
- Produce a documented SOC investigation.

---

## Data Sources

The simulated telemetry includes:

- User activity
- Sysmon Event ID 1 — Process Creation
- Sysmon Event ID 3 — Network Connection
- Sysmon Event ID 11 — File Creation
- Sysmon Event ID 13 — Registry Value Set

---

## Raw Event Timeline

| Timestamp | Event Source | Event Type | Host | User | Details |
|---|---|---|---|---|---|
| 08:42:11 | User Action | File Open | WS-023 | j.perez | Opened attachment `Factura_1023.xls` from Downloads |
| 08:42:28 | Sysmon | Process Create (EID 1) | WS-023 | j.perez | `EXCEL.EXE` spawned `powershell.exe` with obfuscated arguments |
| 08:43:02 | Sysmon | Network Connect (EID 3) | WS-023 | j.perez | `powershell.exe` connected to `cdn-check[.]com:443` |
| 08:43:06 | Sysmon | File Create (EID 11) | WS-023 | j.perez | Wrote `updater.exe` to `AppData\Roaming\Updater\` |
| 08:43:08 | Sysmon | Process Create (EID 1) | WS-023 | j.perez | Executed `updater.exe` from AppData |
| 08:44:12 | Sysmon | Registry Value Set (EID 13) | WS-023 | j.perez | Created HKCU Run key pointing to `updater.exe` |

---

## Investigation

_To be completed during the analysis._