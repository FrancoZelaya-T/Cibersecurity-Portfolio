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
**Initial Status:** Suspicious activity — malware not confirmed

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
- Propose behavioral detection rules.
- Produce a documented SOC investigation.

---

## Executive Summary

A sequence of highly suspicious events was identified on workstation `WS-023` involving user `j.perez`.

The activity began after the user opened `Factura_1023.xls`. Seventeen seconds later, Microsoft Excel spawned PowerShell with obfuscated command-line arguments. PowerShell subsequently established an outbound HTTPS connection to `cdn-check[.]com`.

Shortly afterward, `updater.exe` was created under the user's AppData directory and executed. A Windows Registry Run key was then created pointing to the executable, establishing a persistence mechanism.

The correlation and timing of these events provide strong evidence of a likely endpoint compromise.

The incident is classified as **High Severity** and immediate containment and further investigation are recommended.

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

# Investigation

## Event 1 — Suspicious Excel Document Opened

**Timestamp:** 08:42:11  
**User:** j.perez  
**Host:** WS-023

The user opened `Factura_1023.xls` from the Downloads directory.

At this stage, the event alone is not sufficient to classify the document as malicious. Opening an Excel document from the Downloads directory is normal user activity.

However, the filename could be consistent with a phishing lure, so additional context would be required, including the file origin, hash, metadata, presence of macros and email delivery information.

**Assessment:** Informational / Requires correlation with subsequent events.

---

## Event 2 — Excel Spawns Obfuscated PowerShell

**Timestamp:** 08:42:28  
**Source:** Sysmon Event ID 1 — Process Creation

A suspicious parent-child process relationship was observed:

`EXCEL.EXE → powershell.exe`

PowerShell was executed with obfuscated arguments shortly after the user opened the Excel document.

This behavior significantly increases the level of suspicion. Microsoft Excel spawning PowerShell is unusual for a standard document workflow, and the use of obfuscated command-line arguments may indicate an attempt to conceal the executed commands.

Additional investigation should include analysis of the full PowerShell command line, parent process information, process hashes, user context and correlation with subsequent Sysmon events.

**Assessment:** Highly suspicious.

---

## Event 3 — Outbound Network Connection from PowerShell

**Timestamp:** 08:43:02  
**Source:** Sysmon Event ID 3 — Network Connection

Shortly after its execution, `powershell.exe` established an outbound HTTPS connection to:

`cdn-check[.]com:443`

A connection over TCP port 443 is not inherently malicious, as HTTPS traffic is common in legitimate environments.

However, the surrounding context significantly increases the level of suspicion. The connection was initiated by a PowerShell process spawned by Microsoft Excel with obfuscated arguments only seconds after the user opened `Factura_1023.xls`.

The destination domain should be investigated using threat intelligence and reputation sources. DNS, proxy, firewall and SIEM logs should also be reviewed to determine whether other endpoints communicated with the same infrastructure.

At this stage, containment actions such as blocking the destination and isolating the affected endpoint should be considered according to the organization's incident response procedures.

**Assessment:** Highly suspicious — possible malicious outbound communication.

---

## Event 4 — Suspicious Executable Created in AppData

**Timestamp:** 08:43:06  
**Source:** Sysmon Event ID 11 — File Creation

Four seconds after the outbound PowerShell connection, a new executable named `updater.exe` was written to:

`C:\Users\j.perez\AppData\Roaming\Updater\updater.exe`

The location is writable within the user's profile and does not normally require administrative privileges.

Although legitimate applications may use AppData, the creation of an executable in this location is suspicious when correlated with the preceding Excel, PowerShell and network activity.

The generic name `updater.exe` may also be intended to resemble legitimate software.

The temporal correlation suggests that the executable may have been downloaded during the preceding PowerShell network connection; however, additional telemetry would be required to confirm the file transfer.

**Assessment:** Highly suspicious.

---

## Event 5 — Execution of updater.exe

**Timestamp:** 08:43:08  
**Source:** Sysmon Event ID 1 — Process Creation

Two seconds after being created, `updater.exe` was executed from the user's AppData directory.

At this point, the sequence of events provides strong evidence of a likely endpoint compromise:

`Factura_1023.xls → EXCEL.EXE → powershell.exe → external connection → updater.exe creation → updater.exe execution`

The executable should be treated as potentially malicious and the endpoint should be considered for immediate containment according to incident response procedures.

Before removing the file, relevant evidence should be preserved. This includes file hashes, metadata, process information, network connections, Sysmon events and other available endpoint telemetry.

The SHA-256 hash should be calculated and investigated using threat intelligence sources such as VirusTotal.

A lack of reputation or detections should not be considered proof that the file is benign.

**Assessment:** Likely endpoint compromise — incident response required.

---

## Event 6 — Registry Run Key Persistence

**Timestamp:** 08:44:12  
**Source:** Sysmon Event ID 13 — Registry Value Set

A new registry value was created under:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater`

The value points to:

`C:\Users\j.perez\AppData\Roaming\Updater\updater.exe`

This registry location can automatically execute configured applications when the affected user logs on.

The activity therefore establishes a persistence mechanism for `updater.exe`.

The use of `HKEY_CURRENT_USER` is also relevant because changes within the current user's registry hive can generally be performed without administrative privileges.

This behavior maps to:

**MITRE ATT&CK T1547.001 — Registry Run Keys / Startup Folder**

**Tactic:** Persistence

**Assessment:** Confirmed persistence mechanism associated with the suspicious executable.

---

# Indicators of Compromise (IOCs)

The following indicators were identified during the investigation:

| Type | Indicator | Context |
|---|---|---|
| Domain | `cdn-check[.]com` | Destination contacted by PowerShell |
| File | `updater.exe` | Suspicious executable created and executed from AppData |
| File Path | `C:\Users\j.perez\AppData\Roaming\Updater\updater.exe` | Location of the suspicious executable |
| SHA-256 | Not available in provided telemetry | Should be collected during forensic analysis |

> Note: The domain and file artifacts are training-only indicators.

---

# Indicators of Attack (IOAs)

Behavioral indicators observed during the incident:

| Behavior | Significance |
|---|---|
| `EXCEL.EXE → powershell.exe` | Unusual Office-to-PowerShell process relationship |
| Obfuscated PowerShell arguments | Possible attempt to conceal executed commands |
| PowerShell outbound network connection | Suspicious external communication in context |
| Executable created in AppData | Suspicious file placement in a user-writable directory |
| Execution from AppData | Suspicious execution behavior |
| Registry Run Key creation | Persistence mechanism |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID | Confidence | Evidence |
|---|---|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | High | `EXCEL.EXE` spawned `powershell.exe` |
| Defense Evasion | Obfuscated Files or Information | T1027 | High | PowerShell executed with obfuscated arguments |
| Command and Control | Ingress Tool Transfer | T1105 | Medium | External PowerShell connection followed shortly by creation of `updater.exe`; file transfer is suspected but not directly confirmed |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 | High | HKCU Run key created pointing to `updater.exe` |
| Execution | User Execution: Malicious File | T1204.002 | Medium | User opened `Factura_1023.xls` shortly before the suspicious execution chain; malicious nature of the document is suspected but not independently confirmed |

---

# Incident Severity

## Severity: HIGH

The incident is classified as **High Severity** because the endpoint shows strong evidence of compromise and requires immediate containment.

Observed activity includes:

- Suspicious execution of PowerShell from Microsoft Excel.
- Obfuscated PowerShell command-line arguments.
- Outbound communication with suspicious external infrastructure.
- Creation and execution of `updater.exe`.
- Execution from a user-writable AppData directory.
- Establishment of persistence through a Registry Run key.

At this stage, there is no evidence of lateral movement, data exfiltration, ransomware activity, privilege escalation or compromise of additional endpoints.

For this reason, the incident is classified as **High rather than Critical**, pending further investigation into its scope and impact.

---

# Incident Response Actions

## 1. Containment

- Isolate `WS-023` from the network to prevent additional external communication or potential lateral movement.
- Block `cdn-check[.]com` according to the organization's incident response procedures.

## 2. Evidence Preservation and Investigation

Before removing suspicious artifacts, preserve relevant evidence:

- Calculate and record the SHA-256 hash of `updater.exe`.
- Collect relevant Sysmon and endpoint logs.
- Preserve process and parent-child process information.
- Review active and historical network connections.
- Preserve the suspicious executable for controlled analysis.
- Document the Registry Run key.
- Review additional persistence mechanisms.
- Investigate the origin of `Factura_1023.xls`.

## 3. Threat Hunting

Search across the environment for related indicators and behaviors:

- Connections to `cdn-check[.]com`.
- Hash of `updater.exe`.
- Execution of `updater.exe` or similar executables from user-writable directories.
- Office applications spawning PowerShell.
- Obfuscated PowerShell execution.
- Similar Registry Run key modifications.

This step is required to determine whether `WS-023` is an isolated incident or part of a broader compromise.

## 4. Eradication

After evidence collection:

- Remove or quarantine `updater.exe`.
- Remove the suspicious Registry Run key.
- Remove other related artifacts discovered during the investigation.
- Apply required security updates or configuration changes.

## 5. Recovery

- Verify that no additional persistence mechanisms remain.
- Confirm that suspicious processes and connections are no longer present.
- Restore the endpoint to a trusted operational state.
- Reconnect the endpoint to the network only after validation.
- Increase monitoring for recurrence of the identified behaviors.

## 6. Post-Incident Activities

- Document the complete incident timeline.
- Record identified IOCs and IOAs.
- Update detection rules and SOC documentation.
- Evaluate whether additional controls could prevent or detect similar activity earlier.

---

# Detection Rules

The following behavioral detection ideas are proposed based on the activity observed during the investigation.

The objective is to detect similar attack chains even when specific filenames, hashes or domains change.

## Detection Rule 1 — Office Application Spawning Command Interpreter

**MITRE ATT&CK:** T1059 / T1059.001

**Objective:** Detect unusual child processes launched by Microsoft Office applications.

**Detection Logic:**

```text
ParentImage ENDSWITH (
    '\EXCEL.EXE',
    '\WINWORD.EXE',
    '\POWERPNT.EXE'
)

AND

Image ENDSWITH (
    '\powershell.exe',
    '\cmd.exe',
    '\wscript.exe',
    '\cscript.exe',
    '\mshta.exe'
)
```

**Suggested Severity:** High

**Rationale:**  
Office applications spawning command or scripting interpreters can indicate suspicious document-based execution and should be investigated.

---

## Detection Rule 2 — Suspicious PowerShell Execution

**MITRE ATT&CK:** T1059.001 / T1027

**Objective:** Detect PowerShell executions containing arguments commonly associated with obfuscation, hidden execution or network retrieval.

**Detection Logic:**

```text
Image ENDSWITH '\powershell.exe'

AND

CommandLine CONTAINS_ANY (
    '-EncodedCommand',
    '-enc ',
    '-WindowStyle Hidden',
    'Net.WebClient',
    'DownloadFile',
    'Invoke-WebRequest'
)
```

**Suggested Severity:** Medium / High depending on context.

**Rationale:**  
Individual PowerShell commands may be legitimate. Detection confidence increases significantly when suspicious arguments are correlated with unusual parent processes or network activity.

---

## Detection Rule 3 — Executable Running from User-Writable Directory

**Objective:** Detect suspicious executables launched from user-writable locations such as AppData or temporary directories.

**Detection Logic:**

```text
Image MATCHES 'C:\Users\*\AppData\*\*.exe'

OR

Image MATCHES 'C:\Users\*\AppData\Local\Temp\*.exe'
```

Additional correlation should consider suspicious parent processes such as:

```text
powershell.exe
cmd.exe
wscript.exe
cscript.exe
mshta.exe
```

**Suggested Severity:** Medium / High depending on context.

**Rationale:**  
Legitimate applications may execute from AppData, so the location alone should not automatically classify a process as malicious. Correlation with parent process, file creation and network telemetry increases detection confidence.

---

## Detection Rule 4 — Registry Run Key Persistence from User-Writable Path

**MITRE ATT&CK:** T1547.001 — Registry Run Keys / Startup Folder  
**Relevant Telemetry:** Sysmon Event ID 13

**Objective:** Detect persistence through Run or RunOnce registry keys pointing to executables stored in user-writable locations.

**Detection Logic:**

```text
TargetObject CONTAINS_ANY (
    '\Software\Microsoft\Windows\CurrentVersion\Run',
    '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

AND

Details CONTAINS_ANY (
    '\AppData\Roaming\',
    '\AppData\Local\Temp\'
)
```

**Suggested Severity:** High

**Rationale:**  
Run and RunOnce keys are legitimate Windows functionality but are also frequently abused to establish persistence. Values pointing to executables in user-writable directories deserve additional investigation.

---

## Detection Rule 5 — Correlated Suspicious Execution Chain

**Objective:** Detect a sequence of related behaviors rather than relying on a single IOC.

**Correlation Window:** 5 minutes

**Detection Logic:**

1. Microsoft Office application spawns PowerShell or another script interpreter.
2. The spawned process establishes an external network connection.
3. An executable is created in a user-writable directory.
4. The executable is subsequently executed.
5. A Registry Run/RunOnce key is created.

Conceptually:

```text
Office Application
        ↓
Script Interpreter
        ↓
External Network Connection
        ↓
Executable Created in AppData
        ↓
Executable Executed
        ↓
Registry Persistence
```

**Suggested Severity:** High-confidence / High Severity alert

**Rationale:**  
Each individual event may occur legitimately in some environments. However, their occurrence on the same endpoint within a short time window provides a significantly stronger indication of malicious activity.

This correlation-based approach is also more resilient than detection based exclusively on static IOCs such as filenames, domains or hashes.

---

# Final Incident Conclusion

The investigation of `WS-023` identified a sequence of events providing strong evidence of an endpoint compromise.

The incident was classified as **High Severity** due to suspicious code execution, external communication, execution of a newly created executable and establishment of persistence.

## Observed Attack Chain

**Initial Activity:**  
User `j.perez` opened `Factura_1023.xls` from the Downloads directory. The delivery mechanism and origin of the document could not be confirmed with the available telemetry.

**Execution:**  
Shortly after the document was opened, `EXCEL.EXE` spawned `powershell.exe` with obfuscated command-line arguments.

**Network Activity:**  
PowerShell established an outbound HTTPS connection to `cdn-check[.]com`. The role of this infrastructure could not be independently confirmed from the available telemetry.

**Payload Activity:**  
Seconds after the network connection, `updater.exe` was created under `AppData\Roaming\Updater\` and subsequently executed.

The timing suggests a possible relationship with the preceding network activity, although the actual file transfer was not captured.

**Persistence:**  
A Registry Run key under `HKCU` was created pointing to `updater.exe`, establishing a confirmed persistence mechanism.

## Final Assessment

`WS-023` should be treated as a likely compromised endpoint and immediately enter the organization's incident response process.

No evidence of lateral movement, data exfiltration, ransomware activity or additional compromised endpoints was present in the provided telemetry.

Further investigation is required to determine the full scope and impact of the incident.

---

## Skills Demonstrated

This laboratory demonstrates practical knowledge of:

- SOC alert investigation
- Windows endpoint analysis
- Sysmon event correlation
- Process tree analysis
- IOC and IOA identification
- MITRE ATT&CK mapping
- Incident severity classification
- Incident response
- Threat hunting
- Behavioral detection
- Basic detection engineering

---

## Disclaimer

This laboratory is a cybersecurity training exercise.

All users, hosts, domains, files and indicators presented in this scenario are fictional and were created exclusively for educational purposes.