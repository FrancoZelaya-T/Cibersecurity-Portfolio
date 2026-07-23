# 🛡️ Cybersecurity Portfolio — Franco Zelaya

Hands-on **Cybersecurity, Blue Team and SOC portfolio** focused on security monitoring, incident investigation, threat detection and incident response.

I am currently studying a **Bachelor's Degree in Cybersecurity** and developing practical laboratories to apply concepts related to SOC operations, Windows security, SIEM, endpoint monitoring and threat detection.

This repository documents my learning process through practical investigations, detection rules and defensive security projects.

---

## 🎯 Areas of Focus

- SOC Operations & Security Monitoring
- Incident Detection & Response
- SIEM & Log Analysis
- Windows Endpoint Security
- Sysmon
- Threat Hunting
- IOC & IOA Analysis
- MITRE ATT&CK
- Sigma Detection Rules
- Wazuh
- Windows Forensics
- Network Security

---

# 🔬 Cybersecurity Labs

| Lab | Project | Topics | Status |
|---|---|---|---|
| 01 | [Endpoint Activity Timeline](./Lab-01-Endpoint-Activity-Timeline/) | Sysmon, Incident Investigation, IOC/IOA, MITRE ATT&CK, Incident Response, Sigma | ✅ Completed |

---

## 🔎 Featured Project

### Lab 01 — Endpoint Activity Timeline

Investigation of suspicious activity detected on a simulated Windows workstation.

The investigation reconstructs an attack chain involving:

```text
Excel Document
      ↓
Microsoft Excel
      ↓
Obfuscated PowerShell
      ↓
External Network Connection
      ↓
Executable Created in AppData
      ↓
Payload Execution
      ↓
Registry Persistence
```

The laboratory includes:

- Event timeline reconstruction
- Sysmon event analysis
- Parent-child process analysis
- IOC identification
- Behavioral IOA identification
- MITRE ATT&CK mapping
- Incident severity classification
- Containment, eradication and recovery planning
- Threat hunting recommendations
- Behavioral detection engineering
- Four validated Sigma detection rules

**Sigma validation:** `0 errors / 0 condition errors / 0 issues`

➡️ [View full investigation](./Lab-01-Endpoint-Activity-Timeline/)

---

## 🧰 Technologies & Frameworks

`Windows` `Sysmon` `Sigma` `MITRE ATT&CK` `Wazuh` `SIEM` `PowerShell` `Git` `GitHub`

---

## 📚 Current Development

I am continuing to build practical cybersecurity laboratories focused on:

- SOC alert triage
- SIEM investigations
- Wazuh monitoring
- Windows event analysis
- Threat hunting
- Network traffic analysis
- Incident response
- Detection engineering

The objective of this portfolio is to demonstrate practical cybersecurity skills alongside my academic and professional training.

---

## 👤 About Me

**Franco Zelaya**

Cybersecurity student focused on developing a career in **SOC, Blue Team and defensive cybersecurity**.

Currently strengthening practical skills in security monitoring, incident analysis, Windows environments, networks and detection engineering through hands-on laboratories and cybersecurity training.

---

> This repository is intended for educational and professional portfolio purposes. All malicious indicators and attack scenarios used in the laboratories are simulated or training-only.