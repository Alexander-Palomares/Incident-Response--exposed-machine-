# 🛡️ Incident Response Report: Brute Force Attempts on Internet-Exposed VM

## Overview

This project documents an incident response investigation into brute-force login attempts against an internet-facing Windows virtual machine (`windows-target-1`). The process follows a structured incident handling plan that includes preparation, data collection, analysis, investigation, response, documentation, and improvement phases. It includes live KQL queries, findings, and mappings to MITRE ATT&CK TTPs.

---

## 🔍 1. Preparation

**Goal:** Identify VMs exposed to the internet and determine if brute-force login attempts occurred.

**Hypothesis:**  
During a routine audit of shared services infrastructure (DNS, Domain Services, DHCP, etc.), the security team investigated whether any VMs were unintentionally exposed to the public internet. The working theory was that malicious actors may have targeted these exposed hosts with brute-force login attempts, especially since some systems lacked proper account lockout protections.

---

## 📥 2. Data Collection

**Goal:** Gather relevant logs and telemetry to investigate the hypothesis.

### Data Sources
- `DeviceInfo` – Determines if VM is internet-facing.
- `DeviceLogonEvents` – Shows login attempts, success/failure, and remote IPs.

### Sample Queries

```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| project DeviceName, IsInternetFacing, ExposureLevel

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by RemoteIP
| order by Attempts desc
```
---

## 📊 3. Data Analysis

**Goal:** Look for patterns or evidence supporting brute-force attack behavior.

### Findings:
- `windows-target-1` was confirmed to be internet-facing as of `2025-05-07T23:14:33Z`.
- Over **700 failed login attempts** from multiple remote IPs were observed.
- **No successful logins** occurred from any of the top 5 offending IPs.

```kql
let RemoteIPsInQuestion = dynamic(["194.180.48.36", "88.214.50.13", "37.27.49.254", "192.82.65.200", "191.98.157.22"]);
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

---

## 🕵️ 4. Investigation

**Goal:** Identify tactics and techniques used and assess impact.

### MITRE ATT&CK Mapping

| **Technique ID** | **Technique Name**               | **Justification**                                       |
|------------------|----------------------------------|---------------------------------------------------------|
| T1046            | Network Service Scanning         | Host was exposed to internet and likely scanned.       |
| T1110.001        | Brute Force: Password Guessing   | 700+ failed logins from various remote IPs.             |
| T1589            | Gather Victim Identity Information | Login attempts suggest account reconnaissance.         |
| T1078            | Valid Accounts (attempted use)   | Attempts used legitimate login methods, though failed.  |

### Conclusion:
This was a brute-force campaign against a misconfigured VM. No breach occurred.

---

## 🚨 5. Response

**Goal:** Mitigate and recover from the attempted attack.

### Containment
- Blocked attacking IPs at the firewall.
- Removed public internet access to the VM.

### Eradication
- Disabled unused or legacy user accounts.
- Verified no successful login sessions occurred.
- Installed the latest security updates.

### Recovery
- Enabled Multi-Factor Authentication (MFA).
- Enforced account lockout policy.
- Restricted RDP access using Just-In-Time (JIT) access.
- Implemented alerting for login failure spikes.

---

## 📈 6. Improvement

**Goal:** Strengthen detection, response, and prevention strategies.

### What Could Have Prevented This?
- Avoid exposing critical VMs directly to the internet.
- Enforce MFA and account lockout policies on all systems by default.
- Enable continuous exposure monitoring for VMs.

### How Can We Improve the Hunt?
- Automate detection of repeated failed login patterns.
- Build alert rules for spikes in login failure activity.
- Regularly audit VM internet exposure.
- Maintain a dynamic watchlist of malicious IPs to enrich logs.

---

### ✅ Summary
Despite a high volume of failed login attempts, there was no successful compromise. Proactive configuration and rapid response actions helped prevent escalation. This incident reinforced the importance of reducing attack surface and implementing layered access controls.


