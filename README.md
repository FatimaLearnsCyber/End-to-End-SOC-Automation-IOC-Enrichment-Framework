# End-to-End-SOC-Automation-IOC-Enrichment-Framework
*Windows 11 Endpoint | Wazuh | Shuffle SOAR | VirusTotal | TheHive*


## Project Overview
*This project demonstrates the design and deployment of a fully automated Security Operations pipeline from endpoint event generation to alert enrichment, case creation, and analyst notification.*

![Architecture Diagram](architecture-diagram.png)

The objective was to build a working detection architecture where:
* A Windows 11 endpoint generates telemetry
* Wazuh ingests and analyzes security events
* Custom detection rules identify suspicious behavior
* Shuffle (SOAR) automates alert processing
* VirusTotal enriches Indicators of Compromise (IOCs)
* TheHive creates structured investigation alerts
* Email notifications inform the SOC analyst

This lab simulates how modern SOC environments integrate SIEM, SOAR, and Threat Intelligence platforms into a unified detection workflow.

## Value & Impact of the Lab
Modern SOC environments rely on automation to reduce analyst fatigue and accelerate incident response.  
This framework demonstrates how SIEM, SOAR, and threat intelligence platforms can be integrated to transform raw endpoint telemetry into actionable investigation cases.

---

## Lab Architecture 
### Environment Components

| Component | Role |
| :--- | :--- |
| **Windows 11 VM** | Endpoint (Wazuh Agent Installed) |
| **Ubuntu Server 1** | Wazuh Indexer + Manager + Dashboard |
| **Ubuntu Server 2** | TheHive + Elasticsearch + Cassandra |
| **Shuffle** | SOAR Automation Platform |
| **VirusTotal** | IOC Enrichment Service |

**Network Mode:** Bridged Adapter 
\
All systems were configured to communicate across the same network.

---

## Phase 1 — Wazuh Deployment

### Install Wazuh (All-in-One)
```bash
curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh
sudo bash wazuh-install.sh -a
```
**What this does:**
* Downloads official Wazuh installer
* Installs:
  * Wazuh Indexer (stores and indexes logs)
  * Wazuh Manager (analysis engine)
  * Wazuh Dashboard (web interface)

### Extract Credentials
```bash
sudo tar -xvf wazuh-install-files.tar
cat wazuh-passwords.txt
```
Purpose:
* Retrieves auto-generated admin credentials for dashboard login.

### Access Dashboard
```bash
https://<WAZUH-IP>
```
Login using extracted credentials.

---

## Phase 2 — TheHive Deployment
TheHive required:
* Elasticsearch (data indexing backend)
* Cassandra (database backend)
* TheHive service (case management interface)

### Manage Services
```bash
sudo systemctl status elasticsearch
sudo systemctl start cassandra
sudo systemctl restart thehive
```
Purpose:
* Ensures all services are running correctly before use.

### Access TheHive
```bash
http://<THEHIVE-IP>:9000
```
Default credentials:
* admin@thehive.local
* password: secret

Created:
* Organization
* Analyst account
* Service account (for Shuffle API integration)

---

## Phase 3 — Windows Endpoint & Wazuh Agent
From Wazuh dashboard:

**1.** Deploy New Agent
<br>
**2.** Select Windows
<br>
**3.** Enter Wazuh Server IP
<br>
**4.** Copy generated installation command

Execute in Windows PowerShell (Administrator).

Start agent service:
```bash
net start wazuh-svc
```
Purpose:
* Activates agent
* Begins forwarding endpoint telemetry to Wazuh Manager

---

## Phase 4 — Attack Simulation (Mimikatz)
Downloaded Mimikatz from official repository.

Executed:
```bash
.\mimikatz.exe
```
Purpose:
* Simulate credential dumping behavior
* Generate high-confidence malicious telemetry

---

## Phase 5 — Custom Detection Engineering
Edited:
```bash
/var/ossec/etc/rules/local_rules.xml
```
Created custom rule to detect:
* Mimikatz execution
* Suspicious process behavior
* Related Event IDs

Restarted Wazuh to apply rules.

---

## Phase 6 — Shuffle (SOAR) Automation Workflow
Created automated workflow:

Trigger:
* Wazuh Alert Webhook

**Workflow Actions:**

**1.** Extract SHA256 hash via Regex
<br>
**2.** Query VirusTotal API
<br>
**3.** Retrieve reputation score
<br>
**4.** Create alert in TheHive
<br>
**5.** Send email notification to SOC analyst

---

## VirusTotal Integration
Generated API key and authenticated inside Shuffle.

Purpose:

- Automatically enrich file hashes
- Retrieve community detection ratio
- Provide IOC intelligence context

---

## TheHive Integration
Authenticated using service account API key.

Configured “Create Alert” module to populate:
- Title
- Description
- Severity
- Observables (hashes, IPs)
- Source host
- Detection rule ID

Confirmed alerts appeared automatically inside TheHive dashboard.

---

## Email Notification

Configured Shuffle email node to:
- Send alert summary
- Include hash + severity + endpoint details
- Notify SOC analyst for review

---

## Validation & Testing
Performed additional validation:

- Renamed Mimikatz executable
- Re-executed test

Result:
\
Detection still triggered due to metadata and process behavior analysis.

Verified:
- Process creation logs
- SHA256 hash extraction
- VirusTotal enrichment
- Automated case creation
- Email delivery confirmation

---

## What This Project Demonstrates
- SOC architecture design
- SIEM + SOAR integration
- Detection rule engineering
- IOC enrichment automation
- Threat intelligence integration
- Case management workflow automation
- Endpoint telemetry monitoring
- Cross-platform system troubleshooting

---

## Screenshots & Full Walkthrough
Complete step-by-step screenshots (86 images) documenting:
- Installation
- Configuration
- Errors encountered
- Workflow creation
- Alert validation
- Troubleshooting process

Available in:

[All Screenshots](./screenshots/)

## Key Technical Lessons
- Automation reduces manual triage effort
- Hash reputation adds contextual intelligence
- File renaming does not bypass behavioral detection
- Distributed SOC systems require precise configuration
- Troubleshooting builds real operational expertise
