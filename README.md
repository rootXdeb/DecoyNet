# DecoyNet: Adaptive Cyber Deception Platform

## Overview

DecoyNet is an intelligent cyber deception platform designed to detect and analyze malicious activities within a network environment. The system simulates real network services and resources to attract potential attackers, allowing security teams to observe attacker behavior, collect threat intelligence, and identify suspicious activities in a controlled environment. By combining deception techniques with machine learning-based analysis, DecoyNet helps improve threat visibility and incident response capabilities.

---

## Problem Statement

Traditional security solutions often focus on detecting known threats but may struggle to identify new or sophisticated attack techniques. Organizations also face challenges in understanding attacker behavior and gathering actionable threat intelligence. DecoyNet addresses these issues by creating realistic decoy services that lure attackers, enabling the collection of valuable attack data for analysis and defense improvement.

---


## Key Features

* Multi-service honeypot environment that emulates real network services.
* Real-time monitoring and logging of attacker activities.
* Machine learning-based threat classification and analysis.
* Threat scoring to help prioritize security incidents.
* Interactive dashboard for security monitoring and visualization.
* Automated alert generation for suspicious activities.
* Attack data collection for forensic and threat intelligence purposes.
* Centralized reporting and analysis of captured events.

---

## Installation and Usage

### Prerequisites

Before installing DecoyNet, ensure the following are available:

* Python 3.9 or higher
* Git
* Pip package manager
* Virtual environment (recommended)

### Installation

Clone the repository:

```bash
git clone https://github.com/rootXdeb/DecoyNet.git
cd DecoyNet
```

Create and activate a virtual environment:

```bash
python -m venv venv
```

For Windows:

```bash
venv\Scripts\activate
```

For Linux/macOS:

```bash
source venv/bin/activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

### Running the Application

Start the application using:

```bash
python app.py
```

After the server starts, open your browser and navigate to:

```text
http://127.0.0.1:5000
```

### Usage

1. Launch the DecoyNet platform.
2. Configure the honeypot services and monitoring options.
3. Allow the system to listen for incoming connections and interactions.
4. Monitor attacker activities through the dashboard.
5. Review generated alerts, threat scores, and captured logs.
6. Analyze collected data to gain threat intelligence and improve security defenses.

---

## Architecture

```
Attacker hits any port
        ↓
Protocol listener captures session (SSH/HTTP/FTP/Telnet/MySQL/Redis/
                                     SMTP/RDP/SMB/MongoDB/Elastic/VNC)
        ↓
BehaviorProfiler builds live feature vector
        ↓
ML Engine:
  KMeans        → which attack cluster?
  IsolationForest → is this anomalous?
  DecisionTree  → bot / human / advanced?
        ↓
StrategyEngine selects: DEFLECT / OBSERVE / ENGAGE / TRAP
        ↓
Response adapts — same command, different content per strategy
        ↓
SIEM output: JSON + CEF + Syslog simultaneously
        ↓
Alert fires to Slack/email if CRITICAL
        ↓
Session saved → ML retrains → next attacker gets smarter response
```

---

## Protocol Coverage

| Protocol      | Port  | What it captures                          |
|---------------|-------|-------------------------------------------|
| SSH           | 2222  | Full adaptive shell, credential harvest   |
| HTTP          | 80    | SQL injection, path traversal, web shells |
| FTP           | 21    | Anonymous login, brute force, uploads     |
| Telnet        | 23    | Mirai botnet, IoT attacks                 |
| MySQL         | 3306  | Database brute force                      |
| Redis         | 6379  | RCE via cron injection                    |
| SMTP          | 25    | Spam relay, phishing infrastructure       |
| RDP           | 3389  | BlueKeep scanners, ransomware recon       |
| SMB           | 445   | EternalBlue/WannaCry attempts             |
| MongoDB       | 27017 | Exposed database attacks                  |
| Elasticsearch | 9200  | Data theft, index enumeration             |
| VNC           | 5900  | Remote desktop brute force                |

---

## ML Models

| Model           | Purpose                        | Metric          |
|-----------------|--------------------------------|-----------------|
| K-Means         | Group attack behaviour clusters| Silhouette Score|
| Isolation Forest| Detect unknown attack patterns | Detection Rate  |
| Decision Tree   | Classify attacker type         | F1-Score        |

Models retrain automatically every hour from live session data.

---

## Adaptive Strategy Engine

| Strategy | Triggered by         | Response behaviour                    |
|----------|----------------------|---------------------------------------|
| DEFLECT  | Bot/scanner detected | Minimal, slightly wrong responses     |
| OBSERVE  | Unknown attacker     | Normal responses, collect intel       |
| ENGAGE   | Human confirmed      | Surface fake credentials and secrets  |
| TRAP     | Advanced attacker    | Targeted bait matched to their interest|

---

## SIEM Integration

| Output              | File/Destination       | Compatible With                    |
|---------------------|------------------------|------------------------------------|
| JSON events         | logs/events.json       | Elastic, Logstash, Graylog         |
| CEF events          | logs/events.cef        | Splunk, QRadar, ArcSight           |
| Syslog              | UDP/TCP port 514       | Any SIEM                           |

Configure in config.py:
```python
SIEM_SYSLOG_HOST = "192.168.1.100"   # your SIEM IP
SLACK_WEBHOOK    = "https://hooks.slack.com/..."
ALERT_EMAIL      = "soc@company.com"
```

---

## Dashboard Pages

| Page        | URL              | Content                              |
|-------------|------------------|--------------------------------------|
| Dashboard   | /                | Live stats, charts, recent sessions  |
| Attacks     | /attacks         | Full attack log with filters         |
| Clusters    | /clusters        | ML clustering and protocol breakdown |
| Reports     | /reports         | Daily threat reports, ML metrics     |
| API Docs    | /api/docs        | All REST endpoints documented        |

---

## Docker Deployment

```bash
docker-compose up
```

All 12 DecoyNet ports + dashboard start automatically.

---

## Project Structure

```
DecoyNet_platform/
├── ssh_engine/       Real Paramiko SSH server + adaptive shell
├── protocols/        HTTP, FTP, Telnet, MySQL, Redis, SMTP,
│                     RDP, SMB, MongoDB, Elasticsearch, VNC
├── adaptive/         Strategy engine, behavior profiler,
│                     response library, engagement traps
├── ml_engine/        K-Means, Isolation Forest, Decision Tree
├── analysis/         Threat scorer, attack chain, IOC extractor
├── correlation/      Cross-session attacker memory
├── siem/             JSON, CEF, Syslog output
├── alerts/           Email, Slack, webhook alerts
├── reports/          Daily HTML + JSON threat reports
├── intelligence/     Knowledge base, IOC manager
├── malware/          Safe capture, static analysis
├── database/         SQLite with full schema
├── dashboard/        Flask UI + REST API
├── evaluation/       ML evaluation + attacker simulator
└── security/         Firewall + hardening scripts
```

---

## Ports to Open (Port Forwarding)

Open all DecoyNet ports publicly. Keep port 5000 private.

```
2222, 80, 21, 23, 3306, 6379, 25, 3389, 445, 27017, 9200, 5900
```

---

## Market Position

| | Cowrie / T-Pot | Attivo / Illusive | DecoyNetAI |
|--|--|--|--|
| Adaptive ML responses | ❌ | ✅ | ✅ |
| Multi-protocol unified | ❌ | ✅ | ✅ |
| Built-in SIEM output | ❌ | ✅ | ✅ |
| Cross-session memory | ❌ | ✅ | ✅ |
| Automated reports | ❌ | ✅ | ✅ |
| One command deploy | ❌ | ❌ | ✅ |
| Affordable | ✅ | ❌ | ✅ |

