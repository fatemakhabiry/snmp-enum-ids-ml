# 🛡️ SNMP Enumeration Intrusion Detection System (ML-Based IDS)

## Network Security Project – Machine Learning IDS  
**Course:** Network Security – Network Penetration Testing  
**Attack Type:** SNMP Enumeration  
**Deployment:** Local Streamlit Application  
**Team:** [Add team member names]

---

## 📌 Project Overview

This project implements a **Machine Learning–based Intrusion Detection System (IDS)** to detect **SNMP Enumeration attacks** using a **self-generated dataset** captured from a real lab environment.

SNMP Enumeration is a reconnaissance attack where an attacker sends repeated SNMP queries (UDP port 161) to extract sensitive system information such as network interfaces, running services, and device details. This behavior produces abnormal traffic patterns that can be detected using machine learning.

---

## 🧪 Lab Environment

| Role     | Machine |
|----------|--------|
| Attacker | Kali Linux |
| Victim   | Windows 7 (SNMP enabled) |

- Network: Same VirtualBox internal network
- Attack Tool: `snmpwalk`
- Traffic Capture: `tshark`
- Dataset: Self-generated CSV from captured PCAPs

---

## 🔍 Attack Description – SNMP Enumeration

- Protocol: SNMP (UDP port 161)
- Type: Reconnaissance attack
- Tool used: `snmpwalk`
- Effect:
  - Generates unusually large SNMP responses
  - Longer flow duration
  - Repetitive query patterns
- Goal:
  - Extract system information from victim

---

## 📂 Dataset Creation

1. Normal traffic and attack traffic were captured separately using `tshark`.
2. PCAP files were converted into flow-based CSV records.
3. Five CSV files from different captures were merged.
4. A binary label was added:
   - `0` → Normal traffic
   - `1` → SNMP Enumeration attack

### Final Dataset
- Format: CSV
- Records: Mixed normal + attack flows
- Stored in: `data/processed/snmp_merged_dataset.csv`

---

## 🧠 Feature Engineering

Flow-level features were extracted from raw traffic:

| Feature | Description |
|-------|-------------|
| `srcport` | Source port number |
| `dur` | Flow duration (seconds) |
| `sbytes` | Total bytes sent from source |
| `sttl` | Source IP TTL |
| `dttl` | Destination IP TTL |

Features such as `service` were removed to avoid label leakage.

---

## 🎯 Feature Selection

Feature selection was performed using:

- **Correlation Analysis**
- **ANOVA F-test**

ANOVA results showed that `sbytes` is the most discriminative feature, followed by TTL values and flow duration.

Final selected features:
