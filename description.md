# 🛡️ DNSentinel — Comprehensive Platform Specifications & Architecture Guide

## 📖 Executive Overview

**DNSentinel** is a production-grade, enterprise-class threat intelligence and XDR (Extended Detection and Response) platform designed specifically to monitor, analyze, detect, and mitigate DNS-layer threats in real time. Modern malware, advanced persistent threats (APTs), and ransomware actors heavily leverage the DNS protocol for:
* **DGA (Domain Generation Algorithms)**: Dynamically generating pseudo-random domains to bypass static IP or domain blacklists.
* **DNS Tunneling**: Encapsulating arbitrary protocols (e.g., SSH, HTTP, or custom command payloads) within DNS queries to bypass network firewalls.
* **Data Exfiltration**: Stealthily transmitting sensitive corporate data out of a network inside DNS label segments (subdomains or TXT/NULL record queries).
* **Command and Control (C2) Beaconing**: Intermittent check-ins by infected hosts to external controllers.

DNSentinel utilizes a multi-layered, hybrid classification framework combining **machine learning models (22-feature vector analysis)**, **passive Chrome extension capture**, **adaptive behavioral analytics**, and the **Priority Intelligence Engine (PIE)** to achieve highly accurate threat detection with zero network disruption.

---

## 🏗️ High-Level System Architecture

DNSentinel is designed as an integrated three-tier system:

```
┌─────────────────────────────────────────────────────────────┐
│                    TELEMETRY LAYER                          │
│  ┌─────────────────┐      ┌──────────────────────────────┐  │
│  │ Chrome Extension│      │      SOC Dashboard           │  │
│  │ (Manifest V3)   │      │      (Vite + React)          │  │
│  └────────┬────────┘      └──────────────┬───────────────┘  │
└───────────┼──────────────────────────────┼──────────────────┘
            │ Passive DNS (JSON HTTP)      │ Web UI (Vite Proxy)
            ▼                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    API CORE (FASTAPI)                       │
│                        Port 8001                            │
│                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────┐  │
│  │ Feature Extraction│  │ ML Predict Engine│  │ PIE Engine│  │
│  │ (22-vector parser)│  │ (RF/GradBoost)   │  │ (Priority)│  │
│  └────────┬─────────┘  └────────┬─────────┘  └─────┬─────┘  │
│           │                     │                  │        │
│           ▼                     ▼                  ▼        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │       SQLite Persistent Ledger (presentation_vault.db) │  │
│  └──────────────────────────────┬────────────────────────┘  │
└─────────────────────────────────┼───────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                   SOAR MITIGATION LAYER                     │
│                                                             │
│   ┌──────────────────────────┐  ┌────────────────────────┐  │
│   │ Local Firewall Blocklist │  │  Local DNS Sinkhole    │  │
│   │ (IP Filter Rules)        │  │  (Host Loopback)       │  │
│   └──────────────────────────┘  └────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

1. **Telemetry & Client Layer**:
   * **Chrome Extension (Manifest V3)**: Captures passive browser DNS traffic locally, performs low-latency structural heuristics, and streams event payloads back to the API.
   * **React Dashboard**: An interactive, real-time interface designed for SOC analysts, built with Vite, TailwindCSS, and Recharts. Communication with the API is handled using Server-Sent Events (SSE) for uninterrupted telemetry streams.
2. **FastAPI Backend (Python)**:
   * **Feature Extractor**: Parses DNS logs into a 22-dimensional quantitative feature vector.
   * **Classification Engine**: Houses standard ensemble models (trained on real DGA/Exfiltration datasets).
   * **Priority Intelligence Engine (PIE)**: Calculates the final triage score and actionability vector.
3. **SOAR Mitigation Layer**:
   * Kernel-level blocking of compromised client IPs and auto-sinkholing of resolved domains with automatic 24-hour rule expiration.

---

## 🖥️ Core Dashboard Components

The SOC workstations are built around a high-fidelity cyberpunk design system using vibrant palettes, glassmorphism, and responsive CSS. It consists of the following key interfaces:

* **Triage Feed**: A live, auto-scrolling telemetry table streaming DNS query events. Events are enriched with priority badges (`Critical`, `High`, `Medium`, `Low`), Shorthand MITRE attack tags, and contextual explanations.
* **Topology Map**: A force-directed graphical network layout that maps relationships between local client IPs and external query domains. This helps identify massive beaconing trees and 1-to-many communication clusters.
* **Threat Hunter**: A search/query interface executing custom Domain Specific Language (DSL) patterns against historical logs, offering statistical baselining (`mean + k·σ`) to highlight outliers.
* **Containment Audit**: Shows active SOAR enforcement rules, including currently blocked client IPs and sinkholed C2 domains, along with their automatic cool-down and expiration schedules.
* **Live Intel Ticker**: A continuous Bloomberg-style marquee strip running across the header, displaying active threat indicators and real-time network intelligence feeds.
* **Cyberpunk Splash Screen**: An animated system boot diagnostic sequence simulating authentication protocols, module loading, and SQLite database validation on initial page loads.

---

## 🧠 Machine Learning Engine & Feature Engineering

Every DNS query received is processed through `features.py` to extract **22 features** characterizing its structure, randomness, and temporal behavior:

### 1. The 22-Dimensional Feature Vector
* **entropy**: Shannon entropy measuring structural randomness of the query string.
* **length**: Total character length of the query.
* **subdomain_length**: Length of the subdomain label.
* **ngram_score**: Bi-gram frequency score mapped against standard English language models.
* **frequency**: Short-term temporal query rate tracking (queries per minute for the client IP).
* **consonant_ratio**: Density of consonants relative to string length.
* **digit_ratio**: Density of numbers `0-9` relative to string length.
* **unique_char**: Ratio of unique characters to length.
* **vowels_consonant_ratio**: Ratio of vowels to consonants.
* **max_continuous_numeric_len**: Longest consecutive numerical run.
* **max_continuous_alphabet_len**: Longest consecutive alphabetical run.
* **max_continuous_consonants_len**: Longest consecutive consonant run.
* **max_continuous_same_char**: Longest consecutive run of the exact same character.
* **upper_count**: Number of uppercase characters.
* **lower_count**: Number of lowercase characters.
* **special_count**: Number of special characters (`-`, `_`, etc.).
* **labels**: Count of dot-separated segments in the domain name.
* **labels_max**: Maximum length of a single dot-separated label.
* **labels_average**: Average label segment length.
* **entropy_to_length_ratio**: Shannon entropy divided by total length.
* **high_entropy_flag**: Binary indicator specifying if entropy exceeds `3.8`.
* **domain_complexity**: Polynomial metric: `(length * entropy) - (ngram_score * 10)`.

### 2. Model Architecture
The system trains and runs a hybrid ensemble model consisting of:
* **Logistic Regression**: High-speed linear classifier serving as a baseline.
* **Gradient Boosting Classifier**: Captures sequential tree splits and hard-to-separate non-linear thresholds.
* **Random Forest Classifier**: Primary ensemble model tuned via `RandomizedSearchCV` on a real-world exfiltration dataset (700+ rows).

### 3. High-Precision Deep Training (`train_dga.py`)
For sequence-based modeling of DGA, the system utilizes a precise training script incorporating:
* **AdamW Optimizer**: Integrates weight decay (L2 regularization) directly into the optimization step, avoiding model drift on benign domains.
* **ReduceLROnPlateau Scheduler**: Surges convergence efficiency by dynamically halving the learning rate when validation loss plateaus.
* **Gradient Clipping**: Restricts gradients to a maximum norm of `1.0` during training, preventing gradient explosion on variable-length domain sequences.

---

## 🧮 Priority Intelligence Engine (PIE) Formulation

The core innovation of DNSentinel is the **Priority Intelligence Engine (PIE)**. In modern enterprise SOC configurations, pure ML anomaly scores generate alert fatigue. PIE translates raw risk probabilities into a triage framework based on threat severity, asset impact, and exploitability context.

### 1. Score Aggregation
The overall priority score is computed as:

$$\text{PIE Score} = \min\left(\max\left(W_{\text{risk}} \cdot S_{\text{risk}} + W_{\text{intel}} \cdot S_{\text{intel}} + W_{\text{asset}} \cdot S_{\text{asset}} + W_{\text{behavior}} \cdot S_{\text{behavior}} + W_{\text{attack}} \cdot S_{\text{attack}}, \; 0\right), \; 100\right)$$

* **Weights Configuration**:
  * $W_{\text{risk}} = 0.35$: Machine Learning structural anomaly score.
  * $W_{\text{intel}} = 0.25$: Reputation feed hits (VirusTotal, AbuseIPDB).
  * $W_{\text{asset}} = 0.20$: Crucial server importance index (Domain Controller > isolated laptop).
  * $W_{\text{behavior}} = 0.10$: Temporal rate velocity anomaly.
  * $W_{\text{attack}} = 0.10$: Severity boost according to attack type.
* **Attack Type Scale ($S_{\text{attack}}$)**:
  * `exfiltration`: $90/100$ (Critical outbound risk)
  * `tunneling`: $70/100$ (High threat - command shells)
  * `DGA`: $40/100$ (Medium threat - malware beaconing)
  * `normal`: $0/100$ (No threat)

### 2. Composite Incident Prioritization Index
For upstream SIEM ingest, the platform calculates a composite exposure index:

$$\text{Composite Incident Rating} = (0.40 \cdot \text{Priority}) + (0.35 \cdot \text{Impact}) + (0.25 \cdot \text{Exploitability})$$

### 3. Triage Priorities & Automatic SOAR Playbooks
The PIE score resolves to one of four actionable tiers:

| Score | Priority | Action Policy | SOAR Playbook Action |
|---|---|---|---|
| **$\ge 85$** | **🔴 CRITICAL** | Full SOC Workstation Intercept Popup | **IP Block**: Automatically triggers local firewall rules to isolate client source IP. |
| **$70\text{--}84$** | **🟠 HIGH** | Prioritized in Hunter Workbooks | **Domain Sinkhole**: Automatically redirects queries to `127.0.0.1`. |
| **$50\text{--}69$** | **🟡 MEDIUM** | Standard Analyst Triage Queue | Log for ML retraining pipelines; human-in-the-loop review. |
| **$< 50$** | **🟢 LOW** | Passive Audit Logging | Silent persistence to sqlite `dns_logs` table. |

### 4. Dual-Tier Deployment Architecture
* **Server-Side Engine (`pie_engine.py`)**: Fully integrated into the FastAPI workflow. Calculates scores using real-time threat intelligence queries (AbuseIPDB/VirusTotal) and internal database asset records.
* **Client-Side Engine (`heuristics.js`)**: Runs in the passive Chrome extension. Since it operates disconnected from live backend databases, it uses an optimized local JavaScript heuristic scoring model (`Entropy * 12 + Length penalty + Digit Ratio * 35`) to assess risk in **<5ms** for prompt UI feedback.

---

## 🚨 SOAR Orchestration & Threat Intelligence

* **Auto-Blocking (IP_BLOCK)**: Restricts egress connectivity for compromised hosts. Block entries are managed via `actions.py` and saved to `security_rules` with an active expiration epoch.
* **Sinkholing (DOMAIN_SINKHOLE)**: Configures rules targeting specific malicious domains, redirecting local client lookup traffic back to loopback addresses.
* **Automated Cleanup**: A continuous background routine (`soar_maintenance`) scans active rules, purging firewall blocks and sinkhole redirect rules precisely 24 hours after containment, preventing persistent network blockades.
* **Threat Intel Feeds**: Built-in async connector integrating VirusTotal v3 API and local reputation heuristics to flag known malicious IPs and malware domains.

---

## 📄 Forensic Auditing & Export Capabilities

DNSentinel records historical traffic logs to support compliance reviews and Incident Response (IR) reporting:
* **Interactive Incident Reports**: Generates detailed, markdown-formatted forensic worksheets containing feature maps, MITRE ATT&CK technique details, and recommended containment advice.
* **PDF Report Generation**: Exports professional-grade SOC incident audit ledgers (using the Python `fpdf` package) featuring dark executive layouts, KPI stats tables, and risk level charts.
* **CSV Bulk Ledger Export**: Exposes endpoints for extracting structured incident history logs to integrate directly into secondary SIEM tools (e.g., Splunk or Elastic Security).

---

## ⚙️ Setup & Configuration Files

The platform utilizes environment variables and configuration files to manage operational parameters:

* **`.env`**:
  * `VIRUSTOTAL_API_KEY`: API token for VirusTotal telemetry query.
  * `OPENAI_API_KEY`: Optional API token for generating LLM-powered incident advice.
  * `REDIS_URL`: Endpoint for high-speed caching (optional, falls back gracefully to local variables).
  * `MODEL_PATH`: Directory location pointing to active ensemble model file (`models/dns_model.pkl`).
* **`config/risk_weights.yaml`**:
  * Adjusts the mathematical weights of the risk scoring engine ($W_{\text{ml}}$, $W_{\text{entropy}}$, $W_{\text{query\_rate}}$, $W_{\text{reputation}}$) and configures the standard deviation threshold factor ($k\_factor$).
