# Passive DNS Tunneling & DGA Anomaly Detector

A high-performance, modular network threat hunting utility engineered in Python to evaluate DNS query telemetry, detect covert data exfiltration (DNS Tunneling), and flag algorithmic C2 communications (Domain Generation Algorithms - DGA) via Shannon Entropy mathematics and structural domain tokenization.

---

## Technical Overview

Domain Name System (DNS) protocol channels (Port 53) are frequently leveraged by advanced threat actors as an out-of-band communication vector because egress DNS traffic is rarely inspected or blocked at corporate firewall boundaries.

This engine inspects Fully Qualified Domain Names (FQDNs), tokenizes labels into Second-Level Domains (SLD) and hierarchical subdomains, and runs statistical randomness evaluations to uncover covert channels and automated malware beacons.

---

## Detection Methodology & Threat Vectors

- **Shannon Entropy Mathematical Engine:** Calculates statistical information uncertainty ($H(X) = -\sum P(x_i) \log_2 P(x_i)$) across domain labels. Natural language domains exhibit lower entropy ($2.0 - 3.4$), whereas encoded exfiltration payloads and pseudo-random DGA labels exhibit high entropy ($3.8 - 4.5+$).
- **DNS Tunneling & Data Exfiltration:** Flags long subdomain streams exhibiting high cryptographic randomness (Base64/Hex encoding patterns).
- **Domain Generation Algorithms (DGA):** Detects algorithmically generated domains utilized by malware/ransomware families to communicate with dynamic Command and Control (C2) infrastructure.
- **Diagnostic Output & SIEM Reporting:** Zero-emoji, ANSI-standard telemetry with direct structured JSON export capabilities.

---

## Architectural Workflow

```text
[DNS Query Stream] ──> [Domain Tokenizer (SLD & Subdomain Separation)]
                                      │
                                      ▼
                          [EntropyCalculator Engine]
                             (Shannon Calculation)
                                      │
                                      ▼
                            [DomainAnalyzer Engine]
                      ├── Tunneling Heuristic (Len >= 25 & H >= 3.8)
                      └── DGA Heuristic (SLD Len >= 8 & H >= 3.6)
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            ▼                                                   ▼
[ANSI Diagnostic Console Alert]                     [dns_threat_report.json]
```

---

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Raihan-143/dns-threat-detector.git
   cd dns-threat-detector
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage & Execution

### Basic Execution
```bash
python main.py -f ./data/sample_dns.txt
```

### Custom Thresholds & JSON Report Export
```bash
python main.py -f ./data/sample_dns.txt -e 3.8 -l 25 -o dns_threat_report.json
```

---

## CLI Options Reference

| Argument | Description | Default |
| :--- | :--- | :--- |
| `-f`, `--file` | Path to text file containing target domain queries (Required) | `None` |
| `-e`, `--entropy` | Shannon Entropy threshold for flagging randomness | `3.8` |
| `-l`, `--length` | Subdomain character length threshold for tunneling heuristics | `25` |
| `-o`, `--output` | Destination path for structured JSON export | `None` |

---

## Author

- **Md Raihan Hasan Rana** — Cybersecurity Enthusiast