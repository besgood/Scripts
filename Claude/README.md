# Enterprise Penetration Testing & Attack Surface Triage Pipeline

An automated, operational security (OpSec) compliant workflow designed to triage large-scale internal assessment data (1,000+ hosts). 

This pipeline ingests raw **Nmap XML (`-oX`)** and **Nessus (`.nessus`)** scans, scrubs all sensitive identifiers (IPs, hostnames, MACs) locally, aggregates open ports with vulnerability clusters, and leverages **Claude Enterprise** to generate attack paths, compliance mappings (PCI DSS 4.0, SWIFT CSP), and auditor-ready findings.

---## 🏗️ Architecture Overview```text
┌─────────────────────────────────────────────────────────────┐
│ 1. LOCAL SCANNING (Workstation / Kali VM)                   │
│    • Run Nmap network sweep (-oX)                           │
│    • Run Nessus vulnerability assessment (.nessus)          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. LOCAL FUSION & SANITIZATION (fusion_preprocessor.py)     │
│    • Strips all internal IPs, hostnames, and MACs           │
│    • Correlates active Nmap ports with Nessus CVEs          │
│    • Drops Low/Info noise; clusters systemic flaws          │
│    ├─────────────────────────────┬──────────────────────────┤
│    ▼                             ▼                          │
│ [MAPPING_KEY.json]          [fused_summary.json]            │
│ (Kept strictly LOCAL)       (Token-efficient payload)       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. CLAUDE ENTERPRISE (Custom Project / Skill)               │
│    • Ingests sanitized fused_summary.json (~50 KB)          │
│    • Mode 1: Fleet Triage & High-Exploit Target Ranking     │
│    • Mode 2: Auditor-Grade Finding & Remediation Synthesis  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. LOCAL RE-IDENTIFICATION (remapper.py)                    │
│    • Replaces TARGET_HOST_XXXX tokens with actual assets    │
│    • Produces final stakeholder & executive deliverable     │
└─────────────────────────────────────────────────────────────┘
📁 Repository Structure
Plaintext

.
├── scripts/
│   ├── fusion_preprocessor.py   # Combines Nmap + Nessus into sanitized JSON
│   └── remapper.py              # Restores real IPs from local key into reports
├── config/
│   └── claude_instructions.md   # System instructions for Claude Enterprise Project
├── data/                        # Local raw scans & generated mapping keys (*.gitignore*)
│   ├── raw_scans/
│   └── processed_scans/
└── reports/                     # Final Markdown assessment deliverables

🚀 Quickstart Workflow
Prerequisites
Python 3.9+
Standard libraries only (xml.etree.ElementTree, json, collections, re, os, sys)
Step 1: Execute Internal Scans
Run your standard network discovery and vulnerability scans against the in-scope target environment:
Bash

# 1. Nmap full port/service sweep
nmap -sV -sC -p- 10.10.0.0/20 -oX data/raw_scans/internal_network.xml# 2. Export Nessus scan from Tenable console# Save as: data/raw_scans/internal_vulnerabilities.nessus

Step 2: Local Pre-Processing & Sanitization
Run fusion_preprocessor.py locally to correlate the scans, strip sensitive PII/IPs, and build the compact JSON payload:
Bash

python scripts/fusion_preprocessor.py \
  data/raw_scans/internal_network.xml \
  data/raw_scans/internal_vulnerabilities.nessus \
  Q3_Assessment

Generated Artifacts:
data/processed_scans/Q3_Assessment_fused_summary.json: Token-efficient, sanitized payload ready for Claude.
data/processed_scans/Q3_Assessment_MAPPING_KEY.json: Confidential translation key. Kept strictly on your local machine.

Step 3: Claude Enterprise Triage & Finding Generation
Open your dedicated Claude Enterprise Project (configured with the instructions in config/claude_instructions.md).
Attach Q3_Assessment_fused_summary.json.
Execute Mode 1 (Attack Surface Triage):

"Analyze the attached fused dataset using Mode 1. Identify our top initial exploitation footholds, systemic fleet clusters, lone-wolf outliers, and tactical validation commands."
Execute Mode 2 (Detailed Finding Generation):

"Draft complete compliance-ready findings for Vulnerability Cluster #1 and Target Token TARGET_HOST_0042 using Mode 2."
Copy Claude's generated Markdown report to reports/draft_report.md.

Step 4: Re-Identify Deliverable
Run remapper.py to replace all TARGET_HOST_XXXX and TARGET_DOMAIN_XXXX placeholders with the actual enterprise hostnames and IPs:

Bash

python scripts/remapper.py \
  reports/draft_report.md \
  data/processed_scans/Q3_Assessment_MAPPING_KEY.json \
  reports/FINAL_Q3_PENTEST_REPORT.md

The resulting FINAL_Q3_PENTEST_REPORT.md is complete, verified, and ready for technical engineering teams, compliance auditors, and leadership.

🔒 Operational Security & Compliance Safeguards
Zero Cloud Exposure of Internal Assets: Internal IP subnets, Active Directory domain names, and hardware MAC addresses are scrubbed on your local workstation before any data leaves the boundary.
Deterministic Tokenization: Assets retain their relational context (TARGET_HOST_0001 remains consistent across both Nmap and Nessus datasets) allowing multi-vector attack path discovery without revealing raw infrastructure details.
Context Optimization: Compresses 100+ MB of verbose XML boilerplate down to a ~50 KB structured JSON payload, preventing LLM context window truncation and hallucinations.
