# Enterprise Penetration Testing & Attack Surface Triage Pipeline

An automated, operational security (OpSec)-compliant workflow for triaging large-scale internal security assessment data across 1,000+ hosts.

The pipeline ingests raw **Nmap XML (`-oX`)** and **Nessus (`.nessus`)** scan data, locally sanitizes sensitive identifiers, correlates exposed services with vulnerability clusters, and produces a token-efficient dataset for analysis by **Claude Enterprise**.

The final stage locally re-identifies sanitized assets to produce technical, compliance, and executive-ready deliverables.

> **Security boundary:** Raw scan data and the asset mapping key remain local. Only the sanitized, tokenized assessment summary is intended to leave the local environment.

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. LOCAL SCANNING                                           │
│    Workstation / Kali VM                                    │
│    • Nmap network discovery and service enumeration          │
│    • Nessus vulnerability assessment                         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. LOCAL FUSION & SANITIZATION                              │
│    scripts/fusion_preprocessor.py                           │
│    • Removes internal IPs, hostnames, and MAC addresses      │
│    • Correlates Nmap services with Nessus findings           │
│    • Filters low-value informational findings                │
│    • Clusters systemic vulnerabilities                       │
│                                                             │
│    ┌─────────────────────┐    ┌──────────────────────────┐  │
│    │ MAPPING_KEY.json    │    │ fused_summary.json       │  │
│    │ LOCAL ONLY          │    │ Sanitized payload        │  │
│    └─────────────────────┘    └──────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. CLAUDE ENTERPRISE                                        │
│    Custom Project / Skill                                   │
│    • Fleet triage and target prioritization                  │
│    • Attack-path analysis                                    │
│    • Vulnerability cluster analysis                          │
│    • Compliance mapping                                      │
│    • Auditor-ready finding synthesis                         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. LOCAL RE-IDENTIFICATION                                  │
│    scripts/remapper.py                                      │
│    • Restores real asset identifiers                         │
│    • Produces final stakeholder deliverables                 │
└─────────────────────────────────────────────────────────────┘
```

## Repository Structure

```text
.
├── scripts/
│   ├── fusion_preprocessor.py
│   └── remapper.py
│
├── config/
│   └── claude_instructions.md
│
├── data/
│   ├── raw_scans/
│   └── processed_scans/
│
└── reports/
```

### Directory Responsibilities

| Path                    | Purpose                                           |
| ----------------------- | ------------------------------------------------- |
| `scripts/`              | Local processing and re-identification utilities  |
| `config/`               | Claude Enterprise project instructions            |
| `data/raw_scans/`       | Raw Nmap and Nessus exports; keep local           |
| `data/processed_scans/` | Sanitized summaries and confidential mapping keys |
| `reports/`              | Draft and final assessment deliverables           |

> **Important:** Raw scan data and mapping keys should be excluded from version control.

## Prerequisites

* Python **3.9+**
* Nmap
* Nessus/Tenable export capability
* Claude Enterprise access
* Authorized access to the assessment environment

The Python preprocessing workflow uses only the standard library, including:

```text
xml.etree.ElementTree
json
collections
re
os
sys
```

## Quickstart

### 1. Execute Internal Scans

Run authorized network discovery and vulnerability assessments against the defined assessment scope.

Example Nmap service enumeration:

```bash
nmap -sV -sC -p- 10.10.0.0/20 \
  -oX data/raw_scans/internal_network.xml
```

Export the Nessus assessment from Tenable and save it locally:

```text
data/raw_scans/internal_vulnerabilities.nessus
```

Use only targets that are explicitly authorized and within the assessment scope.

### 2. Locally Fuse and Sanitize the Data

Run the preprocessing pipeline on the workstation handling the raw assessment data:

```bash
python scripts/fusion_preprocessor.py \
  data/raw_scans/internal_network.xml \
  data/raw_scans/internal_vulnerabilities.nessus \
  Q3_Assessment
```

Expected artifacts:

```text
data/processed_scans/
├── Q3_Assessment_fused_summary.json
└── Q3_Assessment_MAPPING_KEY.json
```

#### `fused_summary.json`

The sanitized, token-efficient dataset intended for downstream analysis.

It contains relational identifiers such as:

```text
TARGET_HOST_0001
TARGET_HOST_0042
TARGET_DOMAIN_0007
```

rather than the corresponding internal infrastructure identifiers.

#### `MAPPING_KEY.json`

The confidential translation layer between sanitized tokens and real assets.

**This file must remain local and must never be uploaded to the external analysis environment.**

### 3. Analyze with Claude Enterprise

Open the dedicated Claude Enterprise Project configured with:

```text
config/claude_instructions.md
```

Attach:

```text
Q3_Assessment_fused_summary.json
```

#### Mode 1 — Attack Surface Triage

Use Mode 1 to identify:

* Initial exploitation footholds
* High-priority exposed services
* Systemic vulnerability clusters
* Significant outliers
* Potential attack paths
* Recommended validation priorities

Example instruction:

```text
Analyze the attached fused dataset using Mode 1.

Identify our top initial exploitation footholds, systemic fleet
clusters, lone-wolf outliers, and tactical validation priorities.

Do not attempt to infer or reconstruct real internal IP addresses,
hostnames, MAC addresses, or other sanitized identifiers.
```

#### Mode 2 — Finding Generation

Use Mode 2 to transform prioritized findings into detailed assessment output.

Example:

```text
Draft a complete compliance-ready finding for Vulnerability
Cluster #1 and TARGET_HOST_0042 using Mode 2.

Preserve the sanitized target identifiers in the generated report.
Do not reconstruct or infer real infrastructure identifiers.
```

Save the resulting Markdown locally:

```text
reports/draft_report.md
```

### 4. Re-Identify the Final Deliverable

After reviewing the generated report, run the local remapping utility:

```bash
python scripts/remapper.py \
  reports/draft_report.md \
  data/processed_scans/Q3_Assessment_MAPPING_KEY.json \
  reports/FINAL_Q3_PENTEST_REPORT.md
```

The resulting file:

```text
reports/FINAL_Q3_PENTEST_REPORT.md
```

contains the re-identified assessment results and can be distributed according to the organization's reporting and information-handling requirements.

## Operational Security Model

### Local Sanitization

Sensitive infrastructure identifiers are removed before the assessment dataset is transferred outside the local processing boundary.

Examples include:

* Internal IP addresses
* Hostnames
* Domain names
* MAC addresses
* Other environment-specific asset identifiers handled by the preprocessing logic

### Deterministic Tokenization

Each asset receives a stable token, allowing relationships to remain intact across Nmap and Nessus data.

For example:

```text
TARGET_HOST_0042
```

continues to represent the same underlying asset throughout the sanitized dataset.

This preserves analytical context without exposing the original identifier.

### Local Re-Identification

The relationship between sanitized tokens and real assets is maintained separately in:

```text
*_MAPPING_KEY.json
```

The mapping key is used only during the final local reporting stage.

### Context Optimization

The preprocessing stage converts verbose XML-based scan output into a compact, structured representation.

This reduces unnecessary context consumption and makes large-scale fleet analysis more practical.

> Actual output size varies with scan configuration, finding density, and the amount of metadata retained. Do not assume a fixed compression ratio or payload size.

## Compliance Analysis

The workflow can be used to organize findings against applicable control frameworks, including:

* **PCI DSS 4.0**
* **SWIFT Customer Security Programme (CSP)**

Compliance mappings should be treated as assessment outputs requiring human validation against the applicable version, scope, control language, and organizational requirements.

The pipeline does **not** by itself establish compliance or replace qualified audit judgment.

## Data Handling

Recommended handling model:

```text
                    TRUST BOUNDARY
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ LOCAL ENVIRONMENT                                           │
│                                                             │
│ Raw Nmap XML ──┐                                            │
│                ├──► Fusion / Sanitization                   │
│ Raw Nessus ────┘              │                             │
│                               ├──► Mapping Key (LOCAL ONLY) │
│                               │                             │
└───────────────────────────────┼─────────────────────────────┘
                                │
                                ▼
                    Sanitized JSON Payload
                                │
                                ▼
                     External Analysis Layer
                                │
                                ▼
                       Sanitized Draft Report
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│ LOCAL ENVIRONMENT                                           │
│                                                             │
│ Sanitized Report + Mapping Key                              │
│                │                                            │
│                ▼                                            │
│        Local Re-Identification                              │
│                │                                            │
│                ▼                                            │
│       Final Assessment Report                               │
└─────────────────────────────────────────────────────────────┘
```

## Recommended `.gitignore`

At minimum, prevent raw scans, mapping keys, and generated assessment data from entering source control:

```gitignore
# Raw security assessment data
data/raw_scans/

# Processed assessment data
data/processed_scans/

# Confidential asset mapping
**/*MAPPING_KEY*.json

# Generated reports
reports/*.md
reports/*.html
reports/*.pdf

# Python artifacts
__pycache__/
*.py[cod]
```

Adjust these rules if sanitized datasets or template reports are intentionally version-controlled.

## Validation and Quality Controls

Before producing the final report:

* Verify that all scan inputs belong to the authorized assessment scope.
* Confirm that sensitive identifiers are removed from the sanitized dataset.
* Verify that the mapping key was not transmitted with the sanitized payload.
* Review AI-generated attack paths and remediation recommendations.
* Validate vulnerability severity against authoritative scanner and vendor information.
* Manually verify compliance mappings.
* Review the final re-identified report for token leakage or incorrect mappings.
* Preserve appropriate evidence and assessment provenance according to organizational policy.

## Limitations

This pipeline is an **analysis and reporting workflow**, not an autonomous penetration-testing framework.

AI-generated analysis should be treated as analyst assistance rather than authoritative evidence. In particular:

* A proposed attack path is not proof that exploitation is possible.
* Vulnerability scanner output should be independently validated where appropriate.
* Compliance mappings require qualified human review.
* Sanitization quality depends on the implementation of `fusion_preprocessor.py`.
* Re-identification accuracy depends on the integrity of the mapping key.
* The pipeline should not be used to assess systems without explicit authorization.

## End-to-End Workflow

```text
Authorized Scanning
        │
        ▼
Raw Nmap + Nessus Data
        │
        ▼
Local Fusion & Sanitization
        │
        ├──────────────► Confidential Mapping Key
        │                       │
        ▼                       │
Sanitized Assessment Dataset   │
        │                       │
        ▼                       │
Claude Enterprise Analysis     │
        │                       │
        ▼                       │
Draft Assessment Report        │
        │                       │
        └──────────────┬────────┘
                       ▼
             Local Re-Identification
                       │
                       ▼
             Final Assessment Report
```

## Security Principle

**Sensitive infrastructure identifiers stay local.**

The intended trust model is:

> **Scan locally → sanitize locally → analyze sanitized data → re-identify locally → distribute the final report according to organizational policy.**
