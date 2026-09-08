# 0206: Open, Modular Malware Triage & Evidence-Driven Reporting Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-orange.svg)](https://attack.mitre.org/)
[![Status: Ready](https://img.shields.io/badge/Status-Production%20Triage-brightgreen.svg)]()

**0206** is a modular, evidence-grounded malware triage and automated forensic reporting platform designed to be completely self-contained, reproducible, portable, and privacy-safe.

A new user can clone and run **0206** in minutes without IDA Pro, Ghidra, x64dbg, WinDbg, PEView, cloud APIs, MCP servers, or proprietary courseware.

---

## ⚡ Quickstart

```bash
# 1. Clone repository
git clone https://github.com/DangGPhuc/0206.git
cd 0206

# 2. Set up virtual environment and install in editable mode
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 3. Verify environment health & platform diagnostics
0206 doctor

# 4. Run automated offline self-test
0206 selftest

# 5. Analyze sample in 100% offline mode
0206 analyze sample.exe --offline
```

---

## 🏛️ Core Architectural Philosophy

### 1. The 3-Tier Canonical Domain Model
To eliminate ungrounded claims and hallucinations, 0206 strictly separates **Observed Facts**, **Calibrated Findings**, and **Contextual Assessment**:

```
[ Tier 1: Raw Evidence Records (Facts) ]
       │  E-0020: "API Hash constant 0x382C0F97 (djb2: VirtualAlloc) at offset 0x8200"
       │  E-0027: "File dropped: C:\Users\<REDACTED_USER>\AppData\Local\Temp\payload.exe"
       │  E-0029: "Registry key written: HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
       ▼
[ Tier 2: Derived Findings (Inferences) ]
       │  F-0001: [OBSERVED] "Embedded Win32 API Hashing Constants" (citing E-0020)
       │  F-0002: [OBSERVED] "Executable Dropped to Host Filesystem" (citing E-0027)
       │  F-0003: [OBSERVED] "Registry Autostart Persistence Modification" (citing E-0029)
       ▼
[ Tier 3: Contextual Assessment (Evaluation) ]
          Score: 65/100 (HIGH) | Classification: Backdoor / Persistent Trojan
```

### 2. Evidence States
- `OBSERVED`: Directly verified in binary headers, code sections, or log streams.
- `INFERRED`: Logically deduced capability (e.g., potential packing from high entropy + 0-sized raw section).
- `NOT_CONFIRMED`: Suspected capability whose runtime execution was not validated dynamically.
- `NOT_ANALYZED`: The artifact or analysis phase was omitted.
- `NOT_AVAILABLE`: Required tool or package is not installed.

*Rule: An imported API alone never implies execution; an RWX section indicates potential capability, never confirmed injection.*

---

## 🧩 Runtime Pipeline Architecture

```mermaid
flowchart TD
    subgraph Inputs["1. Analysis Artifacts"]
        PE["PE Binary (.exe, .dll)"]
        PCAP["Network Trace (.pcap)"]
        PROCMON["Procmon Log (.csv)"]
        REGSHOT["Regshot Diff (.txt)"]
    end

    subgraph Orchestrator["2. Analysis Orchestrator"]
        RP["Resource Policy Guard"]
        MAN["AnalysisManifest (Streaming Input Hashes)"]
        ES["EvidenceStore (Atomic EvidenceRecords)"]
    end

    subgraph Analyzers["3. Ingestion Engines"]
        PEA["PEStaticAnalyzer (Headers, Sections, Entropy, Imports)"]
        DIS["CodeAnalyzer (Capstone Static Code Triage)"]
        BEH["BehavioralAnalyzer (Streaming PCAP, Beacons, Host Logs)"]
        ADAPT["Optional Tool Adapters (Tier 2 / Tier 3)"]
    end

    subgraph Correlation["4. Finding Engine & Privacy Boundary"]
        FE["FindingEngine (Evidence Grounding & Validation)"]
        DLP["PrivacyRedactor & DLP Filter\n(Scrub Usernames, Paths, Secrets)"]
    end

    subgraph Synthesis["5. Threat Synthesis"]
        AI["LLMThreatSynthesizer\n- Deterministic Offline Engine (Default)\n- Optional LLM with DLP Audit & Evidence Validation"]
    end

    subgraph Deliverables["6. Canonical Session Deliverables"]
        REP_JSON["report.json"]
        REP_MD["report.md"]
        REP_DOCX["report.docx (Built-in Generic or User Template)"]
        EV_STORE["evidence.json"]
        FIND_CAT["findings.json"]
        AUD_MAN["analysis_manifest.json (Output Lineage Hashes)"]
    end

    PE --> RP --> MAN --> ES
    PCAP --> RP --> MAN --> ES
    PROCMON --> RP --> MAN --> ES
    REGSHOT --> RP --> MAN --> ES

    ES --> PEA --> ES
    ES --> DIS --> ES
    ES --> BEH --> ES
    ES --> ADAPT --> ES

    ES --> FE
    FE --> DLP
    DLP --> AI
    AI --> REP_JSON
    AI --> REP_MD
    AI --> REP_DOCX
    ES --> EV_STORE
    FE --> FIND_CAT
    MAN --> AUD_MAN
```

---

## 🎛️ Analysis Profiles

0206 supports profiles tailored to available resources and depth requirements:

| Profile | Command Flag | Ingestion Scope | Integrations | Default AI |
| :--- | :--- | :--- | :--- | :--- |
| **minimal** | `--profile minimal` | PE headers, hashes, sections, imports, strings, Capstone triage | Built-in only | Offline (forced) |
| **standard** | `--profile standard` | Minimal + PCAP, Procmon, Regshot | YARA, capa (if installed) | Offline (configurable) |
| **full** | `--profile full` | Standard + deep disassembly & decompilation | Ghidra, radare2, pe-sieve, IDA, debuggers (if installed) | Offline (configurable) |

*Missing optional tools are skipped gracefully without failing the analysis.*

---

## 💻 CLI Commands

```bash
# Run environment & tool diagnostic doctor
0206 doctor

# View detected capability matrix
0206 capabilities

# Run automated platform self-test (synthetic benign fixture)
0206 selftest

# Analyze sample with network and process telemetry in offline mode
0206 analyze sample.exe --pcap traffic.pcap --procmon procmon.csv --offline

# Analyze with custom profile and strict privacy mode
0206 analyze sample.exe --profile standard --privacy strict

# Validate a custom DOCX report template
0206 validate-template template.docx

# Inspect an analysis audit manifest and output lineage
0206 manifest output/analysis_manifest.json
```

---

## 📦 Session Deliverables & Output Lineage

Every analysis run produces 6 canonical deliverables:

1. **`report.json`**: Machine-readable triage summary with findings and assessment.
2. **`report.md`**: Clean, human-readable Markdown summary.
3. **`report.docx`**: Professional Word document formatted using the built-in generic adapter or user-supplied template.
4. **`evidence.json`**: Complete atomic `EvidenceRecord` catalog with source provenance.
5. **`findings.json`**: All derived `Finding` objects citing verified evidence IDs.
6. **`analysis_manifest.json`**: Audit trail containing session parameters, environment specs, input artifact hashes, and output deliverable SHA256 lineage hashes.

---

## 🔒 Privacy & DLP Security Boundary

0206 implements a strict data protection boundary before presentation or remote AI enrichment:
- **Username scrubbed:** `C:\Users\JohnDoe\Desktop\sample.exe` $\rightarrow$ `C:\Users\<REDACTED_USER>\Desktop\sample.exe`
- **Linux paths scrubbed:** `/home/analyst/cases/sample.bin` $\rightarrow$ `/home/<REDACTED_USER>/cases/sample.bin`
- **Hostnames sanitized:** `DESKTOP-1234AB` $\rightarrow$ `<REDACTED_HOST>`
- **Secrets & Keys redacted:** API keys (`sk-...`), bearer tokens, and private keys (`-----BEGIN PRIVATE KEY-----`) are redacted.
- **DLP Audit:** If unredacted sensitive tokens remain prior to external transmission, `BLOCK_REMOTE_TRANSMISSION` triggers and forces deterministic offline synthesis.

---

## 🔌 Integration Architecture & MCP Contract

0206 uses an adapter-based design (`integrations/base.py`) that decouples core triage from optional external tooling:

- **Tier 1 (Core):** `pefile`, `scapy`, `capstone`, `python-docx`, `pydantic`, `rich` (100% open-source, pip-installable).
- **Tier 2 (Open Source Optional):** `YARA`, `capa`, `Ghidra`, `radare2`, `pe-sieve`, `FLOSS`.
- **Tier 3 (Proprietary Optional):** `IDA Pro`, `x64dbg`, `WinDbg`.

### Model Context Protocol (MCP) Contract
0206 includes an optional MCP contract (`integrations/mcp_contract.py`). External MCP servers or agentic tools can ingest structured evidence into 0206:
```
External MCP Server / Tool ──► MCPEvidenceIngester ──► EvidenceRecord ──► EvidenceStore
```
MCP is strictly optional; 0206 does not require an active MCP server to function.

---

## 🛡️ Resource Safety Limits

Enforced via `core/resource_policy.py`:
- `MAX_SAMPLE_SIZE`: 100 MB
- `MAX_PCAP_SIZE`: 250 MB
- `MAX_PACKETS`: 50,000 packets (processed via memory-safe streaming `PcapReader`)
- `MAX_LOG_ROWS`: 50,000 log rows
- `ANALYSIS_TIMEOUT`: 300 seconds

---

## ⚠️ Safe Malware Handling & Limitations

1. **Static & Log Telemetry Only:** 0206 does NOT execute malware binaries directly on your analysis station. Execute samples only inside an isolated virtual machine or sandbox.
2. **Heuristic Calibration:** Entropy and section metrics signal potential packing, not mathematical certainty.
3. **Static Code Triage:** Entry-point disassembly via Capstone provides fast initial triage, not full interactive decompilation.

---

## 📄 License
This platform is open source under the [MIT License](LICENSE).
