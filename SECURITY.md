# 0206 Security Policy & Architecture Guarantees

## 1. Product Identity & Safety Principles

**0206** is an automated, local-first malware-analysis platform that collects forensic observations, derives auditable evidence, correlates calibrated findings, computes deterministic threat assessments, and optionally produces an evidence-grounded report.

### Non-Negotiable Safety Constraints:
1. **Zero Hostile Detonation**: 0206 will **NEVER** execute live hostile malware on the analyst workstation. Dynamic analysis is supported strictly via external sandbox lab layers (e.g. Windows REM Workstation VMs).
2. **Zero Sample Upload**: 0206 **NEVER** uploads binary samples or executable code to external services. External reputation services (VirusTotal, MalwareBazaar, ThreatFox) are queried **strictly by cryptographic hash**.
3. **Offline & Air-Gap Friendly**: The `--offline` flag guarantees zero application-level network calls. Deterministic offline analysis operates independently without cloud connectivity or API keys.
4. **Non-Authoritative AI**: AI synthesis models (OpenAI, Anthropic, Ollama) are non-authoritative. The `GroundingValidator` and deterministic `FindingEngine` are authoritative. AI cannot alter threat scores, adjust threat levels, or invent ungrounded indicators.

---

## 2. Security Boundaries & Execution Guarantees

### Bounded External Tool Execution
When executing external tools or helper utilities:
- `shell=False` is strictly enforced.
- Arguments are passed as explicit arrays to prevent shell injection.
- Process execution is strictly bounded by timeouts.
- On POSIX platforms, subprocesses run in independent process sessions (`start_new_session=True`). On timeout, the entire process group is terminated (`os.killpg`) to eliminate orphan descendant processes.
- Process stdout and stderr are spooled directly to operating-system temporary files with strict byte limits (`MAX_STDOUT_BYTES`, `MAX_STDERR_BYTES`), preventing memory exhaustion (DoS).
- Sterile environment dictionaries are used to strip API keys, secrets, and analyst home paths from child processes.

### OS-Level Static Tool Sandbox — NOT_IMPLEMENTED
> [!WARNING]
> 0206 executes static parsing libraries (e.g., `pefile`, `capstone`, `scapy`, YARA) under the analyst host's user process space.
> 0206 does **not** currently implement a kernel-level container or OS-level sandbox for static analysis tools.
> Because hostile binaries may target vulnerabilities in parsing libraries, high-risk or adversarial samples should always be analyzed inside dedicated virtual machines or isolated analysis labs.

### Best-Effort Privacy Redaction & DLP Gate
- `PrivacyRedactor` scrubs usernames, host user paths (`C:\Users\...`, `/home/...`), hostnames, AWS keys, GitHub tokens, JWTs, database connection strings, bearer tokens, private keys, and API keys.
- **DLP Transmission Gate**: Prior to any remote AI request, the payload must pass a pre-flight DLP audit. If unredacted sensitive identifiers remain, remote transmission is immediately aborted with a fallback to offline deterministic synthesis.
- **Notice**: Regex-based redaction is best-effort. It should not be treated as a mathematically absolute confidentiality barrier on sensitive networks.

### Output Permissions & Atomic Writes
- On POSIX platforms, case output directories default to permissions `0700` and output files default to `0600`.
- Case artifacts (`report.json`, `evidence.json`, `findings.json`, `analysis_manifest.json`, etc.) are written using atomic temporary files and `os.replace` to prevent corrupted or truncated case states upon unexpected termination.

---

## 3. Reporting Security Vulnerabilities

If you discover a security vulnerability or sensitive data leakage within 0206, please report it responsibly by opening a private GitHub Security Advisory or contacting the maintainers directly.
