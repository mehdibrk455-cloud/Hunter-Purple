# Hunter — Automated Purple Team & Defensive Hardening Suite

[![Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)]()
[![Security](https://img.shields.io/badge/Focus-Purple%20Team%20%26%20Defensive%20Hardening-red.svg)]()

> **Hunter** is an enterprise-grade, high-performance **Purple Team & Defensive System Hardening CLI** developed in 100% memory-safe Rust. It bridges the gap between proactive security posture assessment and immediate, automated host remediation.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Architecture & Modules](#-architecture--modules)
  - [Module 1: OWASP Top 10 Web Application Audit](#1-owasp-top-10-web-application-audit)
  - [Module 2: Host Posture & AV/EDR Compliance](#2-host-posture--avedr-compliance)
  - [Module 3: Automated Remediation Playbooks](#3-automated-remediation-playbooks)
- [One-Command Installation (Linux / Ubuntu)](#-one-command-installation-linux--ubuntu)
- [Building from Source (Windows & Linux)](#-building-from-source)
- [Command Reference & Usage](#-command-reference--usage)
- [Available Security Scenarios Catalog](#-available-security-scenarios-catalog)
- [Ethics & Compliance](#-ethics--compliance)

---

## 🌟 Key Features

- **🌐 OWASP Top 10 Automated Probe Engine**: Sequentially evaluates 10 web attack surfaces (Broken Access Control, Cryptographic Failures, Injection Resilience, Rate Limiting, Security Misconfigurations, Outdated Components, Auth Failures, Software/Data Integrity, Logging & Monitoring, SSRF).
- **🛡️ 14 Native Host & AV/EDR Posture Checks**: Inspects real-time antivirus engines, benign EICAR on-access quarantining, anti-ransomware Controlled Folder Access, AMSI registration, LSASS memory protection (RunAsPPL), Network Protection against C2 callback domains, script block logging (EID 4104), and host firewall profiles.
- **⚡ Interactive Remediation Playbooks**: When a security control fails, Hunter immediately proposes the official system countermeasure. Upon user confirmation (`y`), Hunter deploys the defensive shield and **automatically verifies** that the endpoint is now protected (`[✓] CONFIRMED`).
- **🌍 Native Bilingual Support**: Default professional English with comprehensive French localization triggered on-demand via `-fr` or `--fr`.
- **🎨 Card-Based Visual Reporting**: High-contrast, boxed terminal cards with ANSI color highlights (`[SECURE]`, `[WARNING]`, `[NON-COMPLIANT]`, `[ERROR]`), automatic text-wrapping, and zero formatting bleed.

---

## 🏛️ Architecture & Modules

```
+-------------------------------------------------------------------------+
|                                HUNTER                                   |
|                Universal Web Audit & Host Defense Suite                 |
+------------------------------------+------------------------------------+
                                     |
         +---------------------------+---------------------------+
         |                                                       |
         v                                                       v
+---------------------------------+     +---------------------------------+
|  Module 1: OWASP Web Auditor   |     | Module 2: Host Auto-Defend Engine|
|  - 10 Safe Web Compliance Probes|     | - 14 Host & Antivirus Checks    |
|  - Real HTTP Latency Tracking   |     | - Real-Time Interception Verification
|  - HTTP Status Code Analysis    |     | - Benign EICAR Sandbox Injection |
+---------------------------------+     +----------------+----------------+
                                                         |
                                                         v
                                        +---------------------------------+
                                        | Module 3: Remediation Playbooks |
                                        | - PowerShell Defender Hardening |
                                        | - Netsh / UFW Host Firewall     |
                                        | - Automatic Post-Recheck Cycle  |
                                        +---------------------------------+
```

### 1. OWASP Top 10 Web Application Audit
Sends benign, standard RFC-compliant HTTP probes with millisecond latency measurement to evaluate defensive controls without ever exploiting vulnerabilities:
- `A01` Broken Access Control (`.git` metadata exposure)
- `A02` Cryptographic Failures (Enforced TLS transport)
- `A03` Injection Flaws (Unhandled 5xx server syntax errors)
- `A04` Rate Limiting (Burst connection threshold resilience)
- `A05` Security Misconfiguration (Exposed `.env` environment files)
- `A06` Vulnerable Components (Sensitive server signature disclosure)
- `A07` Identification & Authentication (Empty credential rejection)
- `A08` Software & Data Integrity (CORS wildcard policies)
- `A09` Security Logging & Monitoring (Standard RFC 404 responses)
- `A10` Server-Side Request Forgery (Local proxy loopback reflection)

### 2. Host Posture & AV/EDR Compliance
Probes whether the host environment enforces modern defense-in-depth policies before attackers can land on disk.

### 3. Automated Remediation Playbooks
When a control fails, Hunter does not leave the operator stranded. It offers an interactive deployment prompt:
```
[*] Failed Scenario: [firewall_policy]
    Recommended Action: Enable Windows Firewall on all network profiles
Do you want Hunter to deploy the defensive shield to counter this risk? (y/n) : y
[*] Applying remediation...
[+] SUCCESS: Windows Firewall enabled on Domain, Private, and Public profiles.

[*] Running automatic post-remediation verification by Hunter...
[✓] CONFIRMED: Defensive countermeasure is active and now successfully protecting the system!
```

---

## 🚀 One-Command Installation (Linux / Ubuntu)

To install Hunter globally on any Ubuntu or Debian-based machine:

```bash
# 1. Clone repository
git clone https://github.com/your-username/Hunter.git
cd Hunter

# 2. Run automated installer with root privileges
sudo bash install.sh
```

The script will automatically:
1. Verify `sudo` / root credentials.
2. Install dependencies: `build-essential`, `libpcap-dev`, `pkg-config`, `libssl-dev`, `curl`.
3. Set up the Rust toolchain (via `rustup` if missing).
4. Compile an optimized release binary with stripped symbols (`cargo build --release`).
5. Deploy the executable globally to `/usr/local/bin/hunter`.
6. Make it immediately available system-wide via the `hunter` command.

---

## 🔨 Building from Source

### On Linux
```bash
cargo build --release
sudo cp target/release/Hunter /usr/local/bin/hunter
sudo chmod +x /usr/local/bin/hunter
```

### On Windows (PowerShell)
```powershell
cargo build --release
.\target\release\Hunter.exe --auto-defend help -fr
```

---

## 💻 Command Reference & Usage

### 1. View the Detailed Scenarios Catalog & Help
Displays boxed visual cards describing every available scenario, what it concretely tests, and what defensive shield Hunter deploys.

```bash
# English (Default)
hunter --auto-defend help

# French
hunter --auto-defend help -fr
```

### 2. Quick List of Checks
```bash
hunter --list-checks -fr
```

### 3. Web Application OWASP Top 10 Audit
Runs all 10 defensive compliance probes against a target URL:

```bash
# English
hunter -owasp http://localhost:3000

# French
hunter -owasp http://localhost:3000 -fr
```

### 4. Evaluate Host Compliance (Auto-Defend)
Execute an individual scenario or run all 14 scenarios sequentially:

```bash
# Test Antivirus Real-Time File Interception (EICAR)
sudo hunter --auto-defend localhost -check eicar_quarantine -fr

# Test Anti-Ransomware Shield (Controlled Folder Access)
sudo hunter --auto-defend localhost -check ransomware_shield -fr

# Run Complete Full Pass Across All 14 Scenarios
sudo hunter --auto-defend localhost -check all -fr
```

---

## 📋 Available Security Scenarios Catalog

| Scenario ID | Target Surface | Concrete Evaluation Test | Defensive Remediation Shield |
| :--- | :--- | :--- | :--- |
| `eicar_quarantine` | Antivirus Engine | Writes standard benign EICAR string to disk and tracks if AV quarantines it | Activates Real-Time Antivirus Protection shield |
| `realtime_protection` | Antivirus Status | Queries background antivirus engine and behavioral monitoring health | Forces background engine service startup |
| `behavior_monitoring` | Heuristics | Validates heuristic process surveillance against fileless execution | Deploys active behavioral process monitoring policy |
| `cloud_protection` | Threat Intel | Checks Microsoft Defender Cloud (MAPS) zero-day threat intelligence link | Enables Advanced MAPS cloud protection and safe sample submission |
| `network_protection` | Network / C2 | Verifies Exploit Guard network protection against rogue domains & C2 | Switches Network Protection shield to full 'Enabled' blocking mode |
| `ransomware_shield` | User Directories | Checks if Controlled Folder Access is locking user files from encryption | Enables Controlled Folder Access shield in locked mode |
| `tamper_protection` | Antivirus Integrity | Verifies Tamper Protection prevents malware from turning off security tools | Guides administrator through Windows Security Center lock |
| `amsi_integrity` | In-Memory Scripts | Checks AMSI provider registry hive for memory script inspection | Executes System File Checker (SFC) repair against `amsi.dll` |
| `pua_protection` | Software Hygiene | Verifies blocking of Potentially Unwanted Apps, adware and coinminers | Configures PUAProtection policy to 'Enabled' mode |
| `credential_guard` | Memory / LSASS | Verifies LSASS runs in Protected Process Light (RunAsPPL) mode | Injects LSA RunAsPPL=1 registry setting to isolate LSASS memory |
| `script_block_logging` | Script Telemetry | Checks deep PowerShell script block logging (EID 4104) for EDR/SOC | Deploys ScriptBlockLogging policy in system machine hive |
| `usb_scanning` | Removable Drives | Verifies antivirus scans external USB media immediately upon insertion | Enforces mandatory automatic scan on removable drives |
| `signature_freshness` | Virus Signatures | Measures definition age in days and flags overdue threat updates | Forces immediate signature update from security update servers |
| `firewall_policy` | Host Network | Checks host firewall state on Domain, Private, and Public profiles | Restores host firewall profiles with default inbound deny rule |
| `all` | Full Host Audit | Sequentially runs all 14 compliance evaluations | Interactively offers remediation for each failed control |

---

## ⚖️ Ethics & Compliance

Hunter is built strictly in accordance with ethical Purple Teaming and defensive DevSecOps compliance standards:
- **Zero Weaponized Exploits**: Hunter does not drop malware, exploit vulnerabilities, or use destructive payloads.
- **Benign Verification**: Filesystem tests strictly rely on the standard, harmless [EICAR](https://www.eicar.org/) test string recognized worldwide by antivirus vendors.
- **Consent-Driven Remediation**: All system hardening changes require explicit interactive operator confirmation (`y/n`) prior to execution.
- **Auditable**: All checks are completely transparent, reproducible, and verifiable by security administrators.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
