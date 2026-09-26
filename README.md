# REVIVER 🛡️🔬
### Autonomous Digital Forensics, Data Carving & Neural Incident Response Suite

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![GUI-CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter%20v5.2-brightgreen.svg)](https://github.com/TomSchimansky/CustomTkinter)
[![DFIR-Ready](https://img.shields.io/badge/DFIR-Court%20Admissible-crimson.svg)](#chain-of-custody--cryptographic-ledger)
[![Architecture-Offline%20First](https://img.shields.io/badge/Architecture-Offline%20First-purple.svg)](#system-architecture)

**REVIVER** is an elite, standalone desktop digital forensics and incident response (DFIR) command center built in Python. Designed for incident responders, federal forensic analysts, and cybersecurity teams, Reviver automates the deep sector carving, cryptographic verification, fragment graph reconstruction, and AI-assisted analysis of corrupted, shredded, or deleted evidentiary data.

---

## ⚡ Quickstart & Hackathon Judge Execution

Reviver requires **zero complex setup** and is fully functional offline out-of-the-box.

### 1. Prerequisites
- **Python 3.10+** (64-bit recommended)
- Windows 10/11, Linux, or macOS

### 2. Dependency Installation
From the root workspace directory, run:
```bash
pip install -r requirements.txt
```
*(Dependencies: `customtkinter>=5.2.0`, `pillow>=10.0.0`, `requests>=2.28.0`, `python-dotenv>=1.0.0`)*

### 3. Launching the Desktop Application
You can launch Reviver immediately using any of the following methods:

**Method A: 1-Click Windows Batch Launcher**
```cmd
run.bat
```

**Method B: Direct Python Launch**
```bash
cd calmstacks-reconstructor
python app.py
```

**Method C: Root NPM Workspace Trigger**
```bash
npm run dev
```

---

## 🧪 Forensic Verification & Evaluation Workflow

Reviver includes a dedicated, 100% reproducible **forensic mock disk sandbox** (`create_sandbox.py` → `test_disk.img`) that gives judges a controlled environment to verify all carving, graph stitching, and integrity algorithms:

### 1. Generate or Inspect the Sandbox Disk (`test_disk.img`)
Run the sandbox generator once to synthesize a fresh raw disk image (or use the pre-generated file):
```bash
python create_sandbox.py
```
*(Synthesizes a 128 KB simulated raw disk with zero active FAT/NTFS filesystem, deliberate ~41 KB fragment separation, corrupted headers, and high-entropy ciphertext).*

### 2. Live GUI Evaluation Walkthrough
1. **Launch Reviver**: Launch the app (`python app.py` or `run.bat`). Reviver automatically pre-loads `test_disk.img`.
2. **Execute "Disk Dig" (Sector Carve)**:
   - Click **⛏️ Run Disk Dig (Raw Blocks)**.
   - **What this proves**: Because `test_disk.img` has no active file allocation table, standard OS explorers show nothing. Reviver's binary carver scans raw sectors directly, extracting unallocated PDF documents, PNG schematics, and ZIP archives.
3. **Execute "AI Deep Scan" (Graph Stitching)**:
   - Click **⚡ Run AI Scan & Deep Carve**.
   - **What this proves**: Reviver detects **FRAGMENT_A** at Sector 20 (Offset 10,240) and **FRAGMENT_B** far away at Sector 100 (Offset 51,200). The heuristic correlation engine links the matching tokens (`0x98442-SWIFT-PAYMENT-SYNC` and `TX-98442-SWIFT`) and displays the relationship graph!
4. **Inspect Structural Integrity & Corrupted Streams**:
   - Select the corrupted JPEG artifact (Sector 32 / Offset 16,384). Reviver's validator detects the invalid EXIF header (`\xFF\xD8...` without valid delimiters) and dynamically degrades its structural health score to **59.3%**.
5. **Engage the AI Copilot & TTS Voice Agent**:
   - Ask the copilot for a summary or click the **`🎙️ Read Aloud`** button to listen to the offline neural voice briefing.
   - Toggle **`🔊 Auto-Read: ON`** for hands-free audio briefings.
6. **Inspect the Chain of Custody Ledger & Export**:
   - Click **📋 Audit Ledger** to view the live, tamper-evident SHA-256 block chain.
   - Click **💾 Export Forensic Report** to export the technical JSON manifest and plain-English executive summary.

### 3. Headless CLI & Test Suite Execution
To verify the engine without launching the graphical interface:

```bash
# Run headless forensic pipeline on sandbox disk
python calmstacks-reconstructor/engine.py calmstacks-reconstructor/test_disk.img

# Run automated unit test suite
python calmstacks-reconstructor/test_suite.py

# Verify cryptographic ledger consistency
python calmstacks-reconstructor/test_ledger.py
```

---

## 🛡️ Ransomware & Anti-Forensics Edge-Case Resilience

Modern adversaries, ransomware operators, and malicious insiders employ aggressive anti-forensic countermeasures to wipe disks, corrupt slack space, and fragment log records. Reviver is specifically architected to counter these evasion techniques:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    REVIVER ANTI-FORENSICS DEFENSE ENGINE                    │
├──────────────────────────┬──────────────────────────┬───────────────────────┤
│  High-Entropy Detection  │ Truncation & Fault Audit │ Tamper-Evident Ledger │
│  H = -Σ p_i log₂(p_i)    │ Header/Footer Symmetry   │ Sequential SHA-256    │
│  Flags Ransomware & Wipes│ Cluster Boundary Drift   │ Immutable Chain       │
└──────────────────────────┴──────────────────────────┴───────────────────────┘
```

### 1. High-Entropy Payload & Ransomware Detection
Ransomware encryption, packed malware trojans, and encrypted credential vaults present mathematically distinct high byte randomness compared to structured source code or text logs.
- **Shannon Entropy Calculation**: Reviver computes actual byte-level Shannon entropy across every fragment:
  $$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$
- **Entropy Spectrum Interpretation**:
  - **`0.0 - 3.5` (Low / Wiped)**: Indicates zero-byte wiping, repetitive NOP sleds, or disk sanitization passes (`srm`, `shred`).
  - **`4.0 - 5.8` (Normal)**: Standard English prose, JSON dumps, source code, and system authentication logs.
  - **`7.0 - 8.0` (Critical / Ransomware)**: Instantly flags AES/RSA encrypted ransomware payload blobs, packed malware binaries, or encrypted truecrypt/bitlocker containers.

### 2. Truncation, Cluster Drift & Wiped Slack Space
When malware abruptly terminates an export or an attacker truncates log files to hide privilege escalations:
- **Cluster Boundary Drift**: Carvers normally assume files align to 512-byte or 4096-byte cluster boundaries. Reviver calculates offset slack drift ($\text{len} \pmod{512}$) and adjusts integrity scoring.
- **Delimiter Symmetry Verification**: Evaluates pairs such as `--- BEGIN` vs `--- END` markers or JSON brace depth (`{ ... }`). If a malicious actor truncated a sector midway, the missing footer triggers a **-24.5% structural fault deduction**.
- **Slack Space Wiper Identification**: Identifies repetitive fill patterns (`0x00` zero fills or `0x90` sleds) in slack space between logical file ends and physical cluster ends, confirming intentional data destruction.

### 3. Cryptographic SHA-256 Chain of Custody Ledger
To prevent legal challenges or defense attorney claims of forensic spoliation:
- **Sequential Block Hashing**: Every forensic operation (`LOAD_FILE`, `CARVE_FRAGMENTS`, `GRAPH_STITCH`, `ORGANIZE_FOLDER`, `EXPORT_REPORT`) creates an immutable block linked to the previous block's SHA-256 hash:
  $$\text{Hash}_n = \text{SHA-256}(\text{Index} \parallel \text{Timestamp} \parallel \text{Action} \parallel \text{Details} \parallel \text{Hash}_{n-1})$$
- **Court Admissibility**: Any retroactive modification, record injection, or evidence deletion breaks the mathematical hash chain instantly.

---

## 🌟 Core System Architecture

```
                    ┌─────────────────────────────────────────┐
                    │    REVIVER LIGHT-CYBER COMMAND HUD      │
                    │   (CustomTkinter 3-Column Resizable)    │
                    └────────────────────┬────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         ▼                               ▼                               ▼
┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
│ FORENSIC CONTROL │           │  ARTIFACT QUEUE  │           │ AI COPILOT & TTS │
│  - File Selector │           │  - Instant Search│           │  - Neural Brain  │
│  - AI Deep Scan  │           │  - Category Pills│           │  - Voice Agent   │
│  - Raw Disk Dig  │           │  - Health Meters │           │  - Inspector     │
└────────┬─────────┘           └─────────┬────────┘           └─────────┬────────┘
         │                               │                              │
         └───────────────────────────────┼──────────────────────────────┘
                                         │
                 ┌───────────────────────▼───────────────────────┐
                 │       CORE FORENSIC ENGINE (engine.py)        │
                 ├───────────────────────────────────────────────┤
                 │ • Binary Magic Byte Scanner & Stream Chunking │
                 │ • Heuristic Fragment Stitcher & Graph Builder │
                 │ • Shannon Entropy Engine & Structural Scorer  │
                 │ • Tamper-Evident SHA-256 Custody Ledger       │
                 │ • Multimodal LLM Reasoning & Text Repair     │
                 │ • Precision Duplicate Scanner & Categorizer   │
                 │ • Offline COM/SAPI Speech Synthesizer         │
                 └───────────────────────────────────────────────┘
```

### Key Modules:

| Module | Core Functionality |
| :--- | :--- |
| **`app.py`** | High-performance CustomTkinter GUI featuring a futuristic Light-Cyber layout (`#f1f5f9` ice-white base, `#2563eb` cobalt highlights), real-time draggable paned splitters, interactive artifact queue, and dual AI panels. |
| **`engine.py`** | Zero-dependency core forensic engine delivering binary signature carving, fragment graph correlation, Shannon entropy analysis, cryptographic ledgering, and duplicate scanning. |
| **`ReviverTTS`** | Background-threaded text-to-speech engine using Windows native COM SAPI speech synthesis with automatic regex sanitization for clean, natural verbal briefings. |
| **`sample_dump.bin`** | Realistic 36-sector synthetic binary dump containing shredded financial wire transactions, PII records, cloud credentials, system authentication logs, and anti-forensics slack patterns. |
| **`generate_sample.py`** | Utility generator script to programmatically synthesize custom damaged disk images and memory dumps. |
| **`test_suite.py`** | Automated regression test harness verifying carving, stitching, classification, and structural integrity scoring. |
| **`test_ledger.py`** | Standalone cryptographic verification script validating block chaining and hash integrity across the audit ledger. |

---

## 📊 Dual Forensic Reporting Engine

Reviver generates two synchronized reporting deliverables to satisfy both technical investigators and corporate executive leadership:

### 1. Plain-English Executive Summary
Designed for legal counsel, C-suite executives, and non-technical stakeholders:
- **Plain-English Overview**: Reconstructed file counts and average structural health.
- **Risk Classification Matrix**: Tier 1 Critical (immediate exposure), Tier 2 Sensitive (PII/compliance), and Tier 3 Operational data.
- **Anti-Forensics Audit**: Explicit counts of high-entropy blocks, truncated sectors, and wiped space.
- **Actionable Leadership Steps**: Immediate containment, credential rotation, and compliance disclosure advisories.

### 2. Court-Admissible JSON Evidence Manifest
A cryptographically verifiable technical package containing:
- Target image SHA-256 acquisition hash and byte length.
- Per-artifact sector offsets (`span`), entropy ($H$), and carved fragments.
- Graph correlation matrices and confidence percentages.
- Complete chain of custody ledger with sequential block hashes and timestamps.

---

## ⚖️ Legal & Ethical Usage Notice

Reviver is engineered strictly for authorized digital forensics investigations, incident response operations, defensive cybersecurity auditing, and academic research. Always ensure proper legal authorization and strict chain-of-custody protocols before analyzing forensic evidence.

*Developed for the Hackathon Digital Forensics & Incident Response Challenge.*
