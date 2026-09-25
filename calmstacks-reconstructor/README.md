# REVIVER 🛡️🔬
### Automated Digital Forensics Carving & Fragment Graph Reconstruction Suite

REVIVER is a standalone desktop digital forensics application engineered in Python and `customtkinter`. It automates the extraction, relationship graph stitching, classification, and integrity validation of fragmented, shredded, or deleted data from raw binary disk dumps and real-world system files.

---

## 🚀 Key Capabilities

1. **Universal Real-World File & Binary Carving (`carve_disk_image`)**:
   - Analyzes raw disk dumps, memory dumps, or any real file on your machine (logs, scripts, DB dumps, JSON, PDFs, images).
   - For **Text Streams**: Chunks content into logical stream blocks (15 lines each) with precise byte spans.
   - For **Binary Files**: Identifies magic byte signatures (JPEG, PNG, PDF, ZIP, ELF, Windows PE Executables, SQLite), calculates SHA-256 hashes, renders formatted 16-byte hex dumps, and extracts embedded string fragments.
   - Computes Shannon entropy ($H$) to differentiate between uncompressed text, structured code, and compressed/encrypted artifacts.

2. **AI & Heuristic Fragment Stitching (`stitch_fragments`)**:
   - Correlates non-contiguous shredded blocks across separate sectors using continuation tokens (e.g. `[CONTINUED IN BLOCK-REF: ...]` <-> `[CONTINUATION: ...]`).
   - Discovers relationship links based on shared IP addresses, user identities, correlation tokens, and stream continuity.
   - Calculates relationship confidence scores (up to 99.2%).
   - Seamlessly stitches fragmented chains into unified composite evidence.

3. **Keyword & Pattern Classification Rule Engine (`classify_and_prioritize`)**:
   - **`[CRITICAL: Financial]`**: Detects SWIFT, IBAN, Fedwire batches, wire transfer settlements, and crypto cold-storage BIP-39 mnemonic seeds.
   - **`[Credentials]`**: Identifies AWS access keys (`AKIA...`), database root passwords, Stripe live tokens, JWT signing secrets, and Redis auth URLs.
   - **`[PII]`**: Extracts customer identities, Social Security Numbers (SSNs), email addresses, phone numbers, and physical addresses.
   - **`[System Logs]`**: Identifies SSH brute-force attempts, sudo escalations, kernel alerts, and promiscuous network captures (`auditd`).
   - **`[Internal Comms: Incident Response]`**: Catalogs internal legal briefings and DFIR incident memos.
   - Organizes all artifacts into a multi-tier priority queue (`Tier 1 - Critical` down to `Tier 4 - Low`).

4. **Forensic Integrity Assessment (`assess_integrity`)**:
   - Assesses structural completeness (e.g. `100% Valid Structure` vs `68% Degraded / Truncated`).
   - Validates header/footer symmetry and balanced parsing (e.g., JSON schema validity).
   - Flags hardware sector faults, unaligned boundaries, and corrupted byte markers.

5. **Modern Dark-Mode Split-Screen GUI (`app.py`)**:
   - **Top Bar**: Live status indicator badge (`● SYSTEM READY`, `⟳ SCANNING...`, `✔ ANALYSIS COMPLETE`) and real-time telemetry counters (carved fragments, stitched chains, critical severity items).
   - **Left Panel**: Target file selector, "Run AI Scan" action button, pulsing progress bar, category filter tabs (`ALL`, `CRITICAL`, `CREDENTIALS`, `PII`, `LOGS`), instant search bar, and scrollable artifact card queue with category color pills.
   - **Right Panel (Inspector)**: Detailed artifact banner with visual integrity health progress bar, category badge, priority pill, copy/export buttons, full-fidelity monospace reconstructed content preview, and interactive AI relationship map box with link metrics.
   - **Bottom Bar**: Real-time status message ticker detailing scan progression step-by-step.

---

## 📂 Project Structure

```text
calmstacks-reconstructor/
│
├── requirements.txt         # Project dependencies (customtkinter, pillow)
├── engine.py                # Core forensic engine (carving, stitching, classification, integrity)
├── app.py                   # CustomTkinter split-screen desktop GUI application
├── sample_dump.bin          # Built-in synthetic test dump with non-contiguous shredded records
├── generate_sample.py       # Utility generator script for realistic test dumps
├── run.bat                  # 1-click Windows launcher
└── README.md                # Documentation and architecture overview
```

---

## ⚙️ Installation & Quickstart

### 1. Prerequisites
- Python 3.10+ installed
- Required packages: `customtkinter`, `pillow`

```bash
cd calmstacks-reconstructor
pip install -r requirements.txt
```

### 2. Launching the Desktop Application
Run the main desktop application:

```bash
python app.py
```

*Or from workspace root:*
```bash
npm run dev
```

*Click **"📂 Select Disk/Image File"** to pick any file or dump, then click **"⚡ Run AI Scan & Deep Carve"**!*

### 3. Running Engine via CLI (Headless Mode)
You can also run the backend engine directly from the command line:

```bash
python engine.py sample_dump.bin
```
