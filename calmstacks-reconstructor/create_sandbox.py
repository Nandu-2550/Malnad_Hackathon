"""
REVIVER // Forensic Sandbox Mock Disk Generator (create_sandbox.py)
===================================================================
Generates 'test_disk.img', a controlled, 100% reproducible binary sandbox disk
for validating Reviver's Disk Dig, Heuristic Fragment Stitching, and Structural
Integrity engines.

Simulated Disk Architecture (128 KB, 256 sectors):
• Sector 4   (0x0800): Confidential Project Notes & Breach Incident Memo
• Sector 8   (0x1000): Production Cloud Secrets & Database Credentials (.env.production)
• Sector 12  (0x1800): Customer PII Database Shred (JSON Schema with SSNs)
• Sector 20  (0x2800): FRAGMENT_A - Financial Wire Record Part 1
• Sector 32  (0x4000): Corrupted JPEG Stream (\xFF\xD8 with corrupted EXIF & bad cluster)
• Sector 48  (0x6000): Encrypted Ransomware Payload (High Entropy H >= 7.8)
• Sector 64  (0x8000): System Authentication Logs (SSH brute force & privilege escalation)
• Sector 100 (0xC800): FRAGMENT_B - Financial Wire Record Part 2 (~41 KB away from Part 1!)
• Sector 140 (0x11800): Unallocated PDF Document (Magic Byte %PDF Carving)
• Sector 180 (0x16800): Unallocated PNG Image Signature (\x89PNG)
• Sector 210 (0x1A400): Unallocated ZIP Archive (PK\x03\x04)
• Slack Space: Zero-byte fill and 0x90 NOP sleds simulating anti-forensics wipe passes.
"""

import os
import sys
import math
import hashlib

SECTOR_SIZE = 512
TOTAL_SECTORS = 256  # 128 KB disk dump
IMAGE_SIZE = TOTAL_SECTORS * SECTOR_SIZE


def generate_high_entropy_bytes(length: int) -> bytes:
    """Generates pseudo-random bytes with high Shannon entropy (H > 7.8) to simulate AES-256 ciphertext."""
    import random
    rng = random.Random(42)  # Deterministic seed for reproducible testing
    return bytes([rng.randint(0, 255) for _ in range(length)])


def build_test_disk(output_paths):
    disk = bytearray(IMAGE_SIZE)

    # 1. Background Slack Space & Anti-Forensic Wiping Simulation
    # Fill with intermittent zero-bytes and NOP sleds (0x90)
    for i in range(len(disk)):
        sec = i // SECTOR_SIZE
        if sec in (2, 7, 15, 25, 40):
            disk[i] = 0x90  # NOP sled / slack pattern
        else:
            disk[i] = 0x00  # Zero-byte wipe marker

    # 2. Offset 2,048 (Sector 4): Confidential Project Notes
    sec4_text = (
        "--- CONFIDENTIAL SECURITY INCIDENT MEMO [CASE-2026-CALMSTACKS] ---\n"
        "To: Incident Response Team & Executive Council\n"
        "From: Lead DFIR Systems Investigator\n"
        "Date: 2026-09-26T04:15:00Z\n"
        "Classification: TOP SECRET // RESTRICTED ACCESS\n"
        "Subject: Forensic Reconstruction of Infiltrated Host\n"
        "Details: Threat actor attempted disk wipe using zero-fill passes.\n"
        "Target System: Production Database Gateway (Cluster Node 4)\n"
        "Investigation Strategy: Perform raw sector carves to bypass wiped FAT tables.\n"
        "--- END INCIDENT MEMO ---\n"
    ).encode("utf-8")
    disk[2048 : 2048 + len(sec4_text)] = sec4_text

    # 3. Offset 4,096 (Sector 8): Production Infrastructure Secrets (.env.production)
    sec8_text = (
        "# --- INTERNAL INFRASTRUCTURE CREDENTIAL DUMP (.env.production) ---\n"
        "ENV=production\n"
        "DB_HOST=primary-db-cluster.internal.local\n"
        "DB_PORT=5432\n"
        "DB_USER=secops_admin\n"
        "DB_PASSWORD=P@ssw0rd_Admin_Vault_2026!\n"
        "AWS_ACCESS_KEY_ID=AKIA_SAMPLE_MOCK_TEST_KEY\n"
        "AWS_SECRET_ACCESS_KEY=MOCK_SECRET_KEY_NOT_REAL_FOR_TESTING_ONLY\n"
        "JWT_SECRET_SIGNING_KEY=mock_jwt_signing_key_for_testing_purposes_only\n"
        "STRIPE_API_KEY=sk_test_dummy_mock_sample_key_00000000000000\n"
        "REDIS_AUTH_URL=redis://:mock_redis_pass_12345@10.0.4.12:6379\n"
        "# --- END CREDENTIAL MANIFEST ---\n"
    ).encode("utf-8")
    disk[4096 : 4096 + len(sec8_text)] = sec8_text

    # 4. Offset 6,144 (Sector 12): Customer PII Database Shred
    sec12_text = (
        '{"export_type": "PII_AUDIT", "schema_version": "2.4", "records": [\n'
        '  {"id": "USR-1092", "full_name": "Eleanor Vance", "ssn": "982-12-4091", "email": "e.vance@quantumcorp.org", "phone": "+1-415-555-0199", "address": "742 Evergreen Terrace, Springfield, OR"},\n'
        '  {"id": "USR-1093", "full_name": "Marcus Kane", "ssn": "451-88-2309", "email": "mkane@apex-fintech.io", "phone": "+1-212-555-0144", "address": "120 Broadway Ave, New York, NY"},\n'
        '  {"id": "USR-1094", "full_name": "Dr. Sarah Lin", "ssn": "309-54-8712", "email": "slin@biotech-systems.com", "phone": "+1-650-555-0182", "address": "404 Silicon Way, San Jose, CA"}\n'
        ']}'
    ).encode("utf-8")
    disk[6144 : 6144 + len(sec12_text)] = sec12_text

    # 5. Offset 10,240 (Sector 20): FRAGMENT_A (Financial Wire Record Part 1)
    # Deliberately separated from Part 2 across 40,960 bytes of unallocated space!
    sec20_text = (
        "--- BEGIN WIRE TRANSFER RECORD [TX-98442-SWIFT] ---\n"
        "Timestamp: 2026-09-24T14:22:19Z\n"
        "Originating Account: ACCT-9921-8841-CHASE\n"
        "SWIFT Code: CHASUS33XXX\n"
        "Beneficiary Name: Apex Holdings International Ltd.\n"
        "Beneficiary IBAN: GB82WEST12345698765432\n"
        "Amount: $4,850,000.00 USD\n"
        "Routing: FEDERAL RESERVE FEDWIRE BATCH 4091\n"
        "Correlation Token: 0x98442-SWIFT-PAYMENT-SYNC\n"
        "[CONTINUED IN BLOCK-REF: SEC-TX-98442-B]\n"
    ).encode("utf-8")
    disk[10240 : 10240 + len(sec20_text)] = sec20_text

    # 6. Offset 16,384 (Sector 32): Corrupted JPEG Stream (\xFF\xD8 Header with Corrupted Delimiter)
    # Tests structural integrity validator and degradation scoring
    sec32_corrupt = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00"
        b"\xff\xdb\x00\x43\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08"
        b"[FATAL_BAD_SECTOR: READ ERROR // CORRUPTED EXIF HEADER // TRUNCATED CLUSTER]"
        b"\x00\xff\x00\xff\xde\xad\xbe\xef"
    )
    disk[16384 : 16384 + len(sec32_corrupt)] = sec32_corrupt

    # 7. Offset 24,576 (Sector 48): Encrypted Ransomware Payload (High Entropy H >= 7.8)
    sec48_header = b"[RANSOMWARE_ENCRYPTED_VAULT_PAYLOAD // AES-256-GCM CIPHERTEXT]\n"
    sec48_cipher = generate_high_entropy_bytes(1024 - len(sec48_header))
    disk[24576 : 24576 + len(sec48_header)] = sec48_header
    disk[24576 + len(sec48_header) : 25600] = sec48_cipher

    # 8. Offset 32,768 (Sector 64): System Authentication Audit Log
    sec64_text = (
        "Sep 26 03:12:01 edge-gateway-01 sshd[9182]: Accepted publickey for secops_admin from 198.51.100.44 port 54112 ssh2\n"
        "Sep 26 03:12:04 edge-gateway-01 sudo: secops_admin : TTY=pts/1 ; PWD=/opt/reviver ; USER=root ; COMMAND=/bin/disk_dump\n"
        "Sep 26 03:12:10 edge-gateway-01 auditd[880]: USER_AUTH pid=9182 uid=0 auid=1000 ses=2 msg='op=PAM:authentication grant'\n"
        "Sep 26 03:12:15 edge-gateway-01 kernel: [10928.441] EXT4-fs (sdb1): unallocated slack carve initiated\n"
    ).encode("utf-8")
    disk[32768 : 32768 + len(sec64_text)] = sec64_text

    # 9. Offset 51,200 (Sector 100): FRAGMENT_B (Financial Wire Record Continuation)
    # The heuristic graph stitcher will find this ~41KB away from FRAGMENT_A!
    sec100_text = (
        "[CONTINUATION: SEC-TX-98442-B] [TX-98442-SWIFT]\n"
        "Correlation Token: 0x98442-SWIFT-PAYMENT-SYNC\n"
        "Wire Status: EXECUTED_PENDING_SETTLEMENT\n"
        "Clearing Reference: CLR-FED-883019472\n"
        "Originator IP: 198.51.100.44 (VPN Tunnel: NordSEC-Gateway-12)\n"
        "Authorization Token: Bearer wt_live_99d08e718293fba41c9b\n"
        "Cryptographic Checksum: SHA256:d8b2e10a4f5c9e2b8a7c1d3e5f7a9b0c\n"
        "--- END WIRE TRANSFER RECORD ---\n"
    ).encode("utf-8")
    disk[51200 : 51200 + len(sec100_text)] = sec100_text

    # 10. Offset 71,680 (Sector 140): Unallocated PDF Document (Magic Byte %PDF Carving)
    sec140_pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Title (TOP_SECRET_ACQUISITION_TARGETS) /Classification (RESTRICTED) /Author (Cyber_Ops) >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Target_1 (Apex Holdings Ltd) /Proposed_Valuation ($14,850,000 USD) /Status (Approved) >>\n"
        b"endobj\n"
        b"%%EOF\n"
    )
    disk[71680 : 71680 + len(sec140_pdf)] = sec140_pdf

    # 11. Offset 92,160 (Sector 180): Unallocated PNG Image Signature (\x89PNG)
    sec180_png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00\x5c\x72\xa8\x66"
        b"\x00\x00\x00\x1ftEXtComment\x00EXFILTRATED_SCHEMATIC_PAYLOAD"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    disk[92160 : 92160 + len(sec180_png)] = sec180_png

    # 12. Offset 107,520 (Sector 210): Unallocated ZIP Archive (PK\x03\x04)
    sec210_zip = (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00"
        b"evidence.txtCONFIDENTIAL_LEAK_DATA_ARCHIVE"
        b"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00Z\x00\x00\x00Z\x00\x00\x00\x00\x00"
    )
    disk[107520 : 107520 + len(sec210_zip)] = sec210_zip

    # Write output to requested destination paths
    sha256_hash = hashlib.sha256(disk).hexdigest()
    for p in output_paths:
        os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
        with open(p, "wb") as f:
            f.write(disk)
        print(f"Generated: {p} ({len(disk):,} bytes, {TOTAL_SECTORS} sectors)")

    print(f"SHA-256 Acquisition Hash: {sha256_hash}")
    return sha256_hash


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Generate in both root and calmstacks-reconstructor folder for maximum convenience
    destinations = [
        os.path.join(current_dir, "test_disk.img"),
        os.path.join(current_dir, "calmstacks-reconstructor", "test_disk.img")
    ]
    if os.path.basename(current_dir) == "calmstacks-reconstructor":
        destinations = [
            os.path.join(current_dir, "test_disk.img"),
            os.path.join(os.path.dirname(current_dir), "test_disk.img")
        ]
    
    unique_dests = list({os.path.abspath(d): d for d in destinations}.values())
    
    print("=" * 70)
    print("   REVIVER // FORENSIC SANDBOX MOCK DISK GENERATOR")
    print("=" * 70)
    print("Building simulated raw disk image with deliberate fragmentation...")
    print("• FRAGMENT_A @ Offset 10,240 (Sector 20)")
    print("• FRAGMENT_B @ Offset 51,200 (Sector 100) [~41 KB separation]")
    print("• Corrupted JPEG header @ Offset 16,384 (Sector 32)")
    print("• High-Entropy Encrypted Payload (H >= 7.8) @ Offset 24,576")
    print("• PDF, PNG, and ZIP Magic Byte Signatures injected.")
    print("• Credentials, PII, and Slack Wipe patterns injected.")
    print("-" * 70)
    build_test_disk(unique_dests)
    print("=" * 70)
    print("READY FOR JUDGING! Load 'test_disk.img' in Reviver to demonstrate:")
    print("1. Disk Dig sector bypass of missing FAT/NTFS filesystem.")
    print("2. Graph Stitching linking FRAGMENT_A and FRAGMENT_B.")
    print("3. Structural Health degradation on corrupted headers.")
    print("4. High-entropy ransomware payload detection.")
    print("=" * 70)
