"""
Script to generate a synthetic forensic disk dump for REVIVER.
Includes shredded fragments, non-contiguous blocks requiring stitching,
credentials, financial transactions, PII, and system logs.
"""
import os
import struct

def build_sample_dump(filepath: str):
    # Sector size 512 bytes
    SECTOR_SIZE = 512
    TOTAL_SECTORS = 36  # ~18 KB dump
    data = bytearray(TOTAL_SECTORS * SECTOR_SIZE)

    # Fill background with intermittent disk slack pattern (zeros and slight noise)
    for i in range(len(data)):
        if (i // 512) % 3 == 0:
            data[i] = 0x00
        elif (i // 512) % 7 == 0:
            data[i] = 0x90  # NOP sled / slack marker
        else:
            data[i] = 0x00

    # Sector 1 (Offset 512): Financial Wire Record Part A (Shredded)
    sec1_text = (
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
    data[1 * SECTOR_SIZE : 1 * SECTOR_SIZE + len(sec1_text)] = sec1_text

    # Sector 3 (Offset 1536): Credentials & Cloud Secrets
    sec3_text = (
        "# --- INTERNAL INFRASTRUCTURE CREDENTIAL DUMP (.env.production) ---\n"
        "ENV=production\n"
        "DB_HOST=primary-db-cluster.internal.local\n"
        "DB_PORT=5432\n"
        "DB_USER=secops_admin\n"
        "DB_PASSWORD=DUMMY_Passw0rd_Mock_Test_Only!\n"
        "AWS_ACCESS_KEY_ID=AKIA_SAMPLE_MOCK_TEST_KEY\n"
        "AWS_SECRET_ACCESS_KEY=MOCK_SECRET_KEY_NOT_REAL_FOR_TESTING_ONLY\n"
        "JWT_SECRET_SIGNING_KEY=mock_jwt_signing_key_for_testing_purposes_only\n"
        "STRIPE_API_KEY=sk_test_dummy_mock_sample_key_00000000000000\n"
        "REDIS_AUTH_URL=redis://:mock_redis_pass_12345@10.0.4.12:6379\n"
        "# --- END CREDENTIAL MANIFEST ---\n"
    ).encode("utf-8")
    data[3 * SECTOR_SIZE : 3 * SECTOR_SIZE + len(sec3_text)] = sec3_text

    # Sector 6 (Offset 3072): PII Customer Database Shred
    sec6_text = (
        '{"export_type": "PII_AUDIT", "schema_version": "2.4", "records": [\n'
        '  {"id": "USR-1092", "full_name": "Eleanor Vance", "ssn": "982-12-4091", "email": "e.vance@quantumcorp.org", "phone": "+1-415-555-0199", "address": "742 Evergreen Terrace, Springfield, OR"},\n'
        '  {"id": "USR-1093", "full_name": "Marcus Kane", "ssn": "451-88-2309", "email": "mkane@apex-fintech.io", "phone": "+1-212-555-0144", "address": "120 Broadway Ave, New York, NY"},\n'
        '  {"id": "USR-1094", "full_name": "Dr. Sarah Lin", "ssn": "309-54-8712", "email": "slin@biotech-systems.com", "phone": "+1-650-555-0182", "address": "404 Silicon Way, San Jose, CA"}\n'
        ']}'
    ).encode("utf-8")
    data[6 * SECTOR_SIZE : 6 * SECTOR_SIZE + len(sec6_text)] = sec6_text

    # Sector 12 (Offset 6144): Financial Wire Record Part B (Shredded continuation)
    sec12_text = (
        "[CONTINUATION: SEC-TX-98442-B] [TX-98442-SWIFT]\n"
        "Correlation Token: 0x98442-SWIFT-PAYMENT-SYNC\n"
        "Wire Status: EXECUTED_PENDING_SETTLEMENT\n"
        "Clearing Reference: CLR-FED-883019472\n"
        "Originator IP: 198.51.100.44 (VPN Tunnel: NordSEC-Gateway-12)\n"
        "Authorization Token: Bearer wt_live_99d08e718293fba41c9b\n"
        "Cryptographic Checksum: SHA256:d8b2e10a4f5c9e2b8a7c1d3e5f7a9b0c\n"
        "--- END WIRE TRANSFER RECORD ---\n"
    ).encode("utf-8")
    data[12 * SECTOR_SIZE : 12 * SECTOR_SIZE + len(sec12_text)] = sec12_text

    # Sector 17 (Offset 8704): System Authentication Logs
    sec17_text = (
        "Sep 24 14:18:02 srv-edge-01 sshd[4912]: Failed password for invalid user root from 203.0.113.88 port 41920 ssh2\n"
        "Sep 24 14:18:05 srv-edge-01 sshd[4912]: Failed password for invalid user admin from 203.0.113.88 port 41924 ssh2\n"
        "Sep 24 14:18:09 srv-edge-01 sshd[4912]: Accepted publickey for secops_admin from 198.51.100.44 port 50122 ssh2: RSA SHA256:4b9f0e11893b\n"
        "Sep 24 14:18:12 srv-edge-01 sudo: secops_admin : TTY=pts/2 ; PWD=/home/secops_admin ; USER=root ; COMMAND=/bin/bash\n"
        "Sep 24 14:18:15 srv-edge-01 auditd[1020]: ANOM_PROMISCUOUS dev=eth0 prom=256 old_prom=0 auid=1001 ses=4\n"
        "Sep 24 14:18:22 srv-edge-01 kernel: [48912.102] ALERT: Out-of-memory killer triggered on /var/log/audit.log exfiltration dump\n"
    ).encode("utf-8")
    data[17 * SECTOR_SIZE : 17 * SECTOR_SIZE + len(sec17_text)] = sec17_text

    # Sector 22 (Offset 11264): Damaged / Partial Memo (Simulates sector degradation)
    sec22_text = (
        "--- CONFIDENTIAL SECURITY INCIDENT MEMO [CASE-2026-X9] ---\n"
        "To: General Counsel & Chief Security Officer\n"
        "From: Lead Incident Responder (DFIR Team)\n"
        "Date: 2026-09-24 15:40 UTC\n"
        "Subject: Forensics Carving of Infiltrator Jump Host\n"
        "Summary of Breach: Threat actor gained initial access via compromised SSH key.\n"
        "Immediate Action Taken: Isolated subnet 10.0.4.0/24 and revoked AWS tokens.\n"
        "Data Loss Assessment: Suspicion of wire transfer tampering.\n"
        "[FATAL_BAD_SECTOR: TRUNCATED AT 0x2E40"
    ).encode("utf-8")
    data[22 * SECTOR_SIZE : 22 * SECTOR_SIZE + len(sec22_text)] = sec22_text
    # Add corrupted trailing bytes
    data[22 * SECTOR_SIZE + len(sec22_text) : 22 * SECTOR_SIZE + len(sec22_text) + 24] = b"\x00\xFF\x00\xFF\xAA\x55\xDE\xAD\xBE\xEF"

    # Sector 26 (Offset 13312): Crypto Wallet Cold Storage & Recovery Seed
    sec26_text = (
        "--- CRYPTO ASSET COLD STORAGE VAULT ---\n"
        "Vault Label: TREZOR-MULTI-SIG-VAULT-04\n"
        "Network: Ethereum Mainnet\n"
        "Deposit Contract: 0x71C840505A4A7d34Fa773821F4a94628D890E0e1\n"
        "BIP39 Seed Phrase: flame vintage orbit fossil weapon dragon helmet galaxy mystery glance dynamic copper\n"
        "Master Private Key (Hex): 4b92c810f5439a812ecf014798b0932145e6d7821034f8a9e0b1c2d3e4f5a6b7\n"
        "Estimated Balance: 420.50 ETH (~$1,450,000 USD)\n"
        "--- END VAULT MANIFEST ---\n"
    ).encode("utf-8")
    data[26 * SECTOR_SIZE : 26 * SECTOR_SIZE + len(sec26_text)] = sec26_text

    # Sector 30 (Offset 15360): Unallocated PDF Document (Magic Byte Carving)
    sec30_bytes = (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Title (CONFIDENTIAL_ACQUISITION_TARGETS_Q4) /Classification (RESTRICTED) /Author (Corporate_Strategy) >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Target_1 (Apex Holdings) /Target_2 (Nordic Security Corp) /Proposed_Valuation ($14.2M) >>\n"
        b"endobj\n"
        b"%%EOF\n"
    )
    data[30 * SECTOR_SIZE : 30 * SECTOR_SIZE + len(sec30_bytes)] = sec30_bytes

    # Sector 33 (Offset 16896): Unallocated PNG Image Signature (Magic Byte Carving)
    sec33_bytes = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00\x5c\x72\xa8\x66"
        b"\x00\x00\x00\x19tEXtComment\x00FORENSIC_EXFILTRATED_SCHEMATIC"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    data[33 * SECTOR_SIZE : 33 * SECTOR_SIZE + len(sec33_bytes)] = sec33_bytes

    with open(filepath, "wb") as f:
        f.write(data)
    print(f"Generated {filepath} ({len(data)} bytes, {TOTAL_SECTORS} sectors)")

if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "sample_dump.bin")
    build_sample_dump(out_path)
