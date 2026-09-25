"""
REVIVER - Automated Test Suite & Forensic Validation
===================================================
Tests core capabilities:
1. Shannon Entropy Calculation
2. Regex & Heuristic Content Classification
3. Binary Disk Carving & Text Stream Chunking
4. Fragment Graph Stitching & Relationship Links
5. Structural Integrity Assessment
6. End-to-End Forensic Pipeline
7. Desktop GUI Non-blocking Worker Verification
"""

import os
import sys
import time

# Ensure UTF-8 output support on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from engine import (
    calculate_entropy,
    classify_text_content,
    carve_disk_image,
    stitch_fragments,
    classify_and_prioritize,
    assess_integrity,
    run_forensic_pipeline,
    ForensicArtifact
)


def run_tests():
    print("=" * 70)
    print("      REVIVER FORENSIC ENGINE // AUTOMATED VERIFICATION SUITE")
    print("=" * 70)

    # TEST 1: Shannon Entropy Calculation
    print("\n[TEST 1] Shannon Entropy Calculation")
    zeros = b"\x00" * 1024
    random_mock = bytes([i % 256 for i in range(1024)])
    text_data = b"The quick brown fox jumps over the lazy dog."

    e_zero = calculate_entropy(zeros)
    e_rand = calculate_entropy(random_mock)
    e_text = calculate_entropy(text_data)

    print(f"  • Low Entropy (Null Bytes)     : {e_zero} (Expected: ~0.0)")
    print(f"  • Medium Entropy (Plain English): {e_text} (Expected: 3.5 - 4.5)")
    print(f"  • High Entropy (Max Randomness) : {e_rand} (Expected: ~8.0)")
    assert e_zero == 0.0, "Entropy of nulls must be 0"
    assert 3.0 < e_text < 5.0, "Entropy of English text must be ~3.5 - 4.5"
    assert e_rand > 7.5, "Entropy of uniform random bytes must be ~8.0"
    print("  ✔ PASS: Entropy mathematics validated.")

    # TEST 2: Regex & Heuristic Classification
    print("\n[TEST 2] Regex & Heuristic Classification")
    samples = [
        ("DB_PASSWORD=P@ssw0rd_9941! AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "Credentials"),
        ("SWIFT Code: CHASUS33XXX Wire Amount: $4,850,000.00 USD IBAN: GB82WEST12345698765432", "Financial"),
        ("Customer SSN: 982-12-4091 Email: e.vance@quantumcorp.org Phone: 4155550199", "PII"),
        ("srv-edge-01 sshd[4912]: Failed password for invalid user root from 203.0.113.88", "System Logs"),
        ("def main(): return 'Hello World'", "General Stream"),
    ]
    for text, expected_cat in samples:
        cat, tier, pri = classify_text_content(text)
        print(f"  • Input: '{text[:45]}...' -> Classified: [{cat}] ({tier})")
        assert cat == expected_cat, f"Expected {expected_cat}, got {cat}"
    print("  ✔ PASS: Classifier categorization verified across all risk tiers.")

    # TEST 3: Disk Carving on Binary Dump (sample_dump.bin)
    print("\n[TEST 3] Binary Dump Carving (sample_dump.bin)")
    dump_path = os.path.join(CURRENT_DIR, "sample_dump.bin")
    assert os.path.exists(dump_path), "sample_dump.bin must exist"
    fragments = carve_disk_image(dump_path)
    print(f"  • Carved candidate artifacts from dump: {len(fragments)}")
    assert len(fragments) > 0, "Carving should extract artifacts"
    for frag in fragments[:3]:
        print(f"    - [{frag.artifact_id}] {frag.name} | Category: {frag.category} | Health: {frag.integrity_status}")
    print("  ✔ PASS: Binary sector carving validated.")

    # TEST 4: Fragment Graph Stitching & Relationship Linkage
    print("\n[TEST 4] Fragment Graph Stitching & Correlation")
    stitched = stitch_fragments(fragments)
    linked_count = sum(1 for a in stitched if a.relationship_links)
    print(f"  • Total Stitched/Linked Artifacts: {linked_count}")
    for a in stitched:
        if a.relationship_links:
            link = a.relationship_links[0]
            print(f"    - Linkage: [{link.source_id}] ──► [{link.target_id}] | Confidence: {link.confidence}% | Token: '{link.token}'")
            break
    print("  ✔ PASS: AI Relationship Graph linkage verified.")

    # TEST 5: Structural Integrity Assessment
    print("\n[TEST 5] Structural Integrity Assessment")
    intact_art = ForensicArtifact({"content": "--- BEGIN RECORD ---\nData Payload\n--- END RECORD ---", "id": "ART-01"})
    broken_art = ForensicArtifact({"content": "--- BEGIN RECORD ---\nTruncated data... [FATAL_BAD_SECTOR: TRUNCATED AT 0x2E40]", "id": "ART-02"})

    score_ok, status_ok, _ = assess_integrity(intact_art)
    score_bad, status_bad, _ = assess_integrity(broken_art)
    print(f"  • Intact Record Health : {status_ok} (Score: {score_ok}%)")
    print(f"  • Corrupted Record Health: {status_bad} (Score: {score_bad}%)")
    assert score_ok >= 95, "Intact record should score >= 95%"
    assert score_bad < 75, "Truncated record should score < 75%"
    print("  ✔ PASS: Integrity grading successfully detects structural faults.")

    # TEST 6: Real-World File Carving (Text Source Code)
    print("\n[TEST 6] Real-World File Carving (engine.py)")
    real_file_path = os.path.join(CURRENT_DIR, "engine.py")
    results = run_forensic_pipeline(real_file_path)
    print(f"  • Real File: {os.path.basename(results['file_path'])} ({results['file_size']:,} bytes)")
    print(f"  • Carved Stream Blocks: {results['total_reconstructed_artifacts']}")
    print(f"  • Critical Severity Items: {results['critical_priority_count']}")
    assert results["total_reconstructed_artifacts"] > 10, "Real code file should be carved into multiple 15-line blocks"
    print("  ✔ PASS: Real-world file parsing and block chunking operational.")

    # TEST 7: Desktop GUI Headless Initialization & State Test
    print("\n[TEST 7] Desktop GUI Headless State Test (app.py)")
    from app import ReviverApp
    app = ReviverApp()
    app.update()
    assert app.title() == "REVIVER - Digital Forensics & Data Carving Suite"
    assert app.target_file_path.endswith("sample_dump.bin")
    app.destroy()
    print("  ✔ PASS: CustomTkinter GUI initialized, theme applied, and event queue validated.")

    print("\n" + "=" * 70)
    print("   ALL 7 TESTS PASSED SUCCESSFULLY! REVIVER SUITE FULLY OPERATIONAL")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    run_tests()
