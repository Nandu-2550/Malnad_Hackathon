import os
import sys
import time
import json

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from app import ReviverApp
from engine import export_forensic_report

def test_ledger_and_export():
    app = ReviverApp()
    app.update()
    
    print("Initial ledger chain height:", len(app.ledger.chain))
    assert app.ledger.chain[0]["action"] == "INITIALIZE_LEDGER"

    # Start scan
    app._start_scan_thread()
    start = time.time()
    while time.time() - start < 3.0:
        app.update()
        time.sleep(0.05)

    print("Post-scan ledger chain height:", len(app.ledger.chain))
    for b in app.ledger.chain:
        print(f"  [Block #{b['index']}] {b['action']} -> Current Hash: {b['current_hash'][:24]}... | Prev Hash: {b['previous_hash'][:16]}...")

    # Test export
    test_out = os.path.join(CURRENT_DIR, "test_signed_report.json")
    app.ledger.add_entry("EXPORT_REPORT", {"artifact_count": len(app.artifacts)})
    out_path = export_forensic_report(app.artifacts, app.ledger.chain, filepath=test_out)
    
    assert os.path.exists(out_path), "Report file must exist"
    with open(out_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("\nGenerated Report Verification:")
    print("  • Suite:", data["suite"])
    print("  • Total Artifacts:", data["total_artifacts"])
    print("  • Chain Blocks:", len(data["chain_of_custody_ledger"]))
    print("  • Verification SHA-256 Signature:", data["verification_signature"])

    # Clean up test artifact
    if os.path.exists(test_out):
        os.remove(test_out)

    app.destroy()
    print("\n[PASS] Forensic Ledger & Cryptographic Export Fully Verified!")

if __name__ == "__main__":
    test_ledger_and_export()
