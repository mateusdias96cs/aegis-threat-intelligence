import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.collectors import cisa, otx, mitre
from src.collectors import abuseipdb
from src.processors import normalizer, classifier, deduplicator
from src.storage.database import DatabaseManager
from src.reporters import html_report


def run():
    # Collect
    print("[pipeline] collecting from CISA-KEV ...")
    cisa_iocs = cisa.collect()
    print(f"[pipeline] CISA-KEV: {len(cisa_iocs)} indicators")

    print("[pipeline] collecting from AlienVault OTX ...")
    otx_iocs = otx.collect()
    print(f"[pipeline] OTX: {len(otx_iocs)} indicators")

    raw_iocs = cisa_iocs + otx_iocs
    print(f"[pipeline] total collected: {len(raw_iocs)}")

    # Load MITRE ATT&CK technique index once before processing
    print("[pipeline] loading MITRE ATT&CK techniques ...")
    techniques = mitre.load_techniques()
    print(f"[pipeline] MITRE: {len(techniques)} techniques loaded")

    # Process
    print("[pipeline] normalizing ...")
    iocs = normalizer.normalize(raw_iocs)

    print("[pipeline] enriching IPs via AbuseIPDB ...")
    iocs = abuseipdb.enrich_batch(iocs)

    print("[pipeline] classifying ...")
    iocs = classifier.classify(iocs)

    print("[pipeline] mapping to MITRE ATT&CK ...")
    for ioc in iocs:
        technique = mitre.map_ioc_to_technique(ioc, techniques)
        if technique:
            ioc["mitre_technique_id"] = technique["id"]
            ioc["mitre_tactic"] = technique["tactic"]
        else:
            ioc["mitre_technique_id"] = None
            ioc["mitre_tactic"] = None

    print("[pipeline] deduplicating ...")
    iocs = deduplicator.deduplicate(iocs)
    print(f"[pipeline] after deduplication: {len(iocs)}")

    # Persist
    print("[pipeline] saving to database ...")
    db = DatabaseManager()
    try:
        db.insert_many(iocs)

        # Report
        print("[pipeline] generating report ...")
        stats = db.get_stats()
        all_iocs = db.get_all_iocs()
        html_report.generate(all_iocs, stats, techniques)
    finally:
        db.close()

    # Summary
    print("\n── Pipeline complete ──────────────────────────")
    print(f"  Total collected:      {len(raw_iocs)}")
    print(f"  After deduplication:  {len(iocs)}")
    print("  Breakdown by severity:")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = stats["by_severity"].get(level, 0)
        print(f"    {level:<10} {count}")
    print("───────────────────────────────────────────────")
    print("[pipeline] report written to output/index.html")


if __name__ == "__main__":
    run()
