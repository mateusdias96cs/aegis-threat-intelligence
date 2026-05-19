import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.collectors import cisa, otx, mitre, threatfox
from src.collectors import abuseipdb
from src.processors import normalizer, classifier, deduplicator
from src.storage.database import DatabaseManager
from src.reporters import html_report


def run():
    db = DatabaseManager()
    try:
        print("[pipeline] cleaning up IOCs older than 30 days ...")
        deleted = db.cleanup_old_iocs(days=30)
        print(f"[pipeline] removed {deleted} expired IOCs")

        # Collect
        print("[pipeline] collecting from CISA-KEV ...")
        cisa_iocs = cisa.collect()
        print(f"[pipeline] CISA-KEV: {len(cisa_iocs)} indicators")

        print("[pipeline] collecting from AlienVault OTX ...")
        otx_iocs = otx.collect()
        print(f"[pipeline] OTX: {len(otx_iocs)} indicators")

        print("[pipeline] collecting from ThreatFox ...")
        tf_iocs = threatfox.collect()
        print(f"[pipeline] ThreatFox: {len(tf_iocs)} indicators")

        raw_iocs = cisa_iocs + otx_iocs + tf_iocs
        print(f"[pipeline] total collected: {len(raw_iocs)}")

        # Deduplicate internally first
        raw_iocs = deduplicator.deduplicate(raw_iocs)
        print(f"[pipeline] after internal deduplication: {len(raw_iocs)}")

        # Filter out existing IOCs
        existing_values = db.get_existing_values()
        new_iocs = [ioc for ioc in raw_iocs if ioc.get("value") not in existing_values]
        print(f"[pipeline] new indicators to process: {len(new_iocs)}")

        # Process new IOCs
        if new_iocs:
            print("[pipeline] normalizing ...")
            new_iocs = normalizer.normalize(new_iocs)
            
            # Limit Enrichment to avoid Rate Limits (e.g., max 300 per run)
            MAX_ENRICH_PER_RUN = 300
            iocs_to_enrich = new_iocs[:MAX_ENRICH_PER_RUN]
            iocs_no_enrich = new_iocs[MAX_ENRICH_PER_RUN:]
            
            if iocs_to_enrich:
                print(f"[pipeline] enriching {len(iocs_to_enrich)} IPs via AbuseIPDB ...")
                iocs_to_enrich = abuseipdb.enrich_batch(iocs_to_enrich)
            else:
                print("[pipeline] no IPs to enrich.")
                
            new_iocs = iocs_to_enrich + iocs_no_enrich

            print("[pipeline] classifying ...")
            new_iocs = classifier.classify(new_iocs)
            new_iocs = classifier.apply_confidence(new_iocs)
            print("[pipeline] confidence scores calculated")

            # Load MITRE ATT&CK technique index once before processing
            print("[pipeline] loading MITRE ATT&CK techniques ...")
            techniques = mitre.load_techniques()
            print(f"[pipeline] MITRE: {len(techniques)} techniques loaded")

            print("[pipeline] mapping to MITRE ATT&CK ...")
            for ioc in new_iocs:
                technique = mitre.map_ioc_to_technique(ioc, techniques)
                if technique:
                    ioc["mitre_technique_id"] = technique["id"]
                    ioc["mitre_tactic"] = technique["tactic"]
                else:
                    ioc["mitre_technique_id"] = None
                    ioc["mitre_tactic"] = None

            print("[pipeline] saving to database ...")
            db.insert_many(new_iocs)
        else:
            print("[pipeline] loading MITRE ATT&CK techniques for report ...")
            techniques = mitre.load_techniques()

        # Report
        print("[pipeline] generating report ...")
        stats = db.get_stats()
        all_iocs = db.get_all_iocs()
        html_report.generate(all_iocs, stats, techniques)

        # Summary
        by_severity = stats.get("by_severity", {})
        print("\n── Pipeline complete ──────────────────────────")
        print(f"  New IOCs added:       {len(new_iocs)}")
        print(f"  Total in DB:          {len(all_iocs)}")
        print("  Breakdown by severity (Total):")
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = by_severity.get(level, 0)
            print(f"    {level:<10} {count}")
        print("───────────────────────────────────────────────")
        print("[pipeline] report written to output/index.html")
    finally:
        db.close()


if __name__ == "__main__":
    run()
