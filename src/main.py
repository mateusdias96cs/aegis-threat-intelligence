import os
import sys
import sentry_sdk
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.collectors import cisa, otx, mitre, threatfox
from src.collectors import urlhaus, feodo, greynoise, emerging_threats
from src.processors import normalizer, classifier, deduplicator
from src.storage.database import DatabaseManager
from src.reporters import html_report
from src.enrichers import ip_enricher


def run():
    sentry_dsn = os.getenv("SENTRY_DSN")
    if sentry_dsn:
        try:
            sentry_sdk.init(
                dsn=sentry_dsn,
                traces_sample_rate=0.1,
                environment=os.getenv("DOPPLER_ENVIRONMENT", "production"),
            )
        except Exception:
            pass

    with sentry_sdk.start_transaction(op="pipeline", name="AEGIS IOC Pipeline"):
        db = DatabaseManager()
        techniques = {}
        new_iocs = []
        try:
            # ── Phase 1: collection + processing (non-fatal) ──────────────────
            try:
                print("[pipeline] cleaning up expired IOCs ...")
                deleted = db.cleanup_old_iocs()
                print(f"[pipeline] removed {deleted} expired IOCs")
                wb_deleted = db.cleanup_expired_workbenches()
                if wb_deleted:
                    print(f"[pipeline] removed {wb_deleted} expired shared workbenches")

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

                print("[pipeline] collecting from URLhaus ...")
                urlhaus_iocs = urlhaus.collect()
                print(f"[pipeline] URLhaus: {len(urlhaus_iocs)} indicators")

                print("[pipeline] collecting from Feodo Tracker ...")
                feodo_iocs = feodo.collect()
                print(f"[pipeline] FeodoTracker: {len(feodo_iocs)} indicators")

                print("[pipeline] collecting from GreyNoise ...")
                greynoise_iocs = greynoise.collect()
                print(f"[pipeline] GreyNoise: {len(greynoise_iocs)} IPs")

                print("[pipeline] collecting from Emerging Threats ...")
                et_iocs = emerging_threats.collect()
                print(f"[pipeline] EmergingThreats: {len(et_iocs)} IPs")

                # Preserve IP-focused feeds for cross-source enrichment (before dedup)
                ip_collected_iocs = (
                    feodo_iocs
                    + [i for i in tf_iocs if i.get("type") == "ip"]
                    + greynoise_iocs
                    + et_iocs
                )

                raw_iocs = cisa_iocs + otx_iocs + tf_iocs + urlhaus_iocs + feodo_iocs + greynoise_iocs + et_iocs
                print(f"[pipeline] total collected: {len(raw_iocs)}")

                # Deduplicate internally first
                raw_iocs = deduplicator.deduplicate(raw_iocs)
                print(f"[pipeline] after internal deduplication: {len(raw_iocs)}")

                # Separate new from existing; reactivate those already in DB
                existing_values = db.get_existing_values()
                new_iocs      = [ioc for ioc in raw_iocs if ioc.get("value") not in existing_values]
                seen_again    = [ioc for ioc in raw_iocs if ioc.get("value") in existing_values]
                print(f"[pipeline] new indicators to process: {len(new_iocs)}")
                print(f"[pipeline] existing IOCs to reactivate: {len(seen_again)}")
                seen_again_values = [ioc.get("value") for ioc in seen_again if ioc.get("value")]
                db.reactivate_many(seen_again_values)

                # Libera as estruturas de coleta já consumidas antes das fases de
                # normalização/enriquecimento (que criam cópias) — reduz o pico de RAM.
                del raw_iocs, seen_again, seen_again_values

                # Process new IOCs
                if new_iocs:
                    print("[pipeline] normalizing ...")
                    new_iocs = normalizer.normalize(new_iocs)

                    ip_new = [i for i in new_iocs if i.get("type") == "ip"]
                    if ip_new:
                        print(f"[pipeline] enriquecendo {len(ip_new)} IPs novos ...")
                        new_iocs = ip_enricher.enrich_batch(new_iocs, ip_collected_iocs)

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
                    db.insert_many(new_iocs, existing=existing_values)
                    del existing_values
                else:
                    print("[pipeline] loading MITRE ATT&CK techniques for report ...")
                    techniques = mitre.load_techniques()
                    print(f"[pipeline] MITRE: {len(techniques)} techniques loaded")

                del ip_collected_iocs

                print("[pipeline] applying BioSec decay ...")
                db.apply_decay()

                print("[pipeline] recalculating scores (skips if already done) ...")
                db.recalculate_all_scores()

            except Exception as e:
                print(f"[pipeline] collection/processing error (continuing to report): {e}")
                sentry_sdk.capture_exception(e)

            # ── Phase 2: report (always runs regardless of phase 1 outcome) ──
            print("[pipeline] generating report ...")
            stats = db.get_stats()
            trends = db.get_trends(days=30)
            top_iocs = db.get_iocs_paginated(page=1, limit=1000)["iocs"]
            html_report.generate_from_parts(top_iocs, stats, techniques, trends, db.get_total_count())

            # Summary
            total_in_db = db.get_total_count()
            by_severity = stats.get("by_severity", {})
            print("\n── Pipeline complete ──────────────────────────")
            print(f"  New IOCs added:       {len(new_iocs)}")
            print(f"  Total in DB:          {total_in_db}")
            print("  Breakdown by severity (Total):")
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                count = by_severity.get(level, 0)
                print(f"    {level:<10} {count}")
            print("───────────────────────────────────────────────")
            print("[pipeline] report written to output/index.html")
        except Exception as e:
            sentry_sdk.capture_exception(e)
            raise
        finally:
            db.close()


if __name__ == "__main__":
    run()
