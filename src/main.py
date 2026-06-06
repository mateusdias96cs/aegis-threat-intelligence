import os
import sys
import sentry_sdk
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.collectors import cisa, otx, mitre, threatfox
from src.collectors import urlhaus, feodo, greynoise, emerging_threats, dshield, ipsum, spamhaus
from src.processors import normalizer, classifier, deduplicator, warninglist
from src.storage.database import DatabaseManager
from src.reporters import html_report
from src.enrichers import ip_enricher, epss_enricher, shodan_enricher, malwarebazaar_enricher, rdap_enricher
from src.enrichers import circl_pdns_enricher, circl_pssl_enricher
from src.enrichers import geoip_db

# Intervalo mínimo entre execuções do pipeline (idempotência). O run leva ~9 min
# (10:13→10:23 nos logs); 15 min dá folga sobre isso e ainda barra o re-disparo de
# 19 min que aconteceu. Configurável; 0 desliga o guard.
_MIN_RUN_INTERVAL_MIN = int(os.getenv("PIPELINE_MIN_INTERVAL_MIN", "15"))


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
            # ── Idempotency guard ─────────────────────────────────────────────
            # Barra re-disparos próximos (retry do Airflow, GitHub Actions e o POST
            # diário colidindo, duplo-clique manual) que reprocessam APIs e limpam
            # IOCs recém-inseridos. Autoritativo no servidor, vale p/ qualquer gatilho.
            if _MIN_RUN_INTERVAL_MIN > 0:
                since = db.minutes_since_last_run()
                if since is not None and since < _MIN_RUN_INTERVAL_MIN:
                    print(f"[pipeline] já executado há {since:.1f} min "
                          f"(< {_MIN_RUN_INTERVAL_MIN} min) — execução ignorada (idempotência)")
                    return
            db.mark_pipeline_run()

            # ── GeoIP2: garante os .mmdb (Render = FS efêmero) ────────────────
            # Resolve por glob e baixa via MAXMIND_LICENSE_KEY se faltar; sem chave
            # degrada graciosamente (country/asn = None). Nunca lança exception.
            geoip_db.ensure_geoip_db()

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

                print("[pipeline] collecting from DShield/ISC ...")
                dshield_iocs = dshield.collect()
                print(f"[pipeline] DShield: {len(dshield_iocs)} IPs")

                print("[pipeline] collecting from IPsum (agregador de blacklists) ...")
                ipsum_iocs = ipsum.collect()
                print(f"[pipeline] IPsum: {len(ipsum_iocs)} IPs")

                print("[pipeline] collecting from Spamhaus DROP (netblocks) ...")
                spamhaus_iocs = spamhaus.collect()
                print(f"[pipeline] Spamhaus DROP: {len(spamhaus_iocs)} netblocks")

                # Preserve IP-focused feeds for cross-source enrichment (before dedup).
                # Netblocks (Spamhaus DROP) NÃO entram aqui — não são IPs individuais.
                ip_collected_iocs = (
                    feodo_iocs
                    + [i for i in tf_iocs if i.get("type") == "ip"]
                    + greynoise_iocs
                    + et_iocs
                    + dshield_iocs
                    + ipsum_iocs
                )

                raw_iocs = (cisa_iocs + otx_iocs + tf_iocs + urlhaus_iocs + feodo_iocs
                            + greynoise_iocs + et_iocs + dshield_iocs + ipsum_iocs + spamhaus_iocs)
                print(f"[pipeline] total collected: {len(raw_iocs)}")

                # Corroboração entre fontes: mapeia value -> {fontes distintas} ANTES do
                # dedup, que colapsaria as duplicatas e zeraria a diversidade de fontes
                # (sem isto o C do score fica sempre em 33).
                value_sources: dict[str, set] = {}
                for _i in raw_iocs:
                    _v = _i.get("value")
                    if _v:
                        value_sources.setdefault(_v, set()).add(_i.get("source") or "")

                # Proveniência/linhagem (P1): registra QUEM viu QUE IOC e QUANDO,
                # antes do dedup colapsar as duplicatas. Base para timeliness por
                # fonte e (futuro) confiabilidade empírica de fonte.
                try:
                    n_sight = db.record_sightings(value_sources)
                    print(f"[pipeline] sightings recorded: {n_sight} (value,source) pairs")
                except Exception as e:
                    print(f"[pipeline] sightings recording skipped: {e}")

                # Deduplicate internally first
                raw_iocs = deduplicator.deduplicate(raw_iocs)
                print(f"[pipeline] after internal deduplication: {len(raw_iocs)}")

                # Separate new from existing; reactivate those already in DB.
                # Passagem ÚNICA: NÃO materializa `seen_again` como lista de dicts
                # completos. No run diário a maioria dos coletados já existe no banco;
                # guardar só os VALORES dos reativados (e não os dicts inteiros) corta o
                # pico de RAM da janela coleta→split, onde o OOM de ~26k IOCs estourava.
                existing_values = db.get_existing_values()
                new_iocs: list[dict] = []
                seen_again_values: list[str] = []
                for ioc in raw_iocs:
                    val = ioc.get("value")
                    if val in existing_values:
                        if val:
                            seen_again_values.append(val)
                    else:
                        new_iocs.append(ioc)
                print(f"[pipeline] new indicators to process: {len(new_iocs)}")
                print(f"[pipeline] existing IOCs to reactivate: {len(seen_again_values)}")
                db.reactivate_many(seen_again_values)

                # Libera as estruturas de coleta já consumidas antes das fases de
                # normalização/enriquecimento (que criam cópias) — reduz o pico de RAM.
                del raw_iocs, seen_again_values

                # Process new IOCs
                if new_iocs:
                    print("[pipeline] normalizing ...")
                    new_iocs = normalizer.normalize(new_iocs)

                    # Re-filtra duplicados pós-normalização. O split novo/existente
                    # roda ANTES da normalização (compara o valor bruto); ao normalizar
                    # (ex.: URL/domínio em minúsculas, defang, strip), o valor pode
                    # passar a coincidir com um IOC já no banco. Sem isto, esses IOCs
                    # são enriquecidos à toa e depois descartados pelo insert_many —
                    # desperdiçando, em especial, o orçamento limitado e rate-limited
                    # do CIRCL (1 req/s, teto por execução). Re-filtrar aqui garante que
                    # o enriquecimento caia só em IOCs que de fato serão persistidos.
                    _pre = len(new_iocs)
                    new_iocs = [i for i in new_iocs if i.get("value") not in existing_values]
                    if len(new_iocs) != _pre:
                        print(f"[pipeline] pós-normalização: {_pre} -> {len(new_iocs)} "
                              f"({_pre - len(new_iocs)} duplicados normalizados removidos)")

                if new_iocs:
                    # Warninglist (P2): marca IOCs que casam infra legítima conhecida
                    # (cloud/CDN/DNS/Tranco) ANTES do score — o classifier aplica a
                    # penalidade de provável-FP. No-op se data/warninglists vazio.
                    print("[pipeline] checking warninglists (known-good infra) ...")
                    n_fp = sum(1 for i in warninglist.annotate(new_iocs) if i.get("fp_warning"))
                    print(f"[pipeline] warninglist flags: {n_fp} likely false-positives")

                    ip_new = [i for i in new_iocs if i.get("type") == "ip"]
                    if ip_new:
                        print(f"[pipeline] enriquecendo {len(ip_new)} IPs novos ...")
                        new_iocs = ip_enricher.enrich_batch(new_iocs, ip_collected_iocs)
                        print(f"[pipeline] enriquecendo {len(ip_new)} IPs com Shodan InternetDB ...")
                        new_iocs = shodan_enricher.enrich_batch(new_iocs)

                    cve_new = [i for i in new_iocs if i.get("type") == "cve"]
                    if cve_new:
                        print(f"[pipeline] enriquecendo {len(cve_new)} CVEs novos com EPSS ...")
                        new_iocs = epss_enricher.enrich_batch(new_iocs)

                    hash_new = [i for i in new_iocs if i.get("type") == "hash"]
                    if hash_new:
                        print(f"[pipeline] enriquecendo {len(hash_new)} hashes novas com MalwareBazaar ...")
                        new_iocs = malwarebazaar_enricher.enrich_batch(new_iocs)

                    domain_new = [i for i in new_iocs if i.get("type") in ("domain", "url")]
                    if domain_new:
                        print(f"[pipeline] enriquecendo {len(domain_new)} domínios/URLs com RDAP ...")
                        new_iocs = rdap_enricher.enrich_batch(new_iocs)

                    print("[pipeline] classifying ...")
                    new_iocs = classifier.classify(new_iocs)
                    new_iocs = classifier.apply_confidence(new_iocs, value_sources)
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

                    # Completude de contexto (D3) — depois de TODO enriquecimento +
                    # MITRE, mede quantas dimensões o IOC tem preenchidas.
                    print("[pipeline] computing context completeness ...")
                    for ioc in new_iocs:
                        cc = classifier.compute_context_completeness(ioc)
                        ioc["context_score"] = cc["score"]
                        ioc["context_breakdown"] = cc   # dict; insert_many serializa

                    print("[pipeline] saving to database ...")
                    db.insert_many(new_iocs, existing=existing_values)
                    del existing_values
                else:
                    print("[pipeline] loading MITRE ATT&CK techniques for report ...")
                    techniques = mitre.load_techniques()
                    print(f"[pipeline] MITRE: {len(techniques)} techniques loaded")

                del ip_collected_iocs

                # Corrobora IOCs já no banco que reapareceram hoje por uma fonte nova
                # (roda antes do decay para que score_atual seja re-derivado).
                print("[pipeline] corroborating existing IOCs ...")
                db.corroborate_existing(value_sources)
                del value_sources

                print("[pipeline] backfilling corroboration by independent family ...")
                db.backfill_corroboration_families()

                print("[pipeline] applying BioSec decay ...")
                db.apply_decay()

                print("[pipeline] recalculating scores (skips if already done) ...")
                db.recalculate_all_scores()

                # Completude de contexto dos IOCs já no banco (corroboração/enrich
                # podem ter mudado as dimensões preenchidas desde o último run).
                print("[pipeline] backfilling context completeness ...")
                db.backfill_context_completeness()

                # CIRCL pDNS/pSSL: enriquece até 200 IOCs por execução (teto diário).
                # Prioridade: nunca enriquecidos primeiro, depois mais antigos.
                # Roda sobre IOCs já persistidos (domain/ip, score >= 50).
                print("[pipeline] CIRCL enrichment: querying up to 200 IOCs ...")
                circl_iocs = db.get_iocs_for_circl_enrichment(limit=200)
                if circl_iocs:
                    print(f"[pipeline] CIRCL: {len(circl_iocs)} IOCs selecionados para enriquecimento")
                    circl_iocs = circl_pdns_enricher.enrich_batch(circl_iocs)
                    circl_iocs = circl_pssl_enricher.enrich_batch(circl_iocs)
                    saved = db.update_circl_enrichment(circl_iocs)
                    print(f"[pipeline] CIRCL: {saved} IOCs atualizados no banco")
                else:
                    print("[pipeline] CIRCL: nenhum IOC elegível para enriquecimento")

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
