import json
import math
import os
from datetime import datetime, timedelta
from itertools import islice
from pathlib import Path

from sqlalchemy import (
    Column, DateTime, Float, Index, Integer, String, Text, UniqueConstraint,
    create_engine, text,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from src.storage.bulk_ops import bulk_update_iocs, bulk_upsert_sightings

_raw_url = os.getenv("DATABASE_URL")

if _raw_url:
    # Railway/Heroku sometimes return postgres:// — SQLAlchemy 2.x requires postgresql://
    if _raw_url.startswith("postgres://"):
        _raw_url = _raw_url.replace("postgres://", "postgresql://", 1)
    engine = create_engine(
        _raw_url,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        connect_args={"connect_timeout": 10, "sslmode": "require"},
    )
else:
    _db_path = "data/iocs.db"
    Path(_db_path).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{_db_path}",
        connect_args={"check_same_thread": False},
    )

Base = declarative_base()


class IOC(Base):
    __tablename__ = "iocs"

    id                 = Column(Integer, primary_key=True, autoincrement=True)
    type               = Column(String)
    value              = Column(String)
    source             = Column(String)
    severity           = Column(String)
    country            = Column(String)
    abuse_score        = Column(Integer)
    description        = Column(String)
    first_seen         = Column(String)
    last_seen          = Column(String)
    mitre_technique_id = Column(String)
    mitre_tactic       = Column(String)
    confidence_score   = Column(Integer)
    # BioSec decay fields
    score_original     = Column(Float)
    score_atual        = Column(Float)
    ioc_status         = Column(String(20), default="ACTIVE")
    reactivation_count = Column(Integer, default=0)
    # BioSec contextualisation fields
    false_positive      = Column(Integer, default=0)   # stored as 0/1 for SQLite compat
    false_positive_note = Column(Text)
    false_positive_at   = Column(String)
    tags                = Column(Text)
    correlated_sources  = Column(Text)
    # BioSec scoring v2
    score_breakdown     = Column(Text)
    # NVD CVSS enrichment
    cvss_score          = Column(Float)
    # AbuseIPDB abuse categories
    abuse_categories    = Column(Text)   # JSON: {"18": 45, "14": 12}
    # GeoLite2-ASN enrichment — número do AS para correlação por infraestrutura
    asn                 = Column(Integer)
    # Campanha real reportada (OTX pulse id / ThreatFox malware) — espinha dorsal
    # de correlação por co-ocorrência verdadeira, não heurística de /24.
    campaign_id         = Column(Text)
    # Ator/grupo atribuído pela fonte (OTX adversary) — "ataque que de fato ocorreu".
    adversary           = Column(Text)
    # Lista JSON de técnicas ATT&CK reais (OTX attack_ids) — Kill Chain confiável.
    mitre_techniques    = Column(Text)
    # EPSS (FIRST.org) — probabilidade de exploração do CVE nos próximos 30 dias.
    epss_score          = Column(Float)
    epss_percentile     = Column(Float)
    # Shodan InternetDB — superfície do IP: {ports, tags, vulns, hostnames} (JSON).
    shodan_data         = Column(Text)
    # MalwareBazaar — contexto da hash: {family, file_type, tags, delivery...} (JSON).
    malware_context     = Column(Text)
    # Completude de Contexto (D3) — quantas dimensões de contexto estão preenchidas.
    context_score       = Column(Integer)
    context_breakdown   = Column(Text)   # JSON: {score, filled, total, dimensions[]}
    # Warninglist (P2) — nome da lista de infra legítima que casou (provável FP).
    fp_warning          = Column(Text)
    # RDAP — ciclo de vida do registro do domínio {registered, expiration, registrar,
    # status, age_days}. Para domains e URLs. age_days < 30 = sinal de risco.
    rdap_data           = Column(Text)
    # CIRCL Passive DNS — histórico de resoluções (domain/ip/url).
    pdns_record_count       = Column(Integer)
    pdns_first_seen         = Column(DateTime)
    pdns_last_seen          = Column(DateTime)
    pdns_resolutions        = Column(Text)   # JSON: últimas resoluções relevantes
    pdns_associated_ips     = Column(Text)   # JSON: IPs associados (query por domínio)
    pdns_associated_domains = Column(Text)   # JSON: domínios associados (query por IP)
    pdns_suspicious         = Column(Integer, default=0)
    pdns_enriched_at        = Column(DateTime)
    # CIRCL Passive SSL — histórico de certificados X.509 por IP.
    pssl_cert_count   = Column(Integer)
    pssl_certificates = Column(Text)   # JSON: primeiros certs (cn/issuer/validade/san)
    pssl_subjects     = Column(Text)   # JSON: CommonNames únicos vistos
    pssl_self_signed  = Column(Integer, default=0)
    pssl_expired      = Column(Integer, default=0)
    pssl_suspicious   = Column(Integer, default=0)
    pssl_enriched_at  = Column(DateTime)


class Report(Base):
    __tablename__ = "reports"

    id           = Column(Integer, primary_key=True, autoincrement=False)
    html_content = Column(Text, nullable=False)
    generated_at = Column(DateTime, nullable=False)


class SharedWorkbench(Base):
    __tablename__ = "shared_workbenches"

    key        = Column(String(8), primary_key=True)
    payload    = Column(Text, nullable=False)   # JSON com pins + notas
    created_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)


class Sighting(Base):
    """Proveniência/linhagem: QUEM (source) viu QUE IOC (value), QUANDO (first/last_seen)
    e QUANTAS vezes (seen_count). Uma linha por par (value, source).

    A tabela `iocs` colapsa o IOC numa única linha (deduplicado); aqui guardamos o
    rastro por fonte ao longo do tempo. É a base para: timeliness real por fonte,
    C com datas verdadeiras, e (frente futura) confiabilidade de fonte EMPÍRICA
    derivada do histórico de falso-positivo. Ver [[research-data-engineering]]."""
    __tablename__ = "sightings"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    value      = Column(String, nullable=False)
    source     = Column(String, nullable=False)
    first_seen = Column(String)   # YYYY-MM-DD — 1ª vez que ESTA fonte viu o IOC
    last_seen  = Column(String)   # YYYY-MM-DD — última vez que ESTA fonte o viu
    seen_count = Column(Integer, default=1)

    __table_args__ = (
        UniqueConstraint("value", "source", name="uq_sightings_value_source"),
        Index("idx_sightings_value", "value"),
    )


class PipelineRun(Base):
    """Marca de início de cada execução do pipeline — base do guard de idempotência.

    O pipeline pode ser disparado por múltiplas fontes (GitHub Actions workflow,
    POST manual em /api/pipeline/run). Persistir o instante do último início
    (autoritativo no servidor) permite pular re-disparos dentro de uma janela
    mínima, independentemente de QUEM disparou."""
    __tablename__ = "pipeline_runs"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, nullable=False)


Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

# ── Índices para queries de correlação (Campaigns) ───────────────────────────
_CAMPAIGN_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_iocs_source       ON iocs (source)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_country      ON iocs (country)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_mitre_tactic ON iocs (mitre_tactic)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_type_status  ON iocs (type, ioc_status)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_first_seen   ON iocs (first_seen)",
]
for _idx_sql in _CAMPAIGN_INDEXES:
    try:
        with engine.connect() as _conn:
            _conn.execute(text(_idx_sql))
            _conn.commit()
    except Exception:
        pass

# ── BioSec migrations (safe — adds columns only if absent) ───────────────────
_DECAY_COLUMNS = [
    ("score_original",     "FLOAT"),
    ("score_atual",        "FLOAT"),
    ("ioc_status",         "VARCHAR(20) DEFAULT 'ACTIVE'"),
    ("reactivation_count", "INTEGER DEFAULT 0"),
    # contextualisation
    ("false_positive",      "INTEGER DEFAULT 0"),
    ("false_positive_note", "TEXT"),
    ("false_positive_at",   "TEXT"),
    ("tags",                "TEXT"),
    ("correlated_sources",  "TEXT"),
    # scoring v2
    ("score_breakdown",     "TEXT"),
    # NVD CVSS enrichment
    ("cvss_score",          "FLOAT"),
    # AbuseIPDB abuse categories
    ("abuse_categories",    "TEXT"),
    # GeoLite2-ASN enrichment
    ("asn",                 "INTEGER"),
    # Campanha real / atribuição / técnicas ATT&CK estruturadas (OTX)
    ("campaign_id",         "TEXT"),
    ("adversary",           "TEXT"),
    ("mitre_techniques",    "TEXT"),
    # EPSS — probabilidade de exploração (FIRST.org)
    ("epss_score",          "FLOAT"),
    ("epss_percentile",     "FLOAT"),
    # Shodan InternetDB — superfície do IP (JSON)
    ("shodan_data",         "TEXT"),
    # MalwareBazaar — contexto da hash (JSON)
    ("malware_context",     "TEXT"),
    # Completude de Contexto (D3)
    ("context_score",       "INTEGER"),
    ("context_breakdown",   "TEXT"),
    # Warninglist / known-good (P2) — qual lista de infra legítima casou (NULL = limpo).
    ("fp_warning",          "TEXT"),
    # RDAP — ciclo de vida do registro do domínio (JSON): registered, expiration,
    # registrar, status, age_days. Para domains e URLs.
    ("rdap_data",           "TEXT"),
    # CIRCL Passive DNS — histórico de resoluções (domain/ip/url).
    ("pdns_record_count",       "INTEGER"),
    ("pdns_first_seen",         "TIMESTAMP"),
    ("pdns_last_seen",          "TIMESTAMP"),
    ("pdns_resolutions",        "TEXT"),
    ("pdns_associated_ips",     "TEXT"),
    ("pdns_associated_domains", "TEXT"),
    ("pdns_suspicious",         "INTEGER DEFAULT 0"),
    ("pdns_enriched_at",        "TIMESTAMP"),
    # CIRCL Passive SSL — histórico de certificados X.509 por IP.
    ("pssl_cert_count",   "INTEGER"),
    ("pssl_certificates", "TEXT"),
    ("pssl_subjects",     "TEXT"),
    ("pssl_self_signed",  "INTEGER DEFAULT 0"),
    ("pssl_expired",      "INTEGER DEFAULT 0"),
    ("pssl_suspicious",   "INTEGER DEFAULT 0"),
    ("pssl_enriched_at",  "TIMESTAMP"),
]
_dialect = engine.dialect.name

for _col_name, _col_def in _DECAY_COLUMNS:
    try:
        _sql = (
            f"ALTER TABLE iocs ADD COLUMN IF NOT EXISTS {_col_name} {_col_def}"
            if _dialect == "postgresql"
            else f"ALTER TABLE iocs ADD COLUMN {_col_name} {_col_def}"
        )
        with engine.connect() as _conn:
            _conn.execute(text(_sql))
            _conn.commit()
    except Exception:
        pass

# Índices criados após a migração das colunas (existem em bancos legados só agora).
for _post_idx in (
    "CREATE INDEX IF NOT EXISTS idx_iocs_asn         ON iocs (asn)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_campaign_id ON iocs (campaign_id)",
):
    try:
        with engine.connect() as _conn:
            _conn.execute(text(_post_idx))
            _conn.commit()
    except Exception:
        pass


class DatabaseManager:
    def __init__(self, db_path: str = "data/iocs.db"):
        self._session: Session = SessionLocal()

    # ── writes ────────────────────────────────────────────────────────────────

    def insert_ioc(self, ioc: dict):
        existing = self._session.execute(
            text("SELECT id FROM iocs WHERE value = :value"),
            {"value": ioc.get("value")},
        ).fetchone()
        if existing:
            return
        self._session.execute(
            text("""
                INSERT INTO iocs
                    (type, value, source, severity, country, abuse_score, description,
                     first_seen, last_seen, mitre_technique_id, mitre_tactic)
                VALUES
                    (:type, :value, :source, :severity, :country, :abuse_score,
                     :description, :first_seen, :last_seen, :mitre_technique_id, :mitre_tactic)
            """),
            {
                "type": ioc.get("type"), "value": ioc.get("value"),
                "source": ioc.get("source"), "severity": ioc.get("severity"),
                "country": ioc.get("country"), "abuse_score": ioc.get("abuse_score"),
                "description": ioc.get("description"), "first_seen": ioc.get("first_seen"),
                "last_seen": ioc.get("last_seen"),
                "mitre_technique_id": ioc.get("mitre_technique_id"),
                "mitre_tactic": ioc.get("mitre_tactic"),
            },
        )
        self._session.commit()

    def insert_many(self, iocs: list[dict], existing: set[str] | None = None):
        if not iocs:
            return
        if existing is None:
            existing = self.get_existing_values()

        seen: set[str] = set()
        BATCH_SIZE = 500
        batch: list[dict] = []

        for ioc in iocs:
            val = ioc.get("value")
            if not val or val in existing or val in seen:
                continue
            seen.add(val)
            cs = ioc.get("confidence_score")
            batch.append({
                "type":               ioc.get("type"),
                "value":              val,
                "source":             ioc.get("source"),
                "severity":           ioc.get("severity"),
                "country":            ioc.get("country"),
                "abuse_score":        ioc.get("abuse_score"),
                "description":        ioc.get("description"),
                "first_seen":         ioc.get("first_seen"),
                "last_seen":          ioc.get("last_seen"),
                "mitre_technique_id": ioc.get("mitre_technique_id"),
                "mitre_tactic":       ioc.get("mitre_tactic"),
                "confidence_score":   cs,
                "score_original":     float(cs) if cs is not None else None,
                "score_atual":        float(cs) if cs is not None else None,
                "ioc_status":         ioc.get("ioc_status", "ACTIVE"),
                "reactivation_count": ioc.get("reactivation_count", 0),
                "score_breakdown":    ioc.get("score_breakdown"),
                "cvss_score":         ioc.get("cvss_score"),
                "abuse_categories":   json.dumps(ioc.get("abuse_categories")) if ioc.get("abuse_categories") else None,
                "correlated_sources": ioc.get("correlated_sources"),
                "asn":                ioc.get("asn"),
                "campaign_id":        ioc.get("campaign_id"),
                "adversary":          ioc.get("adversary"),
                "mitre_techniques":   json.dumps(ioc["mitre_techniques"]) if ioc.get("mitre_techniques") else None,
                "epss_score":         ioc.get("epss_score"),
                "epss_percentile":    ioc.get("epss_percentile"),
                "shodan_data":        json.dumps(ioc["shodan_data"]) if ioc.get("shodan_data") else None,
                "malware_context":    json.dumps(ioc["malware_context"]) if ioc.get("malware_context") else None,
                "context_score":      ioc.get("context_score"),
                "context_breakdown":  json.dumps(ioc["context_breakdown"]) if ioc.get("context_breakdown") else None,
                "fp_warning":         ioc.get("fp_warning"),
                "rdap_data":          json.dumps(ioc["rdap_data"]) if ioc.get("rdap_data") else None,
                # CIRCL Passive DNS
                "pdns_record_count":       ioc.get("pdns_record_count"),
                "pdns_first_seen":         ioc.get("pdns_first_seen"),
                "pdns_last_seen":          ioc.get("pdns_last_seen"),
                "pdns_resolutions":        json.dumps(ioc["pdns_resolutions"]) if ioc.get("pdns_resolutions") else None,
                "pdns_associated_ips":     json.dumps(ioc["pdns_associated_ips"]) if ioc.get("pdns_associated_ips") else None,
                "pdns_associated_domains": json.dumps(ioc["pdns_associated_domains"]) if ioc.get("pdns_associated_domains") else None,
                "pdns_suspicious":         1 if ioc.get("pdns_suspicious") else 0,
                "pdns_enriched_at":        ioc.get("pdns_enriched_at"),
                # CIRCL Passive SSL
                "pssl_cert_count":   ioc.get("pssl_cert_count"),
                "pssl_certificates": json.dumps(ioc["pssl_certificates"]) if ioc.get("pssl_certificates") else None,
                "pssl_subjects":     json.dumps(ioc["pssl_subjects"]) if ioc.get("pssl_subjects") else None,
                "pssl_self_signed":  1 if ioc.get("pssl_self_signed") else 0,
                "pssl_expired":      1 if ioc.get("pssl_expired") else 0,
                "pssl_suspicious":   1 if ioc.get("pssl_suspicious") else 0,
                "pssl_enriched_at":  ioc.get("pssl_enriched_at"),
            })

            if len(batch) >= BATCH_SIZE:
                self._session.execute(IOC.__table__.insert(), batch)
                self._session.commit()
                batch.clear()

        if batch:
            self._session.execute(IOC.__table__.insert(), batch)
            self._session.commit()

    # ── reads ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_breakdown(row: dict) -> dict:
        """Parses score_breakdown from JSON string to dict in-place (if present)."""
        raw = row.get("score_breakdown")
        if raw and isinstance(raw, str):
            try:
                row["score_breakdown"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                pass
        return row

    @staticmethod
    def _parse_abuse_categories(row: dict) -> dict:
        raw = row.get("abuse_categories")
        if raw and isinstance(raw, str):
            try:
                row["abuse_categories"] = {int(k): v for k, v in json.loads(raw).items()}
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        # shodan_data e mitre_techniques: JSON → estrutura, para o drawer/API.
        for _json_field in ("shodan_data", "mitre_techniques", "malware_context", "context_breakdown", "rdap_data",
                            "pdns_resolutions", "pdns_associated_ips", "pdns_associated_domains",
                            "pssl_certificates", "pssl_subjects"):
            _raw = row.get(_json_field)
            if _raw and isinstance(_raw, str):
                try:
                    row[_json_field] = json.loads(_raw)
                except (json.JSONDecodeError, TypeError):
                    pass
        return row

    def get_all_iocs(self) -> list[dict]:
        rows = self._session.execute(text("SELECT * FROM iocs")).mappings().all()
        return [self._parse_breakdown(dict(row)) for row in rows]

    def get_iocs_paginated(
        self,
        page: int = 1,
        limit: int = 50,
        severity: str | None = None,
        ioc_type: str | None = None,
        search: str | None = None,
        status: str | None = None,
        keywords_list: list[str] | None = None,
    ) -> dict:
        page   = max(1, page)
        limit  = min(limit, 500)
        offset = (page - 1) * limit

        conditions: list[str] = []
        params: dict = {}

        if severity:
            conditions.append("severity = :severity")
            params["severity"] = severity.upper()
        if ioc_type:
            conditions.append("type = :ioc_type")
            params["ioc_type"] = ioc_type.lower()
        if search:
            # LOWER(x) LIKE :term works on both SQLite and PostgreSQL
            conditions.append("(LOWER(value) LIKE :search OR LOWER(description) LIKE :search)")
            params["search"] = f"%{search.lower()}%"

        # Status filter — default returns ACTIVE + REACTIVATED + legacy NULLs
        status_upper = (status or "").upper()
        if status_upper == "ALL":
            pass  # no status filter
        elif status_upper in ("ACTIVE", "DECAYED", "HISTORICAL", "REACTIVATED", "FALSE_POSITIVE"):
            conditions.append("ioc_status = :ioc_status")
            params["ioc_status"] = status_upper
        else:
            # default: ACTIVE + REACTIVATED + NULLs (backward compat with pre-decay IOCs)
            conditions.append("(ioc_status IS NULL OR ioc_status IN ('ACTIVE', 'REACTIVATED'))")

        # Relevance keyword pre-filter — OR logic across value + description (capped at 20 terms)
        if keywords_list:
            kw_conds = []
            for i, kw in enumerate(keywords_list[:20]):
                kw_conds.append(
                    f"(LOWER(value) LIKE :kw{i} OR LOWER(description) LIKE :kw{i})"
                )
                params[f"kw{i}"] = f"%{kw.lower()}%"
            conditions.append("(" + " OR ".join(kw_conds) + ")")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        total = self._session.execute(
            text(f"SELECT COUNT(*) FROM iocs {where}"), params
        ).fetchone()[0]

        params["limit"]  = limit
        params["offset"] = offset

        rows = self._session.execute(
            text(f"""
                SELECT * FROM iocs {where}
                ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 0
                        WHEN 'HIGH'     THEN 1
                        WHEN 'MEDIUM'   THEN 2
                        WHEN 'LOW'      THEN 3
                        ELSE 4
                    END,
                    first_seen DESC
                LIMIT :limit OFFSET :offset
            """),
            params,
        ).mappings().all()

        return {
            "total": total,
            "page":  page,
            "pages": max(1, math.ceil(total / limit)),
            "limit": limit,
            "iocs":  [self._parse_breakdown(dict(row)) for row in rows],
        }

    def get_existing_values(self) -> set[str]:
        result = self._session.execute(text("SELECT value FROM iocs"))
        seen: set[str] = set()
        while True:
            chunk = result.fetchmany(2000)
            if not chunk:
                break
            for row in chunk:
                seen.add(row[0])
        return seen

    def get_iocs_by_severity(self, severity: str) -> list[dict]:
        rows = self._session.execute(
            text("SELECT * FROM iocs WHERE severity = :severity"),
            {"severity": severity},
        ).mappings().all()
        return [dict(row) for row in rows]

    def get_stats(self) -> dict:
        by_type = self._session.execute(
            text("SELECT type, COUNT(*) AS count FROM iocs GROUP BY type")
        ).all()
        by_severity = self._session.execute(
            text("SELECT severity, COUNT(*) AS count FROM iocs GROUP BY severity")
        ).all()
        by_status = self._session.execute(
            text("SELECT ioc_status, COUNT(*) AS count FROM iocs GROUP BY ioc_status")
        ).all()
        return {
            "by_type":     {row[0]: row[1] for row in by_type},
            "by_severity": {row[0]: row[1] for row in by_severity},
            "by_status":   {(row[0] or "UNKNOWN"): row[1] for row in by_status},
        }

    def get_total_count(self) -> int:
        return self._session.execute(text("SELECT COUNT(*) FROM iocs")).fetchone()[0]

    def get_ioc_by_value(self, value: str) -> dict | None:
        """Case-insensitive exact lookup; returns a single IOC dict or None."""
        row = self._session.execute(
            text("SELECT * FROM iocs WHERE LOWER(value) = LOWER(:value)"),
            {"value": value},
        ).mappings().fetchone()
        return self._parse_abuse_categories(dict(row)) if row else None

    def get_critical_since(self, hours: int, limit: int = 100) -> list[dict]:
        """Returns CRITICAL IOCs with first_seen within the last N hours, newest first."""
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d")
        rows = self._session.execute(
            text("""
                SELECT * FROM iocs
                WHERE severity = 'CRITICAL' AND first_seen >= :cutoff
                ORDER BY first_seen DESC
                LIMIT :limit
            """),
            {"cutoff": cutoff, "limit": limit},
        ).mappings().all()
        return [dict(row) for row in rows]

    def get_trends(self, days: int = 30) -> list:
        try:
            cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
            # SUBSTR(first_seen, 1, 10) extracts YYYY-MM-DD from both date and datetime
            # strings and is valid in both SQLite and PostgreSQL.
            rows = self._session.execute(
                text("""
                    SELECT SUBSTR(first_seen, 1, 10) AS date,
                           COUNT(*) AS total,
                           SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical,
                           SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END) AS high,
                           SUM(CASE WHEN severity='MEDIUM'   THEN 1 ELSE 0 END) AS medium,
                           SUM(CASE WHEN severity='LOW'      THEN 1 ELSE 0 END) AS low
                    FROM iocs
                    WHERE SUBSTR(first_seen, 1, 10) >= :cutoff
                    GROUP BY SUBSTR(first_seen, 1, 10)
                    ORDER BY date ASC
                """),
                {"cutoff": cutoff},
            ).mappings().all()
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"[database] get_trends failed: {e}")
            return []

    # ── Threat Overview (panorama do SOC) ─────────────────────────────────────

    # IOCs que ainda contam para o panorama operacional (exclui ruído arquivado).
    _ACTIVE_FILTER = "(ioc_status IS NULL OR ioc_status NOT IN ('FALSE_POSITIVE', 'HISTORICAL'))"

    def get_overview(self) -> dict:
        """Agregações para o painel de panorama (Threat Overview).

        Um único método entrega tudo que o dashboard precisa: distribuições,
        rankings de infraestrutura atacante (ASN/país), táticas MITRE, atores e
        campanhas — calculado no banco para não trafegar 9k linhas ao browser.
        """
        s = self._session
        af = self._ACTIVE_FILTER

        def fetch(sql: str) -> list:
            return s.execute(text(sql)).all()

        by_severity = {(r[0] or "UNKNOWN"): r[1] for r in fetch(
            f"SELECT severity, COUNT(*) FROM iocs WHERE {af} GROUP BY severity")}
        by_type = {(r[0] or "unknown"): r[1] for r in fetch(
            f"SELECT type, COUNT(*) FROM iocs WHERE {af} GROUP BY type")}
        by_status = {(r[0] or "UNKNOWN"): r[1] for r in fetch(
            "SELECT ioc_status, COUNT(*) FROM iocs GROUP BY ioc_status")}

        top_sources = [{"source": r[0], "count": r[1]} for r in fetch(
            f"""SELECT source, COUNT(*) c FROM iocs
                WHERE {af} AND source IS NOT NULL AND source != ''
                GROUP BY source ORDER BY c DESC LIMIT 12""")]
        top_asns = [{"asn": r[0], "count": r[1], "country": r[2]} for r in fetch(
            f"""SELECT asn, COUNT(*) c, MAX(country) FROM iocs
                WHERE {af} AND asn IS NOT NULL AND asn > 0
                GROUP BY asn ORDER BY c DESC LIMIT 10""")]
        top_countries = [{"country": r[0], "count": r[1]} for r in fetch(
            f"""SELECT country, COUNT(*) c FROM iocs
                WHERE {af} AND country IS NOT NULL AND country != ''
                GROUP BY country ORDER BY c DESC LIMIT 10""")]
        mitre_tactics = [{"tactic": r[0], "count": r[1]} for r in fetch(
            f"""SELECT mitre_tactic, COUNT(*) c FROM iocs
                WHERE {af} AND mitre_tactic IS NOT NULL AND mitre_tactic != ''
                GROUP BY mitre_tactic ORDER BY c DESC""")]
        top_adversaries = [{"adversary": r[0], "count": r[1]} for r in fetch(
            f"""SELECT adversary, COUNT(*) c FROM iocs
                WHERE {af} AND adversary IS NOT NULL AND adversary != ''
                GROUP BY adversary ORDER BY c DESC LIMIT 10""")]
        top_campaigns = [{"campaign_id": r[0], "count": r[1], "adversary": r[2]} for r in fetch(
            f"""SELECT campaign_id, COUNT(*) c, MAX(adversary) FROM iocs
                WHERE {af} AND campaign_id IS NOT NULL AND campaign_id != ''
                GROUP BY campaign_id ORDER BY c DESC LIMIT 10""")]

        total_active = sum(by_severity.values())
        return {
            "totals": {
                "active":   total_active,
                "critical": by_severity.get("CRITICAL", 0),
                "high":     by_severity.get("HIGH", 0),
                "campaigns": len(top_campaigns),
                "adversaries": len(top_adversaries),
            },
            "by_severity":     by_severity,
            "by_type":         by_type,
            "by_status":       by_status,
            "top_sources":     top_sources,
            "top_asns":        top_asns,
            "top_countries":   top_countries,
            "mitre_tactics":   mitre_tactics,
            "top_adversaries": top_adversaries,
            "top_campaigns":   top_campaigns,
            "timeline":        self.get_trends(30),
        }

    # ── Correlation Graph (entrelaçamento de IOCs) ────────────────────────────

    # Pesos de aresta por força do sinal de correlação (maior = mais confiável).
    _EDGE_WEIGHTS = {"campaign": 3, "asn": 2, "subnet": 2}

    def get_correlation_graph(
        self,
        campaign_id: str | None = None,
        asn: int | None = None,
        tactic: str | None = None,
        country: str | None = None,
        adversary: str | None = None,
        seed: str | None = None,
        limit: int = 120,
    ) -> dict:
        """Monta um grafo navegável (nós = IOCs, arestas = correlações reais).

        As arestas usam SÓ os sinais estruturais que o pipeline já calcula —
        campanha compartilhada (OTX pulse), mesmo ASN e mesmo /24 — que indicam
        infraestrutura comum do atacante. Os nós são limitados (`limit`) e as
        arestas são computadas em memória sobre esse conjunto (O(n²) acotado).
        """
        limit = max(10, min(limit, 250))
        s = self._session
        af = self._ACTIVE_FILTER
        cols = ("value, type, severity, source, score_atual, confidence_score, "
                "campaign_id, asn, mitre_tactic, country, adversary, first_seen")

        if campaign_id:
            where, params = "campaign_id = :cid", {"cid": campaign_id}
        elif asn is not None:
            where, params = "type = 'ip' AND asn = :asn", {"asn": asn}
        elif adversary:
            where, params = "adversary = :adv", {"adv": adversary}
        elif tactic:
            where, params = "mitre_tactic = :tactic", {"tactic": tactic}
        elif country:
            where, params = "country = :country", {"country": country}
        elif seed:
            # Nós = o IOC semente + os que compartilham sua campanha/ASN/-24.
            anchor = s.execute(
                text(f"SELECT {cols} FROM iocs WHERE LOWER(value) = LOWER(:v)"),
                {"v": seed},
            ).mappings().fetchone()
            if not anchor:
                return {"nodes": [], "edges": [], "filter": {"seed": seed}}
            a = dict(anchor)
            net = ""
            if a.get("type") == "ip" and (a.get("value") or "").count(".") == 3:
                net = a["value"].rsplit(".", 1)[0] + ".%"
            rows = s.execute(text(f"""
                SELECT {cols} FROM iocs
                WHERE {af} AND LOWER(value) != LOWER(:v) AND (
                    (:cid != '' AND campaign_id = :cid)
                    OR (:asn != -1 AND type = 'ip' AND asn = :asn)
                    OR (:net != '' AND value LIKE :net)
                )
                LIMIT :limit
            """), {
                "v": a["value"], "cid": a.get("campaign_id") or "",
                "asn": a.get("asn") if a.get("asn") is not None else -1,
                "net": net, "limit": limit - 1,
            }).mappings().all()
            return self._build_graph([a] + [dict(r) for r in rows], {"seed": seed})
        else:
            # Default: clusters completos das maiores campanhas (visão mais útil).
            where = f"""campaign_id IN (
                SELECT campaign_id FROM iocs
                WHERE {af} AND campaign_id IS NOT NULL AND campaign_id != ''
                GROUP BY campaign_id ORDER BY COUNT(*) DESC LIMIT 8
            )"""
            params = {}

        rows = s.execute(
            text(f"SELECT {cols} FROM iocs WHERE {af} AND ({where}) LIMIT :limit"),
            {**params, "limit": limit},
        ).mappings().all()
        flt = {"campaign_id": campaign_id, "asn": asn, "tactic": tactic,
               "country": country, "adversary": adversary}
        return self._build_graph([dict(r) for r in rows], {k: v for k, v in flt.items() if v})

    def _build_graph(self, rows: list[dict], flt: dict) -> dict:
        """Converte linhas de IOC em um grafo hub-and-spoke.

        Cada sinal de correlação (campanha, ASN, /24) vira um NÓ HUB e os IOCs se
        ligam a ele — em vez de conectar todos os pares (que vira um emaranhado
        N²). Dois IOCs ligados ao mesmo hub estão correlacionados; o cluster fica
        visualmente óbvio. Hubs com um único IOC são podados (não há correlação).
        """
        from collections import Counter

        nodes: list[dict] = []
        hubs: dict[str, dict] = {}
        edges: list[dict] = []

        def hub(hub_id: str, label: str, hub_type: str) -> str:
            if hub_id not in hubs:
                hubs[hub_id] = {
                    "id": hub_id, "label": label,
                    "node_kind": "hub", "hub_type": hub_type,
                }
            return hub_id

        for r in rows:
            val = r["value"]
            score = r.get("score_atual")
            if score is None:
                score = r.get("confidence_score") or 0
            nodes.append({
                "id":          val,
                "label":       (val or "")[:42],
                "node_kind":   "ioc",
                "type":        r.get("type"),
                "severity":    (r.get("severity") or "MEDIUM").upper(),
                "score":       round(float(score), 1),
                "source":      r.get("source"),
                "campaign_id": r.get("campaign_id"),
                "asn":         r.get("asn"),
                "tactic":      r.get("mitre_tactic"),
                "country":     r.get("country"),
                "adversary":   r.get("adversary"),
            })

            cid = r.get("campaign_id")
            if cid:
                label = r.get("adversary") or f"Campanha {str(cid)[:8]}"
                hid = hub(f"campaign:{cid}", label, "campaign")
                edges.append({"from": val, "to": hid, "kind": "campaign", "weight": 3})

            # Ator atribuído: liga IOCs do MESMO adversário mesmo em campanhas
            # (pulses) distintas — atribuição é o sinal de correlação mais forte.
            adv = r.get("adversary")
            if adv:
                hid = hub(f"adversary:{adv}", adv, "adversary")
                edges.append({"from": val, "to": hid, "kind": "adversary", "weight": 3})

            if r.get("type") == "ip" and r.get("asn") and r["asn"] > 0:
                hid = hub(f"asn:{r['asn']}", f"AS{r['asn']}", "asn")
                edges.append({"from": val, "to": hid, "kind": "asn", "weight": 2})

            if r.get("type") == "ip" and (val or "").count(".") == 3 and ":" not in (val or ""):
                net = val.rsplit(".", 1)[0] + ".0/24"
                hid = hub(f"subnet:{net}", net, "subnet")
                edges.append({"from": val, "to": hid, "kind": "subnet", "weight": 2})

        # Poda hubs triviais: um hub com um só IOC não evidencia correlação.
        spokes = Counter(e["to"] for e in edges)
        keep = {h for h, c in spokes.items() if c >= 2}
        kept_hubs = [h for hid, h in hubs.items() if hid in keep]
        edges = [e for e in edges if e["to"] in keep]

        # Community detection (Louvain): clusters de campanha/infraestrutura que
        # NÃO compartilham um único sinal explícito, mas se conectam por sobreposição
        # de hubs (mesma campanha + mesmo ASN, etc.). Colore os nós no frontend.
        communities = self._detect_communities(edges)
        for n in nodes:
            n["community"] = communities.get(n["id"], -1)
        for h in kept_hubs:
            h["community"] = communities.get(h["id"], -1)

        return {"nodes": nodes + kept_hubs, "edges": edges, "filter": flt}

    @staticmethod
    def _detect_communities(edges: list[dict]) -> dict:
        """Particiona o grafo bipartite (IOC↔hub) em comunidades via Louvain.
        IOCs que se conectam pelos mesmos hubs caem na mesma comunidade — revela
        clusters que nenhum sinal isolado evidencia. Degrada para componentes
        conexas (ou vazio) se as libs não estiverem disponíveis."""
        if not edges:
            return {}
        from collections import Counter
        try:
            import networkx as nx
            import community as community_louvain  # python-louvain
        except ImportError:
            return {}
        g = nx.Graph()
        for e in edges:
            g.add_edge(e["from"], e["to"], weight=e.get("weight", 1))
        try:
            partition = community_louvain.best_partition(g, weight="weight", random_state=42)
        except Exception:
            # fallback: cada componente conexa é uma comunidade
            partition = {}
            for i, comp in enumerate(nx.connected_components(g)):
                for node in comp:
                    partition[node] = i
        # Renumera por tamanho (maior comunidade = 0) p/ cores estáveis no frontend.
        sizes = Counter(partition.values())
        order = {raw: rank for rank, (raw, _) in enumerate(sizes.most_common())}
        return {node: order[c] for node, c in partition.items()}

    # ── BioSec decay ──────────────────────────────────────────────────────────

    _HALF_LIVES: dict = {
        "ip": 15, "url": 7, "domain": 30, "hash": 180, "cve": 365,
        # netblock (Spamhaus DROP): alocação de rede é estável — meia-vida longa.
        "netblock": 90,
    }

    def apply_decay(self) -> int:
        """Recalculates score_atual and ioc_status for every IOC using exponential decay.

        Half-lives (days): ip=15, url=7, domain=30, hash=180, cve=365, default=30.
        Score thresholds: >=20% ACTIVE, 5-20% DECAYED, <5% HISTORICAL.
        IOCs seen today with reactivation_count>0 keep REACTIVATED status.
        """
        today = datetime.utcnow().date()
        BATCH_SIZE = 1000
        last_id = 0
        total = 0

        # Ao decair para DECAYED/HISTORICAL, libera o score_breakdown (~782 bytes/IOC,
        # ~70% do tamanho de cada registro). O CASE preserva o breakdown dos IOCs que
        # continuam ACTIVE/REACTIVATED sem precisar lê-lo de volta para a memória.
        # Para ACTIVE/REACTIVATED, score_breakdown = score_breakdown (no-op).
        # No PostgreSQL cada batch vira um único UPDATE via UNNEST (ver bulk_update_iocs);
        # este statement por-linha é o fallback usado só no SQLite local.
        update_stmt = text("""
            UPDATE iocs SET
                score_atual = :score_atual,
                ioc_status = :ioc_status,
                score_breakdown = CASE
                    WHEN :ioc_status IN ('DECAYED', 'HISTORICAL') THEN NULL
                    ELSE score_breakdown
                END
            WHERE id = :id
        """)
        decay_set_raw = {
            "score_breakdown": (
                "CASE WHEN u.ioc_status IN ('DECAYED', 'HISTORICAL') "
                "THEN NULL ELSE iocs.score_breakdown END"
            )
        }

        # Keyset pagination por id: o pico de memória fica limitado a um lote
        # (não O(total do banco)), evitando OOM no Render conforme o banco cresce.
        # O UPDATE nunca define FALSE_POSITIVE e a varredura é por id crescente,
        # então nenhuma linha é relida nem perdida — resultado idêntico ao anterior.
        while True:
            rows = self._session.execute(
                text("""
                    SELECT id, type, score_original, last_seen, ioc_status, reactivation_count
                    FROM iocs
                    WHERE score_original IS NOT NULL
                      AND (ioc_status IS NULL OR ioc_status != 'FALSE_POSITIVE')
                      AND id > :last_id
                    ORDER BY id
                    LIMIT :batch
                """),
                {"last_id": last_id, "batch": BATCH_SIZE},
            ).mappings().all()
            if not rows:
                break
            last_id = rows[-1]["id"]

            updates = []
            for row in rows:
                half_life = self._HALF_LIVES.get(row["type"] or "", 30)
                last_seen_raw = str(row["last_seen"] or "")[:10]
                try:
                    last_seen = datetime.strptime(last_seen_raw, "%Y-%m-%d").date()
                except (ValueError, TypeError):
                    last_seen = today

                dias = max(0, (today - last_seen).days)
                score_orig = float(row["score_original"])
                score_atual = min(100.0, score_orig * math.exp(-0.693 * dias / half_life))

                reactivation_count = row["reactivation_count"] or 0
                if last_seen == today and reactivation_count > 0:
                    ioc_status = "REACTIVATED"
                elif score_atual >= 0.20 * score_orig:
                    ioc_status = "ACTIVE"
                elif score_atual >= 0.05 * score_orig:
                    ioc_status = "DECAYED"
                else:
                    ioc_status = "HISTORICAL"

                updates.append({"id": row["id"], "score_atual": score_atual, "ioc_status": ioc_status})

            if updates:
                bulk_update_iocs(
                    self._session, updates,
                    columns={"score_atual": "double precision", "ioc_status": "text"},
                    set_raw=decay_set_raw,
                    fallback_stmt=update_stmt,
                )
                self._session.commit()
                total += len(updates)
            del rows, updates

        print(f"[decay] applied decay to {total} IOCs")
        return total

    def reactivate_ioc(self, value: str) -> None:
        """Updates last_seen, reactivation_count, score_atual, and ioc_status for a known IOC.

        Called when an existing IOC reappears in a new collection.
        Only sets REACTIVATED status if the IOC was previously DECAYED or HISTORICAL.
        """
        today = datetime.utcnow().strftime("%Y-%m-%d")
        row = self._session.execute(
            text("SELECT id, score_original, ioc_status, reactivation_count FROM iocs WHERE value = :value"),
            {"value": value},
        ).fetchone()
        if not row:
            return

        ioc_id, score_original, current_status, reactivation_count = row
        reactivation_count = (reactivation_count or 0) + 1

        score_atual = (
            min(100.0, float(score_original) * (1.0 + 0.2 * reactivation_count))
            if score_original is not None
            else None
        )

        new_status = (
            "REACTIVATED" if current_status in ("DECAYED", "HISTORICAL") else (current_status or "ACTIVE")
        )

        self._session.execute(
            text("""
                UPDATE iocs
                SET last_seen = :last_seen,
                    reactivation_count = :count,
                    score_atual = :score_atual,
                    ioc_status = :status
                WHERE id = :id
            """),
            {
                "last_seen": today,
                "count": reactivation_count,
                "score_atual": score_atual,
                "status": new_status,
                "id": ioc_id,
            },
        )
        self._session.commit()

    def reactivate_many(self, values: list[str]) -> None:
        """Reativação em lote: substitui N commits individuais por batches de 500."""
        if not values:
            return
        today = datetime.utcnow().strftime("%Y-%m-%d")
        BATCH_SIZE = 500
        for i in range(0, len(values), BATCH_SIZE):
            batch = values[i:i + BATCH_SIZE]
            placeholders = ",".join(f":v{j}" for j in range(len(batch)))
            params = {f"v{j}": v for j, v in enumerate(batch)}
            self._session.execute(
                text(f"""
                    UPDATE iocs
                    SET last_seen = '{today}',
                        reactivation_count = COALESCE(reactivation_count, 0) + 1,
                        ioc_status = CASE
                            WHEN ioc_status IN ('DECAYED', 'HISTORICAL') THEN 'REACTIVATED'
                            ELSE COALESCE(ioc_status, 'ACTIVE')
                        END
                    WHERE value IN ({placeholders})
                      AND (ioc_status IS NULL OR ioc_status != 'FALSE_POSITIVE')
                """),
                params,
            )
            self._session.commit()
            print(f"[reactivate_many] batch {i//BATCH_SIZE + 1}: {len(batch)} IOCs reativados")

    def corroborate_existing(self, value_sources: dict[str, set]) -> int:
        """Corrobora IOCs já no banco com as fontes observadas na coleta de hoje.

        Um IP listado hoje pelo GreyNoise que já estava no banco via Feodo deixa de
        contar como "1 fonte": funde as fontes em `correlated_sources` e recalcula o
        score (C sobe de 33 → 66/100). `score_atual` é re-derivado em seguida por
        `apply_decay`, então só gravamos `score_original`/breakdown aqui.

        Idempotente: só atualiza quando há uma fonte realmente nova; reexecutar com o
        mesmo lote não altera nada.
        """
        if not value_sources:
            return 0
        from src.processors.classifier import calculate_score_breakdown

        values  = list(value_sources.keys())
        BATCH   = 500
        updated = 0
        update_stmt = text("""
            UPDATE iocs SET
                correlated_sources = :correlated_sources,
                confidence_score   = :confidence_score,
                score_original     = :score_original,
                score_breakdown    = :score_breakdown
            WHERE id = :id
        """)

        for i in range(0, len(values), BATCH):
            batch = values[i:i + BATCH]
            ph     = ",".join(f":v{j}" for j in range(len(batch)))
            params = {f"v{j}": v for j, v in enumerate(batch)}
            rows = self._session.execute(text(f"""
                SELECT id, type, value, source, abuse_score, cvss_score, correlated_sources,
                       epss_score, epss_percentile, fp_warning, rdap_data
                FROM iocs
                WHERE value IN ({ph})
                  AND (ioc_status IS NULL OR ioc_status != 'FALSE_POSITIVE')
            """), params).mappings().all()

            updates = []
            for row in rows:
                today_sources = value_sources.get(row["value"], set())
                existing: set = set()
                raw = row["correlated_sources"]
                if raw:
                    try:
                        existing = set(json.loads(raw))
                    except (json.JSONDecodeError, TypeError):
                        existing = set()
                if row["source"]:
                    existing.add(row["source"])

                merged = {s for s in (existing | today_sources) if s}
                # Só recalcula se uma fonte nova entrou e há corroboração real (>=2).
                if len(merged) <= len(existing) or len(merged) < 2:
                    continue

                raw_rdap = row["rdap_data"]
                breakdown = calculate_score_breakdown({
                    "type":            row["type"],
                    "value":           row["value"],
                    "source":          row["source"],
                    "abuse_score":     row["abuse_score"],
                    "cvss_score":      row["cvss_score"],
                    "epss_score":      row["epss_score"],
                    "epss_percentile": row["epss_percentile"],
                    "fp_warning":      row["fp_warning"],
                    "rdap_data":       json.loads(raw_rdap) if raw_rdap else None,
                }, sources=merged)
                score = float(breakdown["score_arredondado"])
                updates.append({
                    "id":                 row["id"],
                    "correlated_sources": json.dumps(sorted(merged), ensure_ascii=False),
                    "confidence_score":   breakdown["score_arredondado"],
                    "score_original":     score,
                    "score_breakdown":    json.dumps(breakdown, ensure_ascii=False),
                })

            if updates:
                self._session.execute(update_stmt, updates)
                self._session.commit()
                updated += len(updates)
            del rows, updates

        if updated:
            print(f"[corroborate] {updated} IOCs existentes corroborados por nova fonte")
        return updated

    def backfill_corroboration_families(self) -> int:
        """Recalcula o C dos IOCs multi-fonte existentes com a regra de FAMÍLIAS
        independentes (feeds redundantes da mesma organização não somam).

        Corrige registros pontuados antes da mudança de modelo — ex.: um IOC visto
        por ThreatFox+URLhaus (ambos abuse.ch) tinha C=66 pela contagem antiga e
        passa a C=33. Conjunto é pequeno (só IOCs com correlated_sources) e o write
        só acontece quando o C realmente muda — idempotente e barato.

        Roda ANTES do decay (que re-deriva score_atual a partir do score_original).
        """
        from src.processors.classifier import calculate_score_breakdown

        rows = self._session.execute(text("""
            SELECT id, type, value, source, abuse_score, cvss_score,
                   correlated_sources, score_breakdown, epss_score, epss_percentile,
                   fp_warning, rdap_data
            FROM iocs
            WHERE correlated_sources IS NOT NULL
              AND (ioc_status IS NULL OR ioc_status != 'FALSE_POSITIVE')
        """)).mappings().all()

        update_stmt = text("""
            UPDATE iocs SET
                confidence_score = :confidence_score,
                score_original   = :score_original,
                score_breakdown  = :score_breakdown
            WHERE id = :id
        """)

        updates = []
        for row in rows:
            src_set = {row["source"]} if row["source"] else set()
            try:
                src_set |= set(json.loads(row["correlated_sources"]))
            except (json.JSONDecodeError, TypeError):
                pass

            raw_rdap = row.get("rdap_data")
            breakdown = calculate_score_breakdown({
                "type":            row["type"],
                "value":           row["value"],
                "source":          row["source"],
                "abuse_score":     row["abuse_score"],
                "cvss_score":      row["cvss_score"],
                "epss_score":      row["epss_score"],
                "epss_percentile": row["epss_percentile"],
                "fp_warning":      row.get("fp_warning"),
                "rdap_data":       json.loads(raw_rdap) if raw_rdap else None,
            }, sources=src_set)
            new_score = breakdown["score_arredondado"]

            # Grava se o score mudou OU se o breakdown ainda está no formato antigo
            # (sem o campo `familias`) — assim o drawer fica consistente. Pula só
            # quando nada muda, evitando reescrever à toa.
            old_score, old_has_families = None, False
            if row["score_breakdown"]:
                try:
                    old_bd = json.loads(row["score_breakdown"])
                    old_score = old_bd.get("score_arredondado")
                    old_has_families = "familias" in old_bd.get("corroboration", {})
                except (json.JSONDecodeError, TypeError):
                    pass
            if old_score == new_score and old_has_families:
                continue

            updates.append({
                "id":               row["id"],
                "confidence_score": new_score,
                "score_original":   float(new_score),
                "score_breakdown":  json.dumps(breakdown, ensure_ascii=False),
            })

        if updates:
            bulk_update_iocs(
                self._session, updates,
                columns={
                    "confidence_score": "integer",
                    "score_original":   "double precision",
                    "score_breakdown":  "text",
                },
                fallback_stmt=update_stmt,
            )
            self._session.commit()
            print(f"[backfill] {len(updates)} IOCs multi-fonte recalculados por família independente")
        return len(updates)

    def backfill_context_completeness(self) -> int:
        """(Re)calcula a Completude de Contexto (D3) de todos os IOCs a partir das
        colunas já no banco. Streaming por id para não carregar tudo na memória."""
        from src.processors.classifier import compute_context_completeness

        BATCH = 1000
        last_id = 0
        total = 0
        upd = text(
            "UPDATE iocs SET context_score = :context_score, "
            "context_breakdown = :context_breakdown WHERE id = :id"
        )
        while True:
            rows = self._session.execute(text("""
                SELECT id, type, country, asn, abuse_score, shodan_data, malware_context,
                       cvss_score, epss_score, epss_percentile, mitre_tactic, mitre_technique_id,
                       campaign_id, adversary, correlated_sources
                FROM iocs WHERE id > :last ORDER BY id LIMIT :batch
            """), {"last": last_id, "batch": BATCH}).mappings().all()
            if not rows:
                break
            last_id = rows[-1]["id"]
            updates = []
            for row in rows:
                cc = compute_context_completeness(dict(row))
                updates.append({
                    "context_score": cc["score"],
                    "context_breakdown": json.dumps(cc, ensure_ascii=False),
                    "id": row["id"],
                })
            if updates:
                bulk_update_iocs(
                    self._session, updates,
                    columns={"context_score": "integer", "context_breakdown": "text"},
                    fallback_stmt=upd,
                )
                self._session.commit()
                total += len(updates)
            del rows, updates
        print(f"[context] completude de contexto calculada para {total} IOCs")
        return total

    def get_decay_stats(self) -> dict:
        """Returns IOC count grouped by ioc_status for health checks."""
        rows = self._session.execute(
            text("SELECT ioc_status, COUNT(*) AS count FROM iocs GROUP BY ioc_status")
        ).all()
        return {(row[0] or "UNKNOWN"): row[1] for row in rows}

    # ── BioSec contextualisation ──────────────────────────────────────────────

    def mark_false_positive(self, value: str, note: str = "") -> bool:
        """Flags an IOC as a false positive, reducing its score by 80%."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        row = self._session.execute(
            text("SELECT id, score_atual FROM iocs WHERE LOWER(value) = LOWER(:value)"),
            {"value": value},
        ).fetchone()
        if not row:
            return False
        ioc_id, score_atual = row
        new_score = float(score_atual or 0) * 0.2
        self._session.execute(
            text("""
                UPDATE iocs
                SET false_positive = 1,
                    false_positive_note = :note,
                    false_positive_at = :at,
                    score_atual = :score,
                    ioc_status = 'FALSE_POSITIVE'
                WHERE id = :id
            """),
            {"note": note, "at": today, "score": new_score, "id": ioc_id},
        )
        self._session.commit()
        return True

    def unmark_false_positive(self, value: str) -> bool:
        """Reverts a false-positive flag and restores the natural decay status."""
        today = datetime.utcnow().date()
        row = self._session.execute(
            text("""
                SELECT id, type, score_original, last_seen, reactivation_count
                FROM iocs WHERE LOWER(value) = LOWER(:value)
            """),
            {"value": value},
        ).fetchone()
        if not row:
            return False
        ioc_id, ioc_type, score_original, last_seen_raw, reactivation_count = row
        if score_original is not None:
            half_life = self._HALF_LIVES.get(ioc_type or "", 30)
            try:
                last_seen = datetime.strptime(str(last_seen_raw or "")[:10], "%Y-%m-%d").date()
            except (ValueError, TypeError):
                last_seen = today
            dias = max(0, (today - last_seen).days)
            score_orig = float(score_original)
            score_atual = min(100.0, score_orig * math.exp(-0.693 * dias / half_life))
            rc = reactivation_count or 0
            if last_seen == today and rc > 0:
                ioc_status = "REACTIVATED"
            elif score_atual >= 0.20 * score_orig:
                ioc_status = "ACTIVE"
            elif score_atual >= 0.05 * score_orig:
                ioc_status = "DECAYED"
            else:
                ioc_status = "HISTORICAL"
        else:
            score_atual = None
            ioc_status = "ACTIVE"
        self._session.execute(
            text("""
                UPDATE iocs
                SET false_positive = 0,
                    false_positive_note = NULL,
                    false_positive_at = NULL,
                    score_atual = :score,
                    ioc_status = :status
                WHERE id = :id
            """),
            {"score": score_atual, "status": ioc_status, "id": ioc_id},
        )
        self._session.commit()
        return True

    def get_ioc_context(self, value: str) -> dict | None:
        """Returns all fields of a single IOC by value (case-insensitive).
        score_breakdown is returned as a parsed dict when present."""
        row = self._session.execute(
            text("SELECT * FROM iocs WHERE LOWER(value) = LOWER(:value)"),
            {"value": value},
        ).mappings().fetchone()
        if not row:
            return None
        ctx = self._parse_abuse_categories(self._parse_breakdown(dict(row)))
        # Proveniência: linha do tempo de quais fontes viram o IOC e quando.
        ctx["sightings"] = self.get_sightings(value)
        # Admiralty (P4): garante o grade mesmo em breakdowns legados (derivado em
        # serve-time do próprio breakdown, sem recomputar o score).
        bd = ctx.get("score_breakdown")
        if isinstance(bd, dict) and "admiralty" not in bd:
            from src.processors.classifier import admiralty_for
            adm = admiralty_for(bd, ctx)
            if adm:
                bd["admiralty"] = adm
        return ctx

    def get_correlated_iocs(self, source: str, exclude_value: str, limit: int = 5) -> list[dict]:
        """Returns recent IOCs from the same source, excluding the anchor IOC."""
        if not source:
            return []
        rows = self._session.execute(
            text("""
                SELECT value, type, severity, ioc_status
                FROM iocs
                WHERE source = :source AND LOWER(value) != LOWER(:exclude)
                ORDER BY first_seen DESC
                LIMIT :limit
            """),
            {"source": source, "exclude": exclude_value, "limit": limit},
        ).mappings().all()
        return [dict(row) for row in rows]

    # ── Proveniência (sightings) ────────────────────────────────────────────────
    def record_sightings(self, value_sources: dict[str, set], day: str | None = None) -> int:
        """Registra/atualiza a proveniência da coleta de hoje: para cada par
        (value, source) faz upsert — insere com first/last_seen=hoje, ou incrementa
        seen_count e atualiza last_seen se o par já existe.

        `value_sources` (value -> {fontes}) é o mesmo dict que o pipeline já monta
        ANTES do dedup, então cada par aparece uma vez por execução (1 incremento).
        Idempotência por DIA: reexecutar no mesmo dia conta como "visto de novo"
        (seen_count sobe) — fiel à semântica de sighting. ON CONFLICT funciona igual
        em SQLite (3.24+) e PostgreSQL."""
        if not value_sources:
            return 0
        day = day or datetime.utcnow().strftime("%Y-%m-%d")

        # Gera os pares (value, source) sob demanda — NÃO materializa a lista inteira
        # (~dezenas de milhares de dicts) de uma vez, que somava ao pico de RAM da
        # coleta. Consome em lotes de 500, mesmo padrão das demais escritas em lote.
        def _pairs():
            for v, srcs in value_sources.items():
                if not v:
                    continue
                for s in srcs:
                    if s:
                        yield {"value": v, "source": s, "day": day}

        # No PostgreSQL cada batch vira um único INSERT ... SELECT FROM UNNEST(...)
        # ON CONFLICT (ver bulk_upsert_sightings); no SQLite cai no executemany.
        BATCH = 500
        total = 0
        batch_no = 0
        pairs = _pairs()
        while True:
            chunk = list(islice(pairs, BATCH))
            if not chunk:
                break
            bulk_upsert_sightings(self._session, chunk, day)
            self._session.commit()
            batch_no += 1
            total += len(chunk)
            print(f"[sightings] batch {batch_no}: {len(chunk)} pares registrados")
        return total

    def get_sightings(self, value: str) -> list[dict]:
        """Linha do tempo de proveniência de um IOC: cada fonte que o reportou, com
        primeira/última observação e contagem. Ordenado por first_seen (quem viu
        primeiro encabeça). Usado no drawer."""
        rows = self._session.execute(
            text("""
                SELECT source, first_seen, last_seen, seen_count
                FROM sightings
                WHERE LOWER(value) = LOWER(:value)
                ORDER BY first_seen ASC, seen_count DESC
            """),
            {"value": value},
        ).mappings().all()
        return [dict(r) for r in rows]

    # IOCs que DEVEM ter score_breakdown: ativos, reativados ou legados sem status.
    # IOCs DECAYED/HISTORICAL têm o breakdown liberado de propósito (apply_decay) —
    # este filtro impede que recalculate o reconstrua e desfaça a compactação.
    _NEEDS_BREAKDOWN = (
        "score_breakdown IS NULL "
        "AND (ioc_status IS NULL OR ioc_status IN ('ACTIVE', 'REACTIVATED'))"
    )

    def recalculate_all_scores(self) -> int:
        """Recalculates score_original, score_atual, confidence_score, and score_breakdown
        for two groups:
          1. ACTIVE/REACTIVATED/legacy IOCs without score_breakdown (first-run migration
             + IOCs reativados que tiveram o breakdown liberado enquanto decaídos).
          2. CVEs that already have a score_breakdown using the default T=80 placeholder
             but now have a real cvss_score from NVD.
        Processes in batches of 500 to avoid locking the database."""
        from src.processors.classifier import calculate_score_breakdown

        total_iocs = self._session.execute(
            text("SELECT COUNT(*) FROM iocs")
        ).fetchone()[0]
        null_count = self._session.execute(
            text(f"SELECT COUNT(*) FROM iocs WHERE {self._NEEDS_BREAKDOWN}")
        ).fetchone()[0]
        stale_cvss_count = self._session.execute(
            text("""
                SELECT COUNT(*) FROM iocs
                WHERE type = 'cve'
                  AND cvss_score IS NOT NULL
                  AND score_breakdown LIKE '%padrão CVE%'
            """)
        ).fetchone()[0]
        print(
            f"[recalculate] total IOCs: {total_iocs} | "
            f"sem score_breakdown: {null_count} | "
            f"CVEs com CVSS desatualizado: {stale_cvss_count}"
        )

        if null_count == 0 and stale_cvss_count == 0:
            print("[recalculate] nenhum IOC precisa de recálculo — pulando")
            return 0

        def _build_updates(rows):
            result = []
            for row in rows:
                raw_rdap = row.get("rdap_data")
                ioc_dict = {
                    "type":            row["type"],
                    "value":           row["value"],
                    "source":          row["source"],
                    "abuse_score":     row["abuse_score"],
                    "cvss_score":      row["cvss_score"],
                    "epss_score":      row["epss_score"],
                    "epss_percentile": row["epss_percentile"],
                    "fp_warning":      row.get("fp_warning"),
                    "rdap_data":       json.loads(raw_rdap) if raw_rdap else None,
                }
                # Preserva a corroboração já registrada (C consistente após reativação).
                # Reconstrói o conjunto de feeds para recalcular C por família.
                src_set = {row["source"]} if row["source"] else set()
                raw_cs = row.get("correlated_sources")
                if raw_cs:
                    try:
                        src_set |= set(json.loads(raw_cs))
                    except (json.JSONDecodeError, TypeError):
                        pass
                breakdown = calculate_score_breakdown(ioc_dict, sources=src_set)
                score     = float(breakdown["score_arredondado"])
                result.append({
                    "id":               row["id"],
                    "confidence_score": breakdown["score_arredondado"],
                    "score_original":   score,
                    "score_atual":      score,
                    "score_breakdown":  json.dumps(breakdown, ensure_ascii=False),
                })
            return result

        update_stmt = text("""
            UPDATE iocs
            SET confidence_score = :confidence_score,
                score_original   = :score_original,
                score_atual      = :score_atual,
                score_breakdown  = :score_breakdown
            WHERE id = :id
        """)

        def _stream_recalc(where_clause: str, label: str) -> int:
            """Keyset pagination por id: lê E grava em lotes, mantendo o pico de
            memória limitado a um lote (não O(total)). Cada lote processado tem
            score_breakdown preenchido, saindo do filtro; a varredura por id
            crescente garante cobertura completa sem reler nem entrar em loop."""
            BATCH_SIZE = 500
            last_id = 0
            processed = 0
            batch_no = 0
            while True:
                rows = self._session.execute(
                    text(f"""
                        SELECT id, type, value, source, abuse_score, cvss_score,
                               correlated_sources, epss_score, epss_percentile,
                               fp_warning, rdap_data
                        FROM iocs
                        WHERE {where_clause} AND id > :last_id
                        ORDER BY id
                        LIMIT :batch
                    """),
                    {"last_id": last_id, "batch": BATCH_SIZE},
                ).mappings().all()
                if not rows:
                    break
                last_id = rows[-1]["id"]
                updates = _build_updates(rows)
                if updates:
                    rowcount = bulk_update_iocs(
                        self._session, updates,
                        columns={
                            "confidence_score": "integer",
                            "score_original":   "double precision",
                            "score_atual":      "double precision",
                            "score_breakdown":  "text",
                        },
                        fallback_stmt=update_stmt,
                    )
                    self._session.commit()
                    batch_no += 1
                    processed += len(updates)
                    print(
                        f"[recalculate:{label}] batch {batch_no}: "
                        f"{len(updates)} submetidos, rowcount={rowcount}"
                    )
                del rows, updates
            return processed

        total_updated = 0

        # --- Grupo 1: IOCs ativos/reativados/legados sem score_breakdown ---
        if null_count > 0:
            count_null = _stream_recalc(self._NEEDS_BREAKDOWN, "sem_breakdown")
            total_updated += count_null
            print(f"[recalculate] {count_null} IOCs sem score_breakdown recalculados")

        # --- Grupo 2: CVEs com CVSS real mas breakdown com placeholder padrão ---
        if stale_cvss_count > 0:
            count_stale = _stream_recalc(
                "type = 'cve' AND cvss_score IS NOT NULL AND score_breakdown LIKE '%padrão CVE%'",
                "cvss_atualizado",
            )
            total_updated += count_stale
            print(f"[recalculate] {count_stale} CVEs com CVSS atualizado")

        # Post-update verification — conta apenas os que DEVERIAM ter breakdown.
        # DECAYED/HISTORICAL com breakdown NULL são esperados (compactação), não erro.
        still_null = self._session.execute(
            text(f"SELECT COUNT(*) FROM iocs WHERE {self._NEEDS_BREAKDOWN}")
        ).fetchone()[0]
        now_populated = self._session.execute(
            text("SELECT COUNT(*) FROM iocs WHERE score_breakdown IS NOT NULL")
        ).fetchone()[0]
        print(
            f"[recalculate] DONE — populados: {now_populated} | "
            f"ativos ainda NULL: {still_null} | total submetidos: {total_updated}"
        )
        if still_null > 0:
            print(f"[recalculate] WARNING: {still_null} IOCs ativos ainda têm score_breakdown NULL após atualização")
        return total_updated

    def get_iocs_for_circl_enrichment(self, limit: int = 200) -> list[dict]:
        """Returns up to `limit` active domain/ip IOCs (score >= 50) for CIRCL enrichment.

        Ordered by: never enriched (pdns_enriched_at IS NULL) first, then oldest enriched.
        Query runs on the DB so nothing is loaded into memory beyond `limit` rows.
        """
        try:
            rows = self._session.execute(text("""
                SELECT id, value, type, score_atual, severity, abuse_score
                FROM iocs
                WHERE type IN ('domain', 'ip')
                  AND score_atual >= 50
                  AND ioc_status = 'ACTIVE'
                ORDER BY CASE WHEN pdns_enriched_at IS NULL THEN 0 ELSE 1 END ASC,
                         pdns_enriched_at ASC
                LIMIT :limit
            """), {"limit": limit}).mappings().all()
            return [dict(r) for r in rows]
        except Exception as e:
            print(f"[db] get_iocs_for_circl_enrichment error: {e}")
            return []

    def update_circl_enrichment(self, iocs: list[dict]) -> int:
        """Persists CIRCL pDNS/pSSL enrichment fields for existing IOCs.

        Only updates IOCs where the enricher set pdns_enriched_at or pssl_enriched_at,
        meaning the API returned data (not 404/error). Unrecognized IOCs are skipped.
        """
        updated = 0
        for ioc in iocs:
            val = ioc.get("value")
            if not val:
                continue
            fields: dict = {}
            if ioc.get("pdns_enriched_at") is not None:
                fields.update({
                    "pdns_record_count":       ioc.get("pdns_record_count"),
                    "pdns_first_seen":         ioc.get("pdns_first_seen"),
                    "pdns_last_seen":          ioc.get("pdns_last_seen"),
                    "pdns_resolutions":        json.dumps(ioc["pdns_resolutions"]) if ioc.get("pdns_resolutions") else None,
                    "pdns_associated_ips":     json.dumps(ioc["pdns_associated_ips"]) if ioc.get("pdns_associated_ips") else None,
                    "pdns_associated_domains": json.dumps(ioc["pdns_associated_domains"]) if ioc.get("pdns_associated_domains") else None,
                    "pdns_suspicious":         1 if ioc.get("pdns_suspicious") else 0,
                    "pdns_enriched_at":        ioc["pdns_enriched_at"],
                })
            if ioc.get("pssl_enriched_at") is not None:
                fields.update({
                    "pssl_cert_count":   ioc.get("pssl_cert_count"),
                    "pssl_certificates": json.dumps(ioc["pssl_certificates"]) if ioc.get("pssl_certificates") else None,
                    "pssl_subjects":     json.dumps(ioc["pssl_subjects"]) if ioc.get("pssl_subjects") else None,
                    "pssl_self_signed":  1 if ioc.get("pssl_self_signed") else 0,
                    "pssl_expired":      1 if ioc.get("pssl_expired") else 0,
                    "pssl_suspicious":   1 if ioc.get("pssl_suspicious") else 0,
                    "pssl_enriched_at":  ioc["pssl_enriched_at"],
                })
            if not fields:
                continue
            set_clause = ", ".join(f"{k} = :{k}" for k in fields)
            fields["_value"] = val
            try:
                self._session.execute(
                    text(f"UPDATE iocs SET {set_clause} WHERE value = :_value"),
                    fields,
                )
                updated += 1
            except Exception as e:
                print(f"[db] update_circl_enrichment error for {val}: {e}")
        if updated:
            self._session.commit()
        return updated

    def cleanup_old_iocs(self) -> int:
        try:
            today = datetime.utcnow().date()

            def _cutoff(days: int) -> str:
                return (today - timedelta(days=days)).strftime("%Y-%m-%d")

            # Python-computed date strings make DELETE dialect-agnostic.
            #
            # TTL por last_seen (NÃO first_seen). Vários feeds reportam first_seen com
            # a data REAL de origem do IOC (ThreatFox export "recent" traz first_seen de
            # até anos atrás; DShield = data do ataque; Feodo = surgimento do C2). Usar
            # first_seen como TTL purgava IOCs ATIVOS (ainda no feed de hoje) logo no run
            # seguinte — churn e perda de volume. last_seen = recência de OBSERVAÇÃO:
            # todo collector grava last_seen=hoje e reactivate_many o mantém fresco, então
            # quem continua aparecendo sobrevive e só some N dias após sair dos feeds.
            #
            # NB: a fonte AbuseIPDB-Blacklist foi descontinuada (limite do free tier
            # quebrava o pipeline); registros remanescentes caem na regra geral de IP (d7).
            d2 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'ip' AND source = 'ThreatFox'"
                " AND SUBSTR(last_seen, 1, 10) < :c"
            ), {"c": _cutoff(7)}).rowcount
            self._session.commit()

            d3 = self._session.execute(text(
                "DELETE FROM iocs WHERE source = 'FeodoTracker'"
                " AND SUBSTR(last_seen, 1, 10) < :c"
            ), {"c": _cutoff(14)}).rowcount
            self._session.commit()

            d4 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'url' AND description LIKE '%online%'"
                " AND SUBSTR(last_seen, 1, 10) < :c"
            ), {"c": _cutoff(14)}).rowcount
            self._session.commit()

            d5 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'url' AND description NOT LIKE '%online%'"
                " AND SUBSTR(last_seen, 1, 10) < :c"
            ), {"c": _cutoff(30)}).rowcount
            self._session.commit()

            d6 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'domain'"
                " AND SUBSTR(last_seen, 1, 10) < :c"
            ), {"c": _cutoff(30)}).rowcount
            self._session.commit()

            d7 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'ip'"
                " AND source NOT IN ('ThreatFox', 'FeodoTracker')"
                " AND SUBSTR(last_seen, 1, 10) < :c"
            ), {"c": _cutoff(30)}).rowcount
            self._session.commit()

            d8 = self._session.execute(text(
                "DELETE FROM iocs WHERE type NOT IN ('hash', 'cve', 'ip', 'url', 'domain')"
                " AND source != 'CISA-KEV'"
                " AND SUBSTR(last_seen, 1, 10) < :c"
            ), {"c": _cutoff(90)}).rowcount
            self._session.commit()

            # IOCs já decaídos a HISTORICAL (score < 5% do original) e sem reaparecer
            # há 90+ dias não têm valor operacional — removidos para dar teto ao banco.
            # CISA-KEV é preservado (CVEs institucionais com validade regulatória longa).
            d9 = self._session.execute(text(
                "DELETE FROM iocs WHERE ioc_status = 'HISTORICAL'"
                " AND source != 'CISA-KEV'"
                " AND SUBSTR(last_seen, 1, 10) < :c"
            ), {"c": _cutoff(90)}).rowcount
            self._session.commit()

            total_deleted = d2 + d3 + d4 + d5 + d6 + d7 + d8 + d9
            print(f"[cleanup] ThreatFox IPs: {d2} removed")
            print(f"[cleanup] Feodo IPs: {d3} removed")
            print(f"[cleanup] Active URLs: {d4} removed")
            print(f"[cleanup] Offline URLs: {d5} removed")
            print(f"[cleanup] Domains: {d6} removed")
            print(f"[cleanup] Other IPs: {d7} removed")
            print(f"[cleanup] Other: {d8} removed")
            print(f"[cleanup] HISTORICAL (90d+): {d9} removed")
            print(f"[cleanup] Total removed: {total_deleted}")
            return total_deleted
        except Exception as e:
            print(f"[database] cleanup_old_iocs failed: {e}")
            return 0

    def get_last_updated(self) -> str | None:
        try:
            result = self._session.execute(
                text("SELECT MAX(first_seen) FROM iocs")
            ).fetchone()
            return result[0] if result and result[0] else None
        except Exception as e:
            print(f"[db] get_last_updated error: {e}")
            return None

    # ── pipeline idempotency ───────────────────────────────────────────────────

    def minutes_since_last_run(self) -> float | None:
        """Minutos desde o início do último run registrado, ou None se nunca rodou.

        Fonte da verdade no servidor para o guard de idempotência: vale para
        qualquer gatilho (Airflow, GitHub Actions, POST manual)."""
        try:
            result = self._session.execute(
                text("SELECT MAX(started_at) FROM pipeline_runs")
            ).fetchone()
            last = result[0] if result else None
            if not last:
                return None
            if isinstance(last, str):  # SQLite devolve string
                last = datetime.fromisoformat(last)
            return (datetime.utcnow() - last).total_seconds() / 60.0
        except Exception as e:
            print(f"[db] minutes_since_last_run error: {e}")
            return None

    def mark_pipeline_run(self) -> None:
        """Registra AGORA como início de um run. Chamado só quando o run vai de fato rodar."""
        try:
            self._session.execute(
                text("INSERT INTO pipeline_runs (started_at) VALUES (:ts)"),
                {"ts": datetime.utcnow()},
            )
            self._session.commit()
        except Exception as e:
            self._session.rollback()
            print(f"[db] mark_pipeline_run error: {e}")

    # ── report persistence ────────────────────────────────────────────────────

    def save_report(self, html_content: str) -> None:
        """Upsert (id=1) using dialect-appropriate atomic syntax."""
        now = datetime.utcnow()
        if _dialect == "postgresql":
            self._session.execute(
                text("""
                    INSERT INTO reports (id, html_content, generated_at)
                    VALUES (1, :html, :ts)
                    ON CONFLICT (id) DO UPDATE SET
                        html_content = EXCLUDED.html_content,
                        generated_at = EXCLUDED.generated_at
                """),
                {"html": html_content, "ts": now},
            )
        else:
            self._session.execute(
                text("INSERT OR REPLACE INTO reports (id, html_content, generated_at) VALUES (1, :html, :ts)"),
                {"html": html_content, "ts": now},
            )
        self._session.commit()

    def get_latest_report(self) -> str | None:
        """Returns the HTML content of the most recent saved report, or None."""
        row = self._session.execute(
            text("SELECT html_content FROM reports WHERE id = 1")
        ).fetchone()
        return row[0] if row else None

    # ── Analyst Workbench ─────────────────────────────────────────────────────────

    def save_shared_workbench(self, key: str, payload: str, expires_at: str) -> None:
        """Salva um workbench compartilhado com chave aleatória."""
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        if _dialect == "postgresql":
            self._session.execute(text("""
                INSERT INTO shared_workbenches (key, payload, created_at, expires_at)
                VALUES (:key, :payload, :created_at, :expires_at)
                ON CONFLICT (key) DO UPDATE SET
                    payload    = EXCLUDED.payload,
                    created_at = EXCLUDED.created_at,
                    expires_at = EXCLUDED.expires_at
            """), {"key": key, "payload": payload, "created_at": now, "expires_at": expires_at})
        else:
            self._session.execute(text("""
                INSERT OR REPLACE INTO shared_workbenches (key, payload, created_at, expires_at)
                VALUES (:key, :payload, :created_at, :expires_at)
            """), {"key": key, "payload": payload, "created_at": now, "expires_at": expires_at})
        self._session.commit()

    def get_shared_workbench(self, key: str) -> dict | None:
        """Retorna workbench se existir e não tiver expirado."""
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        row = self._session.execute(
            text("""
                SELECT payload, created_at, expires_at
                FROM shared_workbenches
                WHERE key = :key AND expires_at > :now
            """),
            {"key": key, "now": now}
        ).fetchone()
        if not row:
            return None
        return {
            "payload":    row[0],
            "created_at": row[1],
            "expires_at": row[2],
        }

    def cleanup_expired_workbenches(self) -> int:
        """Remove workbenches expirados. Chamado no pipeline."""
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        result = self._session.execute(
            text("DELETE FROM shared_workbenches WHERE expires_at <= :now"),
            {"now": now}
        )
        self._session.commit()
        return result.rowcount

    def get_campaign_context(self, value: str, ioc_type: str, ioc_data: dict) -> dict:
        """
        Retorna contexto de campanha para um IOC específico.
        Tratamento diferenciado por tipo: ip, cve, hash, url, domain.
        Todas as queries são leves e indexadas.
        """
        ioc_type = (ioc_type or "").lower()
        source   = ioc_data.get("source", "")
        country  = ioc_data.get("country", "")
        tactic   = ioc_data.get("mitre_tactic", "")
        desc     = ioc_data.get("description", "")
        first_seen = (ioc_data.get("first_seen") or "")[:10]

        # Janela temporal: 7 dias antes e depois do first_seen
        try:
            from datetime import datetime, timedelta
            fs_date  = datetime.strptime(first_seen, "%Y-%m-%d")
            win_from = (fs_date - timedelta(days=7)).strftime("%Y-%m-%d")
            win_to   = (fs_date + timedelta(days=7)).strftime("%Y-%m-%d")
        except Exception:
            win_from = win_to = first_seen

        similar = []

        # ── Correlação por campanha REAL (OTX pulse) — prioridade máxima ─────────
        # IOCs que compartilham campaign_id co-ocorreram num MESMO ataque reportado
        # por um analista (adversário + técnicas ATT&CK atribuídos), não por
        # heurística de /24. É o sinal de correlação mais confiável do sistema.
        campaign_id   = ioc_data.get("campaign_id")
        campaign_peers: list[dict] = []
        if campaign_id:
            rows = self._session.execute(text("""
                SELECT value, type, severity, source, mitre_tactic, description,
                       first_seen, ioc_status, adversary, country, abuse_categories
                FROM iocs
                WHERE campaign_id = :cid
                  AND LOWER(value) != LOWER(:value)
                  AND (ioc_status IS NULL OR ioc_status NOT IN ('FALSE_POSITIVE', 'HISTORICAL'))
                ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END,
                         first_seen DESC
                LIMIT 10
            """), {"cid": campaign_id, "value": value}).mappings().all()
            campaign_peers = [dict(r) | {"correlation": "campaign"} for r in rows]

        if ioc_type == "ip":
            # Sinais fortes de "mesma infraestrutura do atacante": mesmo /24 (IPv4)
            # e mesmo ASN. Têm prioridade sobre país/fonte (ruidosos: país agrupa
            # milhões de IPs; "mesma fonte" agrupa o feed inteiro).
            anchor_ip  = (value or "").split(":")[0]
            net_prefix = ""
            if anchor_ip.count(".") == 3 and ":" not in anchor_ip:
                net_prefix = anchor_ip.rsplit(".", 1)[0] + "."
            net_like   = (net_prefix + "%") if net_prefix else ""
            # Sentinela -1 (nenhum AS real é negativo) mantém o operando tipado —
            # evita "could not determine data type" no PostgreSQL com asn ausente.
            anchor_asn = ioc_data.get("asn")
            anchor_asn = anchor_asn if anchor_asn is not None else -1

            # Só os sinais ESTRUTURAIS (mesmo /24, mesmo ASN) indicam infraestrutura
            # comum do atacante. País e "mesma fonte" eram ruído: a maioria das
            # blocklists grava first_seen = data de ingestão, então a janela temporal
            # não discrimina e dois IPs sem relação real, ingeridos no mesmo dia,
            # apareciam "correlacionados" só por compartilhar país/feed.
            rows = self._session.execute(text("""
                SELECT value, severity, source, mitre_tactic, country, abuse_categories,
                       first_seen, ioc_status, reactivation_count, asn
                FROM iocs
                WHERE type = 'ip'
                  AND LOWER(value) != LOWER(:value)
                  AND (
                    (:net_prefix != '' AND value LIKE :net_like)
                    OR (asn = :asn)
                  )
                  AND SUBSTR(first_seen, 1, 10) BETWEEN :win_from AND :win_to
                  AND (ioc_status IS NULL OR ioc_status NOT IN ('FALSE_POSITIVE', 'HISTORICAL'))
                ORDER BY
                    CASE
                        WHEN :net_prefix != '' AND value LIKE :net_like THEN 0
                        ELSE 1
                    END,
                    CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END,
                    first_seen DESC
                LIMIT 8
            """), {
                "value": value,
                "net_prefix": net_prefix, "net_like": net_like, "asn": anchor_asn,
                "win_from": win_from, "win_to": win_to
            }).mappings().all()
            similar = [dict(r) for r in rows]

        elif ioc_type == "cve":
            vendor = desc.split(" - ")[0].strip() if " - " in desc else ""
            if vendor:
                rows = self._session.execute(text("""
                    SELECT value, severity, source, description, cvss_score, first_seen, ioc_status
                    FROM iocs
                    WHERE type = 'cve'
                      AND LOWER(value) != LOWER(:value)
                      AND LOWER(description) LIKE :vendor_pat
                      AND SUBSTR(first_seen, 1, 10) BETWEEN :win_from AND :win_to
                      AND (ioc_status IS NULL OR ioc_status NOT IN ('FALSE_POSITIVE'))
                    ORDER BY cvss_score DESC NULLS LAST, first_seen DESC
                    LIMIT 6
                """), {
                    "value": value,
                    "vendor_pat": f"%{vendor.lower()[:30]}%",
                    "win_from": win_from, "win_to": win_to
                }).mappings().all()
            else:
                rows = self._session.execute(text("""
                    SELECT value, severity, source, description, cvss_score, first_seen, ioc_status
                    FROM iocs
                    WHERE type = 'cve'
                      AND LOWER(value) != LOWER(:value)
                      AND source = :source
                      AND SUBSTR(first_seen, 1, 10) BETWEEN :win_from AND :win_to
                    ORDER BY cvss_score DESC NULLS LAST
                    LIMIT 6
                """), {"value": value, "source": source,
                       "win_from": win_from, "win_to": win_to}).mappings().all()
            similar = [dict(r) for r in rows]

        elif ioc_type == "hash":
            malware_family = ""
            if "malware:" in desc.lower():
                malware_family = desc.split(":")[-1].strip().split(" ")[0]
            elif " - " in desc:
                malware_family = desc.split(" - ")[0].strip()

            if malware_family and len(malware_family) > 3:
                rows = self._session.execute(text("""
                    SELECT value, severity, source, description, first_seen, mitre_tactic, ioc_status
                    FROM iocs
                    WHERE type = 'hash'
                      AND LOWER(value) != LOWER(:value)
                      AND LOWER(description) LIKE :family_pat
                      AND SUBSTR(first_seen, 1, 10) BETWEEN :win_from AND :win_to
                      AND (ioc_status IS NULL OR ioc_status NOT IN ('FALSE_POSITIVE'))
                    ORDER BY first_seen DESC
                    LIMIT 6
                """), {
                    "value": value,
                    "family_pat": f"%{malware_family.lower()[:20]}%",
                    "win_from": win_from, "win_to": win_to
                }).mappings().all()
            else:
                rows = self._session.execute(text("""
                    SELECT value, severity, source, description, first_seen, mitre_tactic, ioc_status
                    FROM iocs
                    WHERE type = 'hash'
                      AND LOWER(value) != LOWER(:value)
                      AND source = :source
                      AND SUBSTR(first_seen, 1, 10) BETWEEN :win_from AND :win_to
                    ORDER BY first_seen DESC
                    LIMIT 6
                """), {"value": value, "source": source,
                       "win_from": win_from, "win_to": win_to}).mappings().all()
            similar = [dict(r) for r in rows]

        elif ioc_type == "url":
            domain_base = ""
            try:
                from urllib.parse import urlparse
                parsed = urlparse(value if value.startswith("http") else "http://" + value)
                domain_base = parsed.netloc.lower().lstrip("www.")
            except Exception:
                pass

            if domain_base:
                rows = self._session.execute(text("""
                    SELECT value, severity, source, description, first_seen, ioc_status
                    FROM iocs
                    WHERE type = 'url'
                      AND LOWER(value) != LOWER(:value)
                      AND LOWER(value) LIKE :domain_pat
                      AND SUBSTR(first_seen, 1, 10) BETWEEN :win_from AND :win_to
                      AND (ioc_status IS NULL OR ioc_status NOT IN ('FALSE_POSITIVE'))
                    ORDER BY first_seen DESC
                    LIMIT 6
                """), {
                    "value": value,
                    "domain_pat": f"%{domain_base[:40]}%",
                    "win_from": win_from, "win_to": win_to
                }).mappings().all()
            else:
                rows = self._session.execute(text("""
                    SELECT value, severity, source, description, first_seen, ioc_status
                    FROM iocs
                    WHERE type = 'url'
                      AND LOWER(value) != LOWER(:value)
                      AND source = :source
                      AND SUBSTR(first_seen, 1, 10) BETWEEN :win_from AND :win_to
                    ORDER BY first_seen DESC
                    LIMIT 6
                """), {"value": value, "source": source,
                       "win_from": win_from, "win_to": win_to}).mappings().all()
            similar = [dict(r) for r in rows]

        elif ioc_type == "domain":
            rows = self._session.execute(text("""
                SELECT value, severity, source, description, first_seen, mitre_tactic, ioc_status
                FROM iocs
                WHERE type = 'domain'
                  AND LOWER(value) != LOWER(:value)
                  AND (source = :source OR mitre_tactic = :tactic)
                  AND SUBSTR(first_seen, 1, 10) BETWEEN :win_from AND :win_to
                  AND (ioc_status IS NULL OR ioc_status NOT IN ('FALSE_POSITIVE'))
                ORDER BY first_seen DESC
                LIMIT 6
            """), {
                "value": value, "source": source, "tactic": tactic or "",
                "win_from": win_from, "win_to": win_to
            }).mappings().all()
            similar = [dict(r) for r in rows]

        # Peers de campanha real têm prioridade; heurísticas preenchem o restante
        # sem duplicar valores já trazidos pela campanha.
        if campaign_peers:
            seen_vals = {c["value"] for c in campaign_peers}
            similar = campaign_peers + [s for s in similar if s.get("value") not in seen_vals]

        # Parse abuse_categories para similar IPs
        import json as _json
        for s in similar:
            raw = s.get("abuse_categories")
            if raw and isinstance(raw, str):
                try:
                    s["abuse_categories"] = {int(k): v for k, v in _json.loads(raw).items()}
                except Exception:
                    s["abuse_categories"] = {}

        return {
            "ioc_type":      ioc_type,
            "value":         value,
            "window":        {"from": win_from, "to": win_to},
            "campaign_id":   campaign_id,
            "adversary":     ioc_data.get("adversary"),
            "similar":       similar,
            "similar_count": len(similar),
        }

    def close(self):
        self._session.close()
