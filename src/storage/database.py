import json
import math
import os
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

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


class Report(Base):
    __tablename__ = "reports"

    id           = Column(Integer, primary_key=True, autoincrement=False)
    html_content = Column(Text, nullable=False)
    generated_at = Column(DateTime, nullable=False)


Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

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

    def insert_many(self, iocs: list[dict]):
        if not iocs:
            return
        existing = self.get_existing_values()
        seen: set = set()
        rows = []
        for ioc in iocs:
            val = ioc.get("value")
            if val in existing or val in seen:
                continue
            seen.add(val)
            cs = ioc.get("confidence_score")
            rows.append({
                "type": ioc.get("type"),
                "value": val,
                "source": ioc.get("source"),
                "severity": ioc.get("severity"),
                "country": ioc.get("country"),
                "abuse_score": ioc.get("abuse_score"),
                "description": ioc.get("description"),
                "first_seen": ioc.get("first_seen"),
                "last_seen": ioc.get("last_seen"),
                "mitre_technique_id": ioc.get("mitre_technique_id"),
                "mitre_tactic": ioc.get("mitre_tactic"),
                "confidence_score": cs,
                "score_original":     float(cs) if cs is not None else None,
                "score_atual":        float(cs) if cs is not None else None,
                "ioc_status":         ioc.get("ioc_status", "ACTIVE"),
                "reactivation_count": ioc.get("reactivation_count", 0),
                "score_breakdown":    ioc.get("score_breakdown"),
            })
        if rows:
            self._session.execute(IOC.__table__.insert(), rows)
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
        rows = self._session.execute(text("SELECT value FROM iocs")).all()
        return {row[0] for row in rows}

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

    def get_ioc_by_value(self, value: str) -> dict | None:
        """Case-insensitive exact lookup; returns a single IOC dict or None."""
        row = self._session.execute(
            text("SELECT * FROM iocs WHERE LOWER(value) = LOWER(:value)"),
            {"value": value},
        ).mappings().fetchone()
        return dict(row) if row else None

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

    # ── BioSec decay ──────────────────────────────────────────────────────────

    _HALF_LIVES: dict = {
        "ip": 15, "url": 7, "domain": 30, "hash": 180, "cve": 365,
    }

    def apply_decay(self) -> int:
        """Recalculates score_atual and ioc_status for every IOC using exponential decay.

        Half-lives (days): ip=15, url=7, domain=30, hash=180, cve=365, default=30.
        Score thresholds: >=20% ACTIVE, 5-20% DECAYED, <5% HISTORICAL.
        IOCs seen today with reactivation_count>0 keep REACTIVATED status.
        """
        today = datetime.utcnow().date()
        rows = self._session.execute(
            text("""
                SELECT id, type, score_original, last_seen, ioc_status, reactivation_count
                FROM iocs
                WHERE score_original IS NOT NULL
                  AND (ioc_status IS NULL OR ioc_status != 'FALSE_POSITIVE')
            """)
        ).mappings().all()

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
            score_atual = score_orig * math.exp(-0.693 * dias / half_life)

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
            self._session.execute(
                text("UPDATE iocs SET score_atual = :score_atual, ioc_status = :ioc_status WHERE id = :id"),
                updates,
            )
            self._session.commit()

        print(f"[decay] applied decay to {len(updates)} IOCs")
        return len(updates)

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
            float(score_original) * (1.0 + 0.2 * reactivation_count)
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
            score_atual = score_orig * math.exp(-0.693 * dias / half_life)
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
        return self._parse_breakdown(dict(row))

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

    def recalculate_all_scores(self) -> int:
        """Recalculates score_original, score_atual, confidence_score, and score_breakdown
        for every IOC that lacks a score_breakdown (first-run migration).
        Processes in batches of 500 to avoid locking the database."""
        from src.processors.classifier import calculate_score_breakdown

        # Pre-check: how many IOCs need recalculation
        total_iocs = self._session.execute(
            text("SELECT COUNT(*) FROM iocs")
        ).fetchone()[0]
        null_count = self._session.execute(
            text("SELECT COUNT(*) FROM iocs WHERE score_breakdown IS NULL")
        ).fetchone()[0]
        print(f"[recalculate] total IOCs in DB: {total_iocs} | missing score_breakdown: {null_count}")

        if null_count == 0:
            print("[recalculate] score_breakdown already present on all IOCs — skipping")
            return 0

        rows = self._session.execute(
            text("""
                SELECT id, type, value, source, abuse_score
                FROM iocs
                WHERE score_breakdown IS NULL
            """)
        ).mappings().all()

        updates = []
        for row in rows:
            ioc_dict = {
                "type":        row["type"],
                "value":       row["value"],
                "source":      row["source"],
                "abuse_score": row["abuse_score"],
            }
            # Corroboration is 1 per row (values are deduplicated in the DB)
            breakdown = calculate_score_breakdown(ioc_dict, source_count=1)
            score     = float(breakdown["score_arredondado"])
            updates.append({
                "id":               row["id"],
                "confidence_score": breakdown["score_arredondado"],
                "score_original":   score,
                "score_atual":      score,
                "score_breakdown":  json.dumps(breakdown, ensure_ascii=False),
            })

        BATCH_SIZE = 500
        total_updated = 0
        for i in range(0, len(updates), BATCH_SIZE):
            batch = updates[i : i + BATCH_SIZE]
            result = self._session.execute(
                text("""
                    UPDATE iocs
                    SET confidence_score = :confidence_score,
                        score_original   = :score_original,
                        score_atual      = :score_atual,
                        score_breakdown  = :score_breakdown
                    WHERE id = :id
                """),
                batch,
            )
            self._session.commit()
            # rowcount may be -1 on some drivers when using executemany; use batch length
            batch_updated = result.rowcount if result.rowcount >= 0 else len(batch)
            total_updated += len(batch)
            print(f"[recalculate] batch {i // BATCH_SIZE + 1}/{-(-len(updates) // BATCH_SIZE)}: "
                  f"{len(batch)} submitted, rowcount={result.rowcount}")

        # Post-update verification
        still_null = self._session.execute(
            text("SELECT COUNT(*) FROM iocs WHERE score_breakdown IS NULL")
        ).fetchone()[0]
        now_populated = self._session.execute(
            text("SELECT COUNT(*) FROM iocs WHERE score_breakdown IS NOT NULL")
        ).fetchone()[0]
        print(f"[recalculate] DONE — populated: {now_populated} | still NULL: {still_null} | total submitted: {total_updated}")
        if still_null > 0:
            print(f"[recalculate] WARNING: {still_null} IOCs still have NULL score_breakdown after update")
        return total_updated

    def cleanup_old_iocs(self) -> int:
        try:
            today = datetime.utcnow().date()

            def _cutoff(days: int) -> str:
                return (today - timedelta(days=days)).strftime("%Y-%m-%d")

            # Python-computed date strings make DELETE dialect-agnostic.
            d1 = self._session.execute(text(
                "DELETE FROM iocs WHERE source = 'AbuseIPDB-Blacklist'"
                " AND SUBSTR(first_seen, 1, 10) < :c"
            ), {"c": _cutoff(7)}).rowcount
            self._session.commit()

            d2 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'ip' AND source = 'ThreatFox'"
                " AND SUBSTR(first_seen, 1, 10) < :c"
            ), {"c": _cutoff(7)}).rowcount
            self._session.commit()

            d3 = self._session.execute(text(
                "DELETE FROM iocs WHERE source = 'FeodoTracker'"
                " AND SUBSTR(first_seen, 1, 10) < :c"
            ), {"c": _cutoff(14)}).rowcount
            self._session.commit()

            d4 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'url' AND description LIKE '%online%'"
                " AND SUBSTR(first_seen, 1, 10) < :c"
            ), {"c": _cutoff(14)}).rowcount
            self._session.commit()

            d5 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'url' AND description NOT LIKE '%online%'"
                " AND SUBSTR(first_seen, 1, 10) < :c"
            ), {"c": _cutoff(30)}).rowcount
            self._session.commit()

            d6 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'domain'"
                " AND SUBSTR(first_seen, 1, 10) < :c"
            ), {"c": _cutoff(30)}).rowcount
            self._session.commit()

            d7 = self._session.execute(text(
                "DELETE FROM iocs WHERE type = 'ip'"
                " AND source NOT IN ('AbuseIPDB-Blacklist', 'ThreatFox', 'FeodoTracker')"
                " AND SUBSTR(first_seen, 1, 10) < :c"
            ), {"c": _cutoff(30)}).rowcount
            self._session.commit()

            d8 = self._session.execute(text(
                "DELETE FROM iocs WHERE type NOT IN ('hash', 'cve', 'ip', 'url', 'domain')"
                " AND source != 'CISA-KEV'"
                " AND SUBSTR(first_seen, 1, 10) < :c"
            ), {"c": _cutoff(90)}).rowcount
            self._session.commit()

            total_deleted = d1 + d2 + d3 + d4 + d5 + d6 + d7 + d8
            print(f"[cleanup] AbuseIPDB-BL: {d1} removed")
            print(f"[cleanup] ThreatFox IPs: {d2} removed")
            print(f"[cleanup] Feodo IPs: {d3} removed")
            print(f"[cleanup] Active URLs: {d4} removed")
            print(f"[cleanup] Offline URLs: {d5} removed")
            print(f"[cleanup] Domains: {d6} removed")
            print(f"[cleanup] Other IPs: {d7} removed")
            print(f"[cleanup] Other: {d8} removed")
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

    # ── report persistence ────────────────────────────────────────────────────

    def save_report(self, html_content: str) -> None:
        """Upsert: always keeps a single row (id=1) with the latest HTML report."""
        now = datetime.utcnow()
        existing = self._session.execute(
            text("SELECT id FROM reports WHERE id = 1")
        ).fetchone()
        if existing:
            self._session.execute(
                text("UPDATE reports SET html_content = :html, generated_at = :ts WHERE id = 1"),
                {"html": html_content, "ts": now},
            )
        else:
            self._session.execute(
                text("INSERT INTO reports (id, html_content, generated_at) VALUES (1, :html, :ts)"),
                {"html": html_content, "ts": now},
            )
        self._session.commit()

    def get_latest_report(self) -> str | None:
        """Returns the HTML content of the most recent saved report, or None."""
        row = self._session.execute(
            text("SELECT html_content FROM reports WHERE id = 1")
        ).fetchone()
        return row[0] if row else None

    def close(self):
        self._session.close()
