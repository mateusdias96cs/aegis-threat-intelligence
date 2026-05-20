import os
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, text
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


class Report(Base):
    __tablename__ = "reports"

    id           = Column(Integer, primary_key=True, autoincrement=False)
    html_content = Column(Text, nullable=False)
    generated_at = Column(DateTime, nullable=False)


Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)


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
                "confidence_score": ioc.get("confidence_score"),
            })
        if rows:
            self._session.execute(IOC.__table__.insert(), rows)
            self._session.commit()

    # ── reads ─────────────────────────────────────────────────────────────────

    def get_all_iocs(self) -> list[dict]:
        rows = self._session.execute(text("SELECT * FROM iocs")).mappings().all()
        return [dict(row) for row in rows]

    def get_iocs_paginated(
        self,
        page: int = 1,
        limit: int = 50,
        severity: str | None = None,
        ioc_type: str | None = None,
        search: str | None = None,
    ) -> dict:
        import math
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
            "iocs":  [dict(row) for row in rows],
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
        return {
            "by_type":     {row[0]: row[1] for row in by_type},
            "by_severity": {row[0]: row[1] for row in by_severity},
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
