import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


class DatabaseManager:
    def __init__(self, db_path: str = "data/iocs.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_table()
        self._migrate()

    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                type         TEXT,
                value        TEXT,
                source       TEXT,
                severity     TEXT,
                country      TEXT,
                abuse_score  INTEGER,
                description  TEXT,
                first_seen   TEXT,
                last_seen    TEXT
            )
        """)
        self.conn.commit()

    def _migrate(self):
        for col_def in ("mitre_technique_id TEXT", "mitre_tactic TEXT", "confidence_score INTEGER"):
            try:
                self.conn.execute(f"ALTER TABLE iocs ADD COLUMN {col_def}")
                self.conn.commit()
            except sqlite3.OperationalError:
                pass

    def insert_ioc(self, ioc: dict):
        existing = self.conn.execute(
            "SELECT id FROM iocs WHERE value = ?", (ioc.get("value"),)
        ).fetchone()
        if existing:
            return
        self.conn.execute(
            """
            INSERT INTO iocs
                (type, value, source, severity, country, abuse_score, description,
                 first_seen, last_seen, mitre_technique_id, mitre_tactic)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ioc.get("type"), ioc.get("value"), ioc.get("source"),
                ioc.get("severity"), ioc.get("country"), ioc.get("abuse_score"),
                ioc.get("description"), ioc.get("first_seen"), ioc.get("last_seen"),
                ioc.get("mitre_technique_id"), ioc.get("mitre_tactic"),
            ),
        )
        self.conn.commit()

    def insert_many(self, iocs: list[dict]):
        if not iocs:
            return
        existing = {
            row[0]
            for row in self.conn.execute("SELECT value FROM iocs").fetchall()
        }
        seen: set = set()
        rows = []
        for ioc in iocs:
            val = ioc.get("value")
            if val in existing or val in seen:
                continue
            seen.add(val)
            rows.append((
                ioc.get("type"), val, ioc.get("source"),
                ioc.get("severity"), ioc.get("country"), ioc.get("abuse_score"),
                ioc.get("description"), ioc.get("first_seen"), ioc.get("last_seen"),
                ioc.get("mitre_technique_id"), ioc.get("mitre_tactic"),
                ioc.get("confidence_score"),
            ))
        if rows:
            self.conn.executemany(
                """
                INSERT INTO iocs
                    (type, value, source, severity, country, abuse_score, description,
                     first_seen, last_seen, mitre_technique_id, mitre_tactic,
                     confidence_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            self.conn.commit()

    def get_all_iocs(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM iocs").fetchall()
        return [dict(row) for row in rows]

    def get_existing_values(self) -> set[str]:
        rows = self.conn.execute("SELECT value FROM iocs").fetchall()
        return {row["value"] for row in rows}

    def get_iocs_by_severity(self, severity: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM iocs WHERE severity = ?", (severity,)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_stats(self) -> dict:
        by_type = self.conn.execute(
            "SELECT type, COUNT(*) AS count FROM iocs GROUP BY type"
        ).fetchall()
        by_severity = self.conn.execute(
            "SELECT severity, COUNT(*) AS count FROM iocs GROUP BY severity"
        ).fetchall()
        return {
            "by_type": {row["type"]: row["count"] for row in by_type},
            "by_severity": {row["severity"]: row["count"] for row in by_severity},
        }

    def get_ioc_by_value(self, value: str) -> dict | None:
        """Case-insensitive exact lookup; returns a single IOC dict or None."""
        row = self.conn.execute(
            "SELECT * FROM iocs WHERE LOWER(value) = LOWER(?)", (value,)
        ).fetchone()
        return dict(row) if row else None

    def get_critical_since(self, hours: int, limit: int = 100) -> list[dict]:
        """Returns CRITICAL IOCs with first_seen within the last N hours, newest first."""
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d")
        rows = self.conn.execute(
            """
            SELECT * FROM iocs
            WHERE severity = 'CRITICAL' AND first_seen >= ?
            ORDER BY first_seen DESC
            LIMIT ?
            """,
            (cutoff, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def cleanup_old_iocs(self, days: int = 30) -> int:
        try:
            cursor = self.conn.execute(
                """
                DELETE FROM iocs
                WHERE first_seen < date('now', '-' || ? || ' days')
                AND NOT (source = 'CISA-KEV' AND severity = 'CRITICAL')
                """,
                (days,),
            )
            self.conn.commit()
            return cursor.rowcount
        except sqlite3.OperationalError as e:
            print(f"[database] cleanup_old_iocs failed: {e}")
            return 0

    def close(self):
        self.conn.close()
