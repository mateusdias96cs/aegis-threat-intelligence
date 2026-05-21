"""
Cache persistente para dados MITRE ATT&CK no banco PostgreSQL/SQLite.
TTL: 30 dias. Evita fetch do GitHub a cada pipeline run.
"""
import json
from datetime import datetime, timedelta
from sqlalchemy import text
from src.storage.database import engine

_TTL_DAYS = 30
_CACHE_KEY = "mitre_techniques"


def _ensure_table() -> None:
    """Cria tabela de cache se não existir."""
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS kv_cache (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """))
        conn.commit()


def load() -> dict | None:
    """
    Retorna dict de técnicas do cache se existir e não tiver expirado.
    Retorna None se cache ausente ou expirado (>30 dias).
    """
    _ensure_table()
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT value, updated_at FROM kv_cache WHERE key = :k"),
                {"k": _CACHE_KEY}
            ).fetchone()
        if not row:
            return None
        updated_at = datetime.fromisoformat(row[1])
        if datetime.utcnow() - updated_at > timedelta(days=_TTL_DAYS):
            print(f"[mitre_cache] cache expirado ({_TTL_DAYS} dias) — será renovado")
            return None
        data = json.loads(row[0])
        if not data:
            print("[mitre_cache] cache existe mas está vazio — será renovado")
            return None
        print(f"[mitre_cache] {len(data)} técnicas carregadas do cache (atualizado em {row[1][:10]})")
        return data
    except Exception as e:
        print(f"[mitre_cache] erro ao ler cache: {e}")
        return None


def save(techniques: dict) -> None:
    """Persiste o dict de técnicas no banco com timestamp atual."""
    _ensure_table()
    try:
        now = datetime.utcnow().isoformat()
        payload = json.dumps(techniques, ensure_ascii=False)
        with engine.connect() as conn:
            dialect = engine.dialect.name
            if dialect == "postgresql":
                conn.execute(text("""
                    INSERT INTO kv_cache (key, value, updated_at)
                    VALUES (:k, :v, :ts)
                    ON CONFLICT (key) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = EXCLUDED.updated_at
                """), {"k": _CACHE_KEY, "v": payload, "ts": now})
            else:
                conn.execute(text(
                    "INSERT OR REPLACE INTO kv_cache (key, value, updated_at) VALUES (:k, :v, :ts)"
                ), {"k": _CACHE_KEY, "v": payload, "ts": now})
            conn.commit()
        print(f"[mitre_cache] {len(techniques)} técnicas salvas no cache")
    except Exception as e:
        print(f"[mitre_cache] erro ao salvar cache: {e}")
