"""Bulk-update helpers — colapsam N round-trips em 1 query no PostgreSQL.

`session.execute(UPDATE ... WHERE id=:id, [dict, dict, ...])` parece um batch,
mas psycopg2 emite **um round-trip de rede por linha**. Co-localizado (Render) isso
custava ~0,5ms/linha; contra o Neon (RTT 15-200ms) viram minutos/horas para dezenas
de milhares de IOCs. `bulk_update_iocs` reescreve o UPDATE como um único comando via
UNNEST de arrays, levando 55k linhas de ~horas para ~1s.

SQLite (dev local) não tem UNNEST nem arrays — e lá não há latência de rede, então
o caminho de fallback mantém o `executemany` original, byte-a-byte idêntico.
"""

from sqlalchemy import text


def bulk_update_iocs(
    session,
    updates: list[dict],
    columns: dict[str, str],
    *,
    key: str = "id",
    key_type: str = "bigint",
    set_raw: dict[str, str] | None = None,
    fallback_stmt=None,
    table: str = "iocs",
) -> int:
    """Executa um UPDATE em massa, substituindo N round-trips por 1 (PostgreSQL).

    Args:
        session: SQLAlchemy Session.
        updates: lista de dicts; cada dict DEVE conter `key` + cada coluna de `columns`
                 (e qualquer coluna referenciada por `set_raw`).
        columns: {nome_coluna: tipo_array_postgres}, ex. {"score_atual": "double precision",
                 "ioc_status": "text"}. Geram `SET col = u.col` (valor vindo de `updates`).
        key: coluna usada no JOIN (default "id").
        key_type: tipo do array da chave para o CAST do UNNEST (default "bigint").
        set_raw: {nome_coluna: expressão_sql} para SETs derivados (ex. CASE). A expressão
                 pode referenciar `u.<coluna>` (valores do UNNEST) e `<table>.<coluna>`
                 (valor atual da linha). Usado pela compactação de score_breakdown no decay.
        fallback_stmt: `text()` por-linha usado no caminho não-PostgreSQL (SQLite). Se None,
                 um `UPDATE table SET col=:col ... WHERE key=:key` é montado automaticamente.
                 Passe explicitamente quando houver `set_raw` (ex. o CASE do decay).
        table: tabela alvo (default "iocs").

    Returns:
        Número de linhas afetadas (rowcount no PostgreSQL; len(updates) no fallback).
    """
    if not updates:
        return 0

    set_raw = set_raw or {}
    dialect = session.bind.dialect.name

    if dialect == "postgresql":
        # Monta arrays paralelos: chave + uma coluna de dados por entrada de `columns`.
        params: dict = {f"_a_{key}": [row[key] for row in updates]}
        unnest_args = [f"CAST(:_a_{key} AS {key_type}[])"]
        for col, arr_type in columns.items():
            params[f"_a_{col}"] = [row[col] for row in updates]
            unnest_args.append(f"CAST(:_a_{col} AS {arr_type}[])")

        # UNNEST(arr1, arr2, ...) AS u(key, col1, col2, ...) — arrays de mesmo tamanho
        # expandem para uma tabela virtual; o JOIN por chave aplica cada linha.
        alias_cols = ", ".join([key] + list(columns.keys()))
        unnest_sql = ", ".join(unnest_args)

        set_clauses = [f"{col} = u.{col}" for col in columns]
        set_clauses += [f"{col} = {expr}" for col, expr in set_raw.items()]

        stmt = text(
            f"UPDATE {table} SET "
            + ", ".join(set_clauses)
            + f" FROM UNNEST({unnest_sql}) AS u({alias_cols})"
            + f" WHERE {table}.{key} = u.{key}"
        )
        result = session.execute(stmt, params)
        return result.rowcount if result.rowcount is not None else len(updates)

    # Fallback (SQLite/dev local): executemany por-linha — sem latência de rede.
    if fallback_stmt is None:
        assigns = ", ".join(f"{col} = :{col}" for col in columns)
        fallback_stmt = text(f"UPDATE {table} SET {assigns} WHERE {key} = :{key}")
    session.execute(fallback_stmt, updates)
    return len(updates)


def bulk_upsert_sightings(session, pairs: list[dict], day: str) -> int:
    """Upsert em massa dos pares (value, source) de proveniência.

    Mesma motivação do bulk_update_iocs, mas para INSERT ... ON CONFLICT: o
    executemany emitia 1 round-trip por par (~27k/execução → ~54min no Neon).
    No PostgreSQL um único INSERT ... SELECT FROM UNNEST(...) ON CONFLICT cobre
    o batch inteiro. SQLite (dev local) mantém o executemany por-linha.

    `pairs`: lista de dicts {"value": str, "source": str}. `day`: 'YYYY-MM-DD'.
    Retorna o número de pares submetidos.
    """
    if not pairs:
        return 0

    dialect = session.bind.dialect.name

    if dialect == "postgresql":
        stmt = text("""
            INSERT INTO sightings (value, source, first_seen, last_seen, seen_count)
            SELECT u.value, u.source, :day, :day, 1
            FROM UNNEST(CAST(:values AS text[]), CAST(:sources AS text[]))
                 AS u(value, source)
            ON CONFLICT (value, source) DO UPDATE SET
                last_seen  = excluded.last_seen,
                seen_count = sightings.seen_count + 1
        """)
        session.execute(stmt, {
            "values":  [p["value"] for p in pairs],
            "sources": [p["source"] for p in pairs],
            "day": day,
        })
        return len(pairs)

    # Fallback (SQLite/dev local): executemany por-linha — sem latência de rede.
    stmt = text("""
        INSERT INTO sightings (value, source, first_seen, last_seen, seen_count)
        VALUES (:value, :source, :day, :day, 1)
        ON CONFLICT (value, source) DO UPDATE SET
            last_seen  = excluded.last_seen,
            seen_count = sightings.seen_count + 1
    """)
    session.execute(stmt, [{**p, "day": day} for p in pairs])
    return len(pairs)
