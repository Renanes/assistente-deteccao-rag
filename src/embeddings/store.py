"""Schema do pgvector e escrita dos chunks vetorizados.

O schema é montado em função do provedor de embedding em uso, porque a dimensão
do vetor faz parte do tipo da coluna (`vector(N)`) — não dá para criar a tabela
antes de saber qual modelo vai preenchê-la.

Três decisões de schema, todas voltadas para a Fase 4 (busca híbrida):

1. **Metadados como colunas, não como JSON.** `platforms` e `mitre_techniques`
   são `TEXT[]` com índice GIN. O filtro "só regras de Windows para T1055" é o
   critério de aceite da Fase 4, e um `jsonb` genérico tornaria isso mais lento
   e mais verboso sem ganhar nada — o schema já é conhecido e estável.

2. **Coluna `search_text` gerada, com índice GIN de full-text.** É a metade
   lexical da busca híbrida. Indexa o texto embeddado mais a query bruta — a
   query entrou na Fase 6, quando a medição mostrou que indexar só a narrativa
   deixava esta coluna redundante com o vetor, que cobre o mesmo texto. A perna
   lexical está desligada por padrão desde então (ver `src/retrieval/search.py`,
   `USE_FULLTEXT_BY_DEFAULT`); a coluna e o índice continuam porque ativá-la é
   uma flag, e o custo de mantê-los é irrelevante.

3. **`embedding_model` gravado em cada linha.** Vetores de modelos diferentes
   não são comparáveis. Sem essa coluna, trocar o `EMBEDDING_PROVIDER` no meio
   do caminho produziria uma base silenciosamente misturada e um retrieval
   ruim sem causa aparente.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import psycopg
from pgvector.psycopg import register_vector
from psycopg import sql

from ..chunking.chunk import RuleChunk

TABLE_NAME = "rule_chunks"

# Quantas linhas por `executemany`. Vetores de 1536 floats deixam cada linha
# na casa dos 20 KB; 500 por vez mantém a transação leve sem pagar round-trip
# por linha.
INSERT_BATCH_SIZE = 500


@dataclass(frozen=True)
class IndexedCorpusInfo:
    """O que a base já contém — usado para detectar incompatibilidade."""

    exists: bool
    row_count: int = 0
    dimensions: int | None = None
    models: tuple[str, ...] = ()


def connect(database_url: str) -> psycopg.Connection:
    """Abre conexão com o tipo `vector` registrado no adaptador."""
    conn = psycopg.connect(database_url)
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    # Precisa vir depois do CREATE EXTENSION: o registro consulta o OID do tipo
    # `vector`, que não existe antes da extensão ser criada.
    register_vector(conn)
    return conn


def describe_corpus(conn: psycopg.Connection) -> IndexedCorpusInfo:
    """Inspeciona a tabela existente, se houver.

    Serve para recusar uma ingestão que misturaria modelos de embedding, em vez
    de descobrir o problema só quando o retrieval vier ruim.
    """
    row = conn.execute(
        "SELECT to_regclass(%s) IS NOT NULL",
        (f"public.{TABLE_NAME}",),
    ).fetchone()
    if row is None or not row[0]:
        return IndexedCorpusInfo(exists=False)

    dimensions_row = conn.execute(
        """
        SELECT a.atttypmod
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        WHERE c.relname = %s AND a.attname = 'embedding'
        """,
        (TABLE_NAME,),
    ).fetchone()

    count_row = conn.execute(
        sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(TABLE_NAME))
    ).fetchone()

    models_rows = conn.execute(
        sql.SQL("SELECT DISTINCT embedding_model FROM {}").format(sql.Identifier(TABLE_NAME))
    ).fetchall()

    return IndexedCorpusInfo(
        exists=True,
        row_count=count_row[0] if count_row else 0,
        dimensions=dimensions_row[0] if dimensions_row else None,
        models=tuple(sorted(row[0] for row in models_rows)),
    )


def drop_schema(conn: psycopg.Connection) -> None:
    conn.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(TABLE_NAME)))


def create_schema(conn: psycopg.Connection, dimensions: int) -> None:
    """Cria tabela e índices para vetores de `dimensions` dimensões."""
    conn.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                chunk_uid        TEXT PRIMARY KEY,
                rule_uid         TEXT NOT NULL,
                chunk_index      INTEGER NOT NULL,
                chunk_total      INTEGER NOT NULL,

                embedding_text   TEXT NOT NULL,
                embedding        vector({dims}) NOT NULL,
                embedding_model  TEXT NOT NULL,

                query            TEXT NOT NULL,
                query_truncated  BOOLEAN NOT NULL,
                query_language   TEXT NOT NULL,

                source           TEXT NOT NULL,
                title            TEXT NOT NULL,
                source_url       TEXT,
                platforms        TEXT[] NOT NULL DEFAULT '{{}}',
                mitre_techniques TEXT[] NOT NULL DEFAULT '{{}}',
                mitre_tactics    TEXT[] NOT NULL DEFAULT '{{}}',
                data_sources     TEXT[] NOT NULL DEFAULT '{{}}',
                severity         TEXT,

                indexed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

                -- Metade lexical da busca híbrida da Fase 4. Gerada pelo banco
                -- para não poder ficar dessincronizada do texto de origem.
                --
                -- Não inclui `platforms`/`mitre_techniques`: a linha de
                -- contexto da Fase 2 já embute os dois em `embedding_text`, e
                -- `array_to_string` é STABLE (não IMMUTABLE), o que o Postgres
                -- recusa numa coluna gerada.
                --
                -- Inclui a `query` bruta desde a Fase 6. Indexar só a narrativa
                -- tornava esta coluna redundante com o vetor, que cobre o mesmo
                -- texto; a lógica de detecção é o único material que o
                -- embedding não vê (medido: "tttracer" aparece em 3 chunks na
                -- narrativa e em outros 6 apenas na query).
                search_text      tsvector GENERATED ALWAYS AS (
                    to_tsvector('english', embedding_text || ' ' || query)
                ) STORED
            )
            """
        ).format(table=sql.Identifier(TABLE_NAME), dims=sql.Literal(dimensions))
    )

    # Similaridade de cosseno: os vetores dos dois provedores vêm normalizados,
    # e cosseno é a métrica que ambos documentam para busca semântica.
    conn.execute(
        sql.SQL(
            "CREATE INDEX IF NOT EXISTS {name} ON {table} "
            "USING hnsw (embedding vector_cosine_ops)"
        ).format(
            name=sql.Identifier(f"{TABLE_NAME}_embedding_hnsw"),
            table=sql.Identifier(TABLE_NAME),
        )
    )

    for column in ("platforms", "mitre_techniques", "search_text"):
        conn.execute(
            sql.SQL("CREATE INDEX IF NOT EXISTS {name} ON {table} USING gin ({column})").format(
                name=sql.Identifier(f"{TABLE_NAME}_{column}_gin"),
                table=sql.Identifier(TABLE_NAME),
                column=sql.Identifier(column),
            )
        )

    conn.execute(
        sql.SQL("CREATE INDEX IF NOT EXISTS {name} ON {table} ({column})").format(
            name=sql.Identifier(f"{TABLE_NAME}_rule_uid"),
            table=sql.Identifier(TABLE_NAME),
            column=sql.Identifier("rule_uid"),
        )
    )


_UPSERT = sql.SQL(
    """
    INSERT INTO {table} (
        chunk_uid, rule_uid, chunk_index, chunk_total,
        embedding_text, embedding, embedding_model,
        query, query_truncated, query_language,
        source, title, source_url,
        platforms, mitre_techniques, mitre_tactics, data_sources, severity
    )
    VALUES (
        %s, %s, %s, %s,
        %s, %s, %s,
        %s, %s, %s,
        %s, %s, %s,
        %s, %s, %s, %s, %s
    )
    ON CONFLICT (chunk_uid) DO UPDATE SET
        rule_uid         = EXCLUDED.rule_uid,
        chunk_index      = EXCLUDED.chunk_index,
        chunk_total      = EXCLUDED.chunk_total,
        embedding_text   = EXCLUDED.embedding_text,
        embedding        = EXCLUDED.embedding,
        embedding_model  = EXCLUDED.embedding_model,
        query            = EXCLUDED.query,
        query_truncated  = EXCLUDED.query_truncated,
        query_language   = EXCLUDED.query_language,
        source           = EXCLUDED.source,
        title            = EXCLUDED.title,
        source_url       = EXCLUDED.source_url,
        platforms        = EXCLUDED.platforms,
        mitre_techniques = EXCLUDED.mitre_techniques,
        mitre_tactics    = EXCLUDED.mitre_tactics,
        data_sources     = EXCLUDED.data_sources,
        severity         = EXCLUDED.severity,
        indexed_at       = now()
    """
)


def _row(chunk: RuleChunk, vector: Sequence[float], model: str) -> tuple:
    return (
        chunk.chunk_uid,
        chunk.rule_uid,
        chunk.chunk_index,
        chunk.chunk_total,
        chunk.embedding_text,
        vector,
        model,
        chunk.query,
        chunk.query_truncated,
        chunk.query_language.value,
        chunk.source.value,
        chunk.title,
        chunk.source_url,
        chunk.platforms,
        chunk.mitre_techniques,
        chunk.mitre_tactics,
        chunk.data_sources,
        chunk.severity.value if chunk.severity else None,
    )


def upsert_chunks(
    conn: psycopg.Connection,
    chunks: Iterable[RuleChunk],
    vectors: Iterable[Sequence[float]],
    model: str,
) -> int:
    """Grava (ou atualiza) chunks vetorizados. Devolve quantas linhas escreveu.

    É upsert e não insert para que reindexar depois de corrigir o chunking não
    exija apagar a base — o `chunk_uid` é estável entre execuções.
    """
    statement = _UPSERT.format(table=sql.Identifier(TABLE_NAME))
    rows = [_row(chunk, vector, model) for chunk, vector in zip(chunks, vectors, strict=True)]

    written = 0
    with conn.cursor() as cursor:
        for start in range(0, len(rows), INSERT_BATCH_SIZE):
            batch = rows[start : start + INSERT_BATCH_SIZE]
            cursor.executemany(statement, batch)
            written += len(batch)

    return written
