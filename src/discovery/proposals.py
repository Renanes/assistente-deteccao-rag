"""O estado das propostas e o único caminho que escreve no acervo.

A regra de ouro da ferramenta está aqui: **nada entra no índice sem uma decisão
humana registrada**. A busca (`search.py`) só produz candidatos; é `approve` que
chunka, embeda e grava — e ela exige uma proposta que já esteja persistida como
pendente, o que impede que um caminho novo de código "aprove" algo que ninguém
viu.

Decisões de estado:

1. **A chave é o `rule_uid`, não um id de proposta.** A mesma regra encontrada
   em duas buscas é a mesma decisão, não duas. Com id próprio, recusar uma regra
   hoje não impediria ela de voltar amanhã como novidade — e a recusa que não
   gruda é pior que não ter recusa, porque dá a impressão de ter funcionado.

2. **Recusa é sticky e visível, não um sumiço.** Uma regra recusada continua
   aparecendo em buscas seguintes, marcada como recusada e fora da lista de
   pendentes. Esconder faria a ferramenta parecer não achar nada; e a decisão
   antiga pode ter sido tomada com outro contexto.

3. **O modelo de embedding é conferido antes de escrever.** Vetor de modelo
   diferente do que indexou o corpus não é comparável com o resto da tabela: a
   busca não quebra, ela só passa a errar. É o modo de falha mais caro do
   projeto inteiro, e o lugar certo de barrá-lo é aqui, antes do INSERT.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

import psycopg
from psycopg.types.json import Json

from ..chunking.chunk import chunk_rule
from ..embeddings import store
from ..ingestion.schema import DetectionRule
from ..providers.base import EmbeddingProvider, ProviderError
from .search import Proposal

TABLE_NAME = "discovery_proposals"


class ProposalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ProposalCounts:
    pending: int = 0
    approved: int = 0
    rejected: int = 0


def ensure_schema(conn: psycopg.Connection) -> None:
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
            rule_uid          TEXT PRIMARY KEY,
            status            TEXT NOT NULL,
            prompt            TEXT NOT NULL DEFAULT '',
            source_slug       TEXT NOT NULL,
            source_label      TEXT NOT NULL DEFAULT '',
            source_path       TEXT NOT NULL,
            source_url        TEXT NOT NULL,
            score             REAL NOT NULL DEFAULT 0,
            matched_terms     TEXT[] NOT NULL DEFAULT '{{}}',
            matched_techniques TEXT[] NOT NULL DEFAULT '{{}}',
            found_by          TEXT[] NOT NULL DEFAULT '{{}}',
            rule              JSONB NOT NULL,
            found_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
            decided_at        TIMESTAMPTZ
        )
        """
    )
    conn.execute(
        f"CREATE INDEX IF NOT EXISTS {TABLE_NAME}_status ON {TABLE_NAME} (status)"
    )


def record_findings(
    conn: psycopg.Connection, prompt: str, proposals: list[Proposal]
) -> list[Proposal]:
    """Persiste o que a busca achou e devolve as propostas com o estado real.

    Uma proposta que já foi decidida antes **mantém** a decisão: o payload e a
    nota são atualizados (a regra pode ter mudado no repositório), mas o status
    não volta para pendente. É o que faz "recusar" significar alguma coisa na
    busca seguinte.
    """
    ensure_schema(conn)
    if not proposals:
        return []

    decided: list[Proposal] = []
    for proposal in proposals:
        row = conn.execute(
            f"""
            INSERT INTO {TABLE_NAME} (
                rule_uid, status, prompt, source_slug, source_label, source_path,
                source_url, score, matched_terms, matched_techniques, found_by, rule
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (rule_uid) DO UPDATE SET
                prompt             = EXCLUDED.prompt,
                source_slug        = EXCLUDED.source_slug,
                source_label       = EXCLUDED.source_label,
                source_path        = EXCLUDED.source_path,
                source_url         = EXCLUDED.source_url,
                score              = EXCLUDED.score,
                matched_terms      = EXCLUDED.matched_terms,
                matched_techniques = EXCLUDED.matched_techniques,
                found_by           = EXCLUDED.found_by,
                rule               = EXCLUDED.rule
            RETURNING status
            """,
            (
                proposal.rule_uid,
                ProposalStatus.PENDING.value,
                prompt,
                proposal.source_slug,
                proposal.source_label,
                proposal.source_path,
                proposal.source_url,
                proposal.score,
                proposal.matched_terms,
                proposal.matched_techniques,
                proposal.found_by,
                Json(proposal.rule.model_dump(mode="json")),
            ),
        ).fetchone()
        status = row[0] if row else ProposalStatus.PENDING.value
        decided.append(proposal.model_copy(update={"status": status}))

    conn.commit()
    return decided


def _row_to_proposal(row: tuple) -> Proposal:
    return Proposal(
        rule_uid=row[0],
        status=row[1],
        source_slug=row[2],
        source_label=row[3],
        source_path=row[4],
        source_url=row[5],
        score=row[6],
        matched_terms=list(row[7] or []),
        matched_techniques=list(row[8] or []),
        found_by=list(row[9] or []),
        rule=DetectionRule.model_validate(row[10]),
    )


def list_proposals(
    conn: psycopg.Connection, status: str | None = ProposalStatus.PENDING.value, limit: int = 50
) -> list[Proposal]:
    ensure_schema(conn)
    where = "WHERE status = %s" if status else ""
    params: tuple = (status, limit) if status else (limit,)
    rows = conn.execute(
        f"""
        SELECT rule_uid, status, source_slug, source_label, source_path, source_url,
               score, matched_terms, matched_techniques, found_by, rule
        FROM {TABLE_NAME} {where}
        ORDER BY score DESC, found_at DESC
        LIMIT %s
        """,
        params,
    ).fetchall()
    return [_row_to_proposal(row) for row in rows]


def get_proposal(conn: psycopg.Connection, rule_uid: str) -> Proposal | None:
    ensure_schema(conn)
    row = conn.execute(
        f"""
        SELECT rule_uid, status, source_slug, source_label, source_path, source_url,
               score, matched_terms, matched_techniques, found_by, rule
        FROM {TABLE_NAME} WHERE rule_uid = %s
        """,
        (rule_uid,),
    ).fetchone()
    return _row_to_proposal(row) if row else None


def count_by_status(conn: psycopg.Connection) -> ProposalCounts:
    ensure_schema(conn)
    rows = conn.execute(f"SELECT status, count(*) FROM {TABLE_NAME} GROUP BY status").fetchall()
    counts = {status: total for status, total in rows}
    return ProposalCounts(
        pending=counts.get(ProposalStatus.PENDING.value, 0),
        approved=counts.get(ProposalStatus.APPROVED.value, 0),
        rejected=counts.get(ProposalStatus.REJECTED.value, 0),
    )


def _set_status(conn: psycopg.Connection, rule_uid: str, status: ProposalStatus) -> None:
    conn.execute(
        f"UPDATE {TABLE_NAME} SET status = %s, decided_at = %s WHERE rule_uid = %s",
        (status.value, datetime.now().astimezone(), rule_uid),
    )


def reject(conn: psycopg.Connection, rule_uid: str) -> Proposal:
    """Marca a proposta como recusada. Não escreve nada no acervo."""
    proposal = get_proposal(conn, rule_uid)
    if proposal is None:
        raise LookupError(f"não há proposta registrada para '{rule_uid}'.")
    _set_status(conn, rule_uid, ProposalStatus.REJECTED)
    conn.commit()
    return proposal.model_copy(update={"status": ProposalStatus.REJECTED.value})


def check_embedding_compatibility(conn: psycopg.Connection, embedding: EmbeddingProvider) -> None:
    """Recusa indexar com um modelo diferente do que construiu o acervo.

    Sem esta checagem a regra aprovada entraria com um vetor incomparável com os
    outros 5.664 — e o sintoma não seria erro, seria a regra nova nunca aparecer
    (ou aparecer para qualquer pergunta). Falha silenciosa de retrieval é
    exatamente o que este projeto existe para não ter.
    """
    info = store.describe_corpus(conn)
    if not info.exists or info.row_count == 0:
        return

    if info.dimensions is not None and info.dimensions != embedding.dimensions:
        raise ProviderError(
            f"O acervo guarda vetores de {info.dimensions} dimensões e "
            f"'{embedding.model}' produz {embedding.dimensions}. A regra não foi "
            "indexada — seria um vetor incomparável com o resto da base."
        )
    other = [model for model in info.models if model != embedding.model]
    if other:
        raise ProviderError(
            f"O acervo foi indexado com {', '.join(other)} e a chave em uso resolve "
            f"para '{embedding.model}'. Vetores de modelos diferentes não são "
            "comparáveis: a regra não foi indexada. Use uma chave do mesmo modelo "
            "ou reindexe o acervo inteiro."
        )


def approve(
    conn: psycopg.Connection, rule_uid: str, embedding: EmbeddingProvider
) -> tuple[Proposal, int]:
    """Indexa a regra proposta no acervo e marca a proposta como aprovada.

    Devolve (proposta, chunks escritos). O commit é único: ou a regra entrou no
    índice e a proposta ficou aprovada, ou nada aconteceu. Um estado em que a
    proposta consta aprovada mas a regra não está indexada seria invisível — e
    apareceria como "aprovei e a busca não acha".
    """
    proposal = get_proposal(conn, rule_uid)
    if proposal is None:
        raise LookupError(
            f"não há proposta registrada para '{rule_uid}'. Rode a busca antes de aprovar."
        )
    if proposal.status == ProposalStatus.APPROVED.value:
        return proposal, 0

    check_embedding_compatibility(conn, embedding)

    chunks = chunk_rule(proposal.rule)
    vectors = embedding.embed_documents([chunk.embedding_text for chunk in chunks])

    info = store.describe_corpus(conn)
    if not info.exists:
        # Acervo vazio é um estado legítimo: quem quer experimentar a descoberta
        # antes de rodar a ingestão das 3 fontes.
        store.ensure_extension(conn)
        store.create_schema(conn, embedding.dimensions)

    written = store.upsert_chunks(conn, chunks, vectors, embedding.model)
    _set_status(conn, rule_uid, ProposalStatus.APPROVED)
    conn.commit()

    return proposal.model_copy(update={"status": ProposalStatus.APPROVED.value}), written


def indexed_uids(conn: psycopg.Connection) -> set[str]:
    """Todos os `rule_uid` já no índice vetorial.

    Carregado inteiro, uma vez por busca, em vez de consultado por candidato: o
    `rule_uid` de um arquivo só é conhecido **depois** de parseá-lo, então uma
    consulta pontual viraria uma ida ao banco por arquivo lido. São ~5.700
    strings curtas numa consulta indexada — mais barato que as idas evitadas.
    """
    info = store.describe_corpus(conn)
    if not info.exists:
        return set()
    rows = conn.execute(f"SELECT DISTINCT rule_uid FROM {store.TABLE_NAME}").fetchall()
    return {row[0] for row in rows}
