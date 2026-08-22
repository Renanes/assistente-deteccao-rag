"""Busca híbrida: filtro por metadado + similaridade vetorial + full-text.

A arquitetura tem três peças com papéis distintos, e a distinção importa:

1. **Filtro por metadado é rígido, não é ranqueamento.** Se o analista digitou
   `T1055`, uma regra de `T1027` está errada — não "menos relevante". Filtro
   remove do conjunto; as outras duas pernas ordenam o que sobrou.

2. **Similaridade vetorial** responde à intenção descrita em linguagem natural,
   inclusive em outro idioma que o corpus (o corpus é em inglês e as perguntas
   costumam vir em português).

3. **Full-text** casa identificador exato que o embedding borra: `4688`,
   `mimikatz`, `rundll32`.

As duas listas ranqueadas são fundidas por RRF (ver `fusion.py`), que dispensa
normalizar pontuações incomparáveis.

**Expansão de técnica-pai.** O full-text tokeniza `T1213.003` como um termo só,
então uma busca por `T1213` não o encontraria — foi medido na Fase 3 (16 regras
pela coluna de metadado contra 10 pelo full-text). Por isso o filtro ATT&CK
roda sobre a coluna `mitre_techniques` e expande nos dois sentidos: pai casa
suas subtécnicas, subtécnica casa também o pai.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import psycopg
from pydantic import BaseModel, Field

from ..providers import EmbeddingProvider
from .fusion import RRF_K, FusedResult, RankedList, reciprocal_rank_fusion
from .query import ParsedQuery, build_tsquery, parse_query

TABLE_NAME = "rule_chunks"

# Quantos candidatos cada perna traz antes da fusão.
#
# Precisa ser bem maior que o `top_k` final: um documento que fica em 40º no
# vetor e em 3º no full-text só pode ser resgatado pela fusão se estiver nas
# duas listas. Um pool curto transformaria a fusão em decoração.
CANDIDATE_POOL_MULTIPLIER = 8
MIN_CANDIDATE_POOL = 50

# Inferir plataforma da pergunta e transformar isso em filtro rígido: DESLIGADO.
#
# Era o comportamento padrão até a Fase 6 medi-lo. `infer_platforms` foi escrito
# para texto de telemetria (`data_source` de uma regra), não para pergunta em
# linguagem natural, e aplicado a perguntas ele dispara demais. Três falhas
# medidas, todas do mesmo tipo — o filtro excluiu a resposta certa:
#   q06: "endereço de e-mail" infere `email`; a regra é `web`.
#   q14: "logs web" infere `web`; a regra é `network`.
#   q24: "Google Workspace" infere `gcp`; a regra não declara plataforma —
#        e 181 chunks estão nesse caso, então qualquer filtro os elimina.
# Nas três, sem o filtro a regra volta para o 1º lugar. Filtro de plataforma
# explícito (de uma faceta de interface) segue válido: quem escolheu "windows"
# num menu quis dizer isso; quem escreveu "logs web" numa frase, não.
INFER_PLATFORM_BY_DEFAULT = False

# Perna de full-text no caminho padrão: DESLIGADA.
#
# A Fase 6 mediu quatro variantes dela (peso 1,0 e 0,5; só identificadores;
# indexando também a query bruta) e nenhuma superou simplesmente não usá-la:
# MRR 0,879 sem a perna contra 0,867 na melhor variante com ela, com o mesmo
# recall@5 de 97%. A causa é estrutural, não de ajuste: `search_text` indexa
# `embedding_text`, exatamente o texto que o vetor já cobre — as duas pernas
# olham para a mesma coisa, e a lexical só acrescenta ruído de OR.
#
# O que a medição NÃO invalida é o filtro por metadado, que continua ligado e é
# o que faz "T1055" recuperar corretamente (critério de aceite da Fase 4). A
# perna segue implementada e ativável: a coluna `search_text` passou a incluir
# a query bruta, o que a tornaria útil para termo que só existe na lógica de
# detecção — caso que o conjunto de avaliação atual não cobre.
USE_FULLTEXT_BY_DEFAULT = False


@dataclass(frozen=True)
class SearchFilters:
    """Filtros rígidos aplicados no SQL."""

    mitre_techniques: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (self.mitre_techniques or self.platforms or self.sources)

    @classmethod
    def from_parsed(cls, parsed: ParsedQuery) -> SearchFilters:
        return cls(
            mitre_techniques=tuple(parsed.mitre_techniques),
            platforms=tuple(parsed.platforms),
        )


class RetrievedRule(BaseModel):
    """Uma regra recuperada, com tudo que a Fase 5 precisa para citá-la."""

    chunk_uid: str
    rule_uid: str
    title: str
    source: str
    source_url: str | None = None

    narrative: str = Field(description="O texto que foi embeddado (contexto + narrativa).")
    query: str
    query_language: str
    query_truncated: bool

    platforms: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: str | None = None

    score: float = Field(description="Pontuação da fusão RRF.")
    similarity: float | None = Field(
        default=None, description="Similaridade de cosseno, quando a perna vetorial a trouxe."
    )
    matched_by: list[str] = Field(
        default_factory=list, description="Quais pernas trouxeram esta regra."
    )
    ranks: dict[str, int] = Field(
        default_factory=dict, description="Posição em cada perna, para explicar o resultado."
    )


@dataclass
class SearchResponse:
    """Resultado da busca, com o que foi decidido pelo caminho."""

    results: list[RetrievedRule] = field(default_factory=list)
    parsed: ParsedQuery | None = None
    filters: SearchFilters = SearchFilters()
    #: True quando o filtro rígido não devolveu nada e a busca foi refeita sem
    #: ele. Precisa ser visível: a resposta da Fase 5 não pode afirmar que
    #: existe regra para `T1055` quando na verdade relaxou o filtro.
    relaxed_filters: bool = False
    legs_used: tuple[str, ...] = ()


def _filter_sql(filters: SearchFilters) -> tuple[str, dict[str, object]]:
    """Monta o WHERE dos filtros rígidos e os parâmetros correspondentes."""
    clauses: list[str] = []
    params: dict[str, object] = {}

    if filters.mitre_techniques:
        exact: list[str] = []
        prefixes: list[str] = []
        for technique in filters.mitre_techniques:
            exact.append(technique)
            if "." in technique:
                # Subtécnica citada: a regra do pai também é relevante.
                exact.append(technique.split(".", 1)[0])
            else:
                # Técnica-pai citada: casa as subtécnicas dela.
                prefixes.append(f"{technique}.%")

        clauses.append(
            "EXISTS (SELECT 1 FROM unnest(mitre_techniques) AS t "
            "WHERE t = ANY(%(mitre_exact)s) OR t LIKE ANY(%(mitre_prefixes)s))"
        )
        params["mitre_exact"] = sorted(set(exact))
        params["mitre_prefixes"] = prefixes or [""]

    if filters.platforms:
        # `&&` é interseção de arrays e usa o índice GIN de `platforms`.
        clauses.append("platforms && %(platforms)s::text[]")
        params["platforms"] = list(filters.platforms)

    if filters.sources:
        clauses.append("source = ANY(%(sources)s)")
        params["sources"] = list(filters.sources)

    return (" AND ".join(clauses) if clauses else "TRUE"), params


class HybridRetriever:
    """Executa a busca híbrida contra o pgvector."""

    def __init__(self, conn: psycopg.Connection, provider: EmbeddingProvider) -> None:
        self._conn = conn
        self._provider = provider

    def _vector_candidates(
        self, vector: list[float], where: str, params: dict[str, object], pool: int
    ) -> tuple[list[str], dict[str, float]]:
        rows = self._conn.execute(
            f"""
            SELECT chunk_uid, 1 - (embedding <=> %(vector)s::vector) AS similarity
            FROM {TABLE_NAME}
            WHERE {where}
            ORDER BY embedding <=> %(vector)s::vector
            LIMIT %(pool)s
            """,
            {**params, "vector": vector, "pool": pool},
        ).fetchall()
        return [row[0] for row in rows], {row[0]: float(row[1]) for row in rows}

    def _fulltext_candidates(
        self, tsquery: str, where: str, params: dict[str, object], pool: int
    ) -> list[str]:
        rows = self._conn.execute(
            f"""
            SELECT chunk_uid
            FROM {TABLE_NAME}, to_tsquery('english', %(tsquery)s) AS q
            WHERE search_text @@ q AND {where}
            ORDER BY ts_rank(search_text, q) DESC, chunk_uid
            LIMIT %(pool)s
            """,
            {**params, "tsquery": tsquery, "pool": pool},
        ).fetchall()
        return [row[0] for row in rows]

    def _hydrate(self, fused: list[FusedResult], similarities: dict[str, float]) -> list[RetrievedRule]:
        """Busca os campos completos dos candidatos, preservando a ordem da fusão."""
        if not fused:
            return []

        uids = [item.chunk_uid for item in fused]
        rows = self._conn.execute(
            f"""
            SELECT chunk_uid, rule_uid, title, source, source_url,
                   embedding_text, query, query_language, query_truncated,
                   platforms, mitre_techniques, severity
            FROM {TABLE_NAME}
            WHERE chunk_uid = ANY(%s)
            """,
            (uids,),
        ).fetchall()

        by_uid = {row[0]: row for row in rows}
        results: list[RetrievedRule] = []
        for item in fused:
            row = by_uid.get(item.chunk_uid)
            if row is None:  # pragma: no cover - só se a linha sumir entre as consultas
                continue
            results.append(
                RetrievedRule(
                    chunk_uid=row[0],
                    rule_uid=row[1],
                    title=row[2],
                    source=row[3],
                    source_url=row[4],
                    narrative=row[5],
                    query=row[6],
                    query_language=row[7],
                    query_truncated=row[8],
                    platforms=list(row[9] or []),
                    mitre_techniques=list(row[10] or []),
                    severity=row[11],
                    score=item.score,
                    similarity=similarities.get(item.chunk_uid),
                    matched_by=list(item.matched_by),
                    ranks=dict(item.ranks),
                )
            )
        return results

    def _run(
        self,
        parsed: ParsedQuery,
        filters: SearchFilters,
        top_k: int,
        rrf_k: int,
        use_fulltext: bool = True,
        fulltext_weight: float = 1.0,
    ) -> tuple[list[RetrievedRule], tuple[str, ...]]:
        where, params = _filter_sql(filters)
        pool = max(top_k * CANDIDATE_POOL_MULTIPLIER, MIN_CANDIDATE_POOL)

        vector = self._provider.embed_query(parsed.text)
        vector_uids, similarities = self._vector_candidates(vector, where, params, pool)

        lists = [RankedList(name="vetorial", chunk_uids=vector_uids)]

        tsquery = build_tsquery(parsed.lexical_terms) if use_fulltext else ""
        if tsquery:
            fulltext_uids = self._fulltext_candidates(tsquery, where, params, pool)
            if fulltext_uids:
                lists.append(
                    RankedList(
                        name="full-text",
                        chunk_uids=fulltext_uids,
                        weight=fulltext_weight,
                    )
                )

        fused = reciprocal_rank_fusion(lists, k=rrf_k, limit=top_k)
        return self._hydrate(fused, similarities), tuple(item.name for item in lists)

    def search(
        self,
        question: str,
        top_k: int = 5,
        filters: SearchFilters | None = None,
        rrf_k: int = RRF_K,
        use_fulltext: bool = USE_FULLTEXT_BY_DEFAULT,
        fulltext_weight: float = 1.0,
        infer_platform: bool = INFER_PLATFORM_BY_DEFAULT,
        identifiers_only: bool = False,
    ) -> SearchResponse:
        """Busca as regras mais relevantes para a pergunta.

        Se `filters` não vier, os filtros são deduzidos da pergunta — hoje isso
        significa apenas a técnica ATT&CK (ver `INFER_PLATFORM_BY_DEFAULT`).
        Filtro de plataforma explícito, vindo da API ou da interface, continua
        funcionando normalmente: o que a medição desligou foi a *inferência*.

        `use_fulltext` e `infer_platform` seguem parametrizados para a avaliação
        poder medir as duas pernas; os defaults saíram de `eval/results.md`.
        """
        parsed = parse_query(
            question, infer_platform=infer_platform, identifiers_only=identifiers_only
        )
        effective = filters if filters is not None else SearchFilters.from_parsed(parsed)

        results, legs = self._run(
            parsed, effective, top_k, rrf_k, use_fulltext, fulltext_weight
        )

        # Filtro que não devolve nada é pior que filtro nenhum: o analista fica
        # sem resposta e sem saber por quê. Refazemos sem o filtro e marcamos —
        # a Fase 5 precisa dizer "não achei regra para T9999, mas veja estas".
        relaxed = False
        if not results and not effective.is_empty:
            results, legs = self._run(
                parsed, SearchFilters(), top_k, rrf_k, use_fulltext, fulltext_weight
            )
            relaxed = True

        return SearchResponse(
            results=results,
            parsed=parsed,
            filters=effective,
            relaxed_filters=relaxed,
            legs_used=legs,
        )
