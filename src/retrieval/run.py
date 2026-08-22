"""Consulta a busca híbrida pela linha de comando.

Uso:
    python -m src.retrieval.run "tem regra pra T1055 no Windows?"
    python -m src.retrieval.run "coleta de credenciais" --top-k 10
    python -m src.retrieval.run "mimikatz" --explain

Serve para inspecionar o retrieval sem subir a API — é como o critério de
aceite da Fase 4 foi verificado à mão, e é o que a Fase 6 automatiza.
"""

from __future__ import annotations

import argparse
import sys

from ..embeddings import store
from ..providers import ProviderError, get_embedding_provider, get_settings
from .search import HybridRetriever


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question", help="A pergunta do analista, em linguagem natural.")
    parser.add_argument("--top-k", type=int, default=None)
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Mostra a posição em cada perna e os filtros deduzidos.",
    )
    parser.add_argument(
        "--no-filters",
        action="store_true",
        help="Desliga os filtros rígidos — útil para comparar com a linha de base.",
    )
    args = parser.parse_args()

    settings = get_settings()
    top_k = args.top_k or settings.retrieval_top_k

    try:
        provider = get_embedding_provider(settings)
    except ProviderError as error:
        print(f"erro de provedor: {error}", file=sys.stderr)
        return 1

    try:
        connection = store.connect(settings.resolved_database_url())
    except Exception as error:  # noqa: BLE001 - a mensagem do driver é o que ajuda
        print(f"erro ao conectar no Postgres: {error}", file=sys.stderr)
        return 1

    with connection as conn:
        from .search import SearchFilters

        retriever = HybridRetriever(conn, provider)
        response = retriever.search(
            args.question,
            top_k=top_k,
            filters=SearchFilters() if args.no_filters else None,
        )

    if args.explain and response.parsed is not None:
        parsed = response.parsed
        print(f"técnicas na pergunta: {parsed.mitre_techniques or '(nenhuma)'}")
        print(f"plataformas:          {parsed.platforms or '(nenhuma)'}")
        print(f"termos lexicais:      {parsed.lexical_terms or '(nenhum)'}")
        print(f"pernas usadas:        {', '.join(response.legs_used)}")
        print()

    if response.relaxed_filters:
        print(
            "AVISO: nenhuma regra casou os filtros deduzidos "
            f"({response.filters.mitre_techniques or ''} "
            f"{response.filters.platforms or ''}). "
            "Resultados abaixo são da busca sem filtro.\n"
        )

    if not response.results:
        print("nenhuma regra encontrada.")
        return 0

    for position, rule in enumerate(response.results, start=1):
        print(f"{position}. {rule.title}")
        print(f"   {rule.source} | {rule.rule_uid}")
        if rule.platforms or rule.mitre_techniques:
            print(
                f"   plataformas: {', '.join(rule.platforms) or '-'}"
                f" | ATT&CK: {', '.join(rule.mitre_techniques) or '-'}"
            )
        if rule.source_url:
            print(f"   {rule.source_url}")
        if args.explain:
            similarity = f"{rule.similarity:.3f}" if rule.similarity is not None else "-"
            print(
                f"   score RRF: {rule.score:.4f} | cosseno: {similarity}"
                f" | veio de: {', '.join(rule.matched_by)} {rule.ranks}"
            )
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
