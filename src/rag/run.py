"""Pergunta ao assistente pela linha de comando.

Uso:
    python -m src.rag.run "como detectar injeção de processo no Windows?"
    python -m src.rag.run "tem regra pra T1055?" --provider openai
    python -m src.rag.run "mimikatz" --top-k 8 --show-sources

`--provider` sobrescreve o `LLM_PROVIDER` do `.env` para uma execução, que é
como o critério de aceite da fase (funcionar com os dois provedores) foi
verificado sem editar arquivo entre um teste e outro.
"""

from __future__ import annotations

import argparse
import sys

from ..embeddings import store
from ..providers import ProviderError, get_embedding_provider, get_llm_provider, get_settings
from .pipeline import RagPipeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question")
    parser.add_argument("--top-k", type=int, default=None)
    parser.add_argument(
        "--provider",
        choices=("anthropic", "openai"),
        default=None,
        help="Sobrescreve LLM_PROVIDER só nesta execução.",
    )
    parser.add_argument(
        "--show-sources", action="store_true", help="Lista as regras recuperadas."
    )
    args = parser.parse_args()

    settings = get_settings()
    if args.provider:
        settings = settings.model_copy(update={"llm_provider": args.provider})

    try:
        embedding_provider = get_embedding_provider(settings)
        llm_provider = get_llm_provider(settings)
    except ProviderError as error:
        print(f"erro de provedor: {error}", file=sys.stderr)
        return 1

    try:
        connection = store.connect(settings.resolved_database_url())
    except Exception as error:  # noqa: BLE001 - a mensagem do driver é o que ajuda
        print(f"erro ao conectar no Postgres: {error}", file=sys.stderr)
        return 1

    with connection as conn:
        pipeline = RagPipeline.build(
            conn, embedding_provider, llm_provider, top_k=args.top_k or settings.retrieval_top_k
        )
        result = pipeline.answer(args.question)

    print(result.answer)
    print()
    print("-" * 70)
    print(f"gerado por {result.llm_provider}/{result.llm_model}")

    if result.answered_without_model:
        print("nenhuma regra recuperada — modelo não foi chamado")
        return 0

    check = result.citation_check
    print(f"regras recuperadas: {len(result.retrieved)} | citadas: {list(check.cited)}")
    if check.invalid:
        print(f"ATENÇÃO: citações inválidas na resposta: {list(check.invalid)}")
    if check.uncited:
        print("ATENÇÃO: a resposta não citou nenhuma regra.")
    if result.answer_truncated:
        print("ATENÇÃO: a resposta pode ter sido cortada pelo limite de tokens.")
    if result.search and result.search.relaxed_filters:
        print("nota: o filtro foi relaxado — não há regra para o termo exato pedido.")

    if args.show_sources:
        print()
        for index, rule in enumerate(result.retrieved, start=1):
            marker = "*" if index in check.cited else " "
            print(f" {marker}[{index}] {rule.title}")
            print(f"      {rule.rule_uid}")
            if rule.source_url:
                print(f"      {rule.source_url}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
