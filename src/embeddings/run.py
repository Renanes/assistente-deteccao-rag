"""Gera os embeddings dos chunks e popula o pgvector.

Uso:
    python -m src.embeddings.run                 # indexa o corpus inteiro
    python -m src.embeddings.run --limit 50      # amostra, para validar setup
    python -m src.embeddings.run --reset         # recria a tabela do zero
    python -m src.embeddings.run --dry-run       # não chama a API nem escreve

O provedor vem de `EMBEDDING_PROVIDER` no `.env` — este módulo não conhece
nenhum SDK.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from pathlib import Path

from ..chunking.chunk import RuleChunk
from ..providers import (
    PGVECTOR_INDEX_MAX_DIMENSIONS,
    EmbeddingProvider,
    ProviderError,
    get_embedding_provider,
    get_settings,
)
from . import store

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = REPO_ROOT / "data" / "normalized" / "chunks.jsonl"


def iter_chunks(path: Path, limit: int | None = None) -> Iterator[RuleChunk]:
    """Lê o JSONL da Fase 2, validando cada linha contra o schema do chunk."""
    if not path.is_file():
        raise FileNotFoundError(
            f"Chunks não encontrados em {path}. "
            "Rode `python -m src.chunking.run` antes da indexação."
        )

    with path.open(encoding="utf-8") as handle:
        for position, line in enumerate(handle):
            if limit is not None and position >= limit:
                return
            if line.strip():
                yield RuleChunk.model_validate_json(line)


def check_index_support(provider: EmbeddingProvider) -> None:
    """Recusa um modelo cujo vetor o pgvector não consegue indexar.

    Falhar aqui, antes de gastar chamadas de API, é bem melhor que descobrir
    depois de embeddar o corpus inteiro que a busca vai ser sequencial.
    """
    if provider.dimensions > PGVECTOR_INDEX_MAX_DIMENSIONS:
        raise ProviderError(
            f"O modelo '{provider.model}' produz vetores de {provider.dimensions} "
            f"dimensões, acima do limite de {PGVECTOR_INDEX_MAX_DIMENSIONS} dos "
            "índices HNSW/IVFFlat do pgvector. A busca vetorial cairia em "
            "varredura sequencial. Use um modelo de dimensão menor "
            "(text-embedding-3-small tem 1536) ou migre a coluna para halfvec."
        )


def check_model_consistency(info: store.IndexedCorpusInfo, provider: EmbeddingProvider) -> None:
    """Impede misturar vetores de modelos diferentes na mesma tabela.

    Vetores de modelos distintos não são comparáveis entre si: a distância
    calculada entre eles é um número sem significado. Uma base misturada não
    quebra nada de forma visível — só devolve resultados ruins.
    """
    if not info.exists or info.row_count == 0:
        return

    if info.dimensions is not None and info.dimensions != provider.dimensions:
        raise ProviderError(
            f"A tabela existente guarda vetores de {info.dimensions} dimensões, "
            f"mas '{provider.model}' produz {provider.dimensions}. "
            "Rode com --reset para recriar a tabela."
        )

    other_models = [model for model in info.models if model != provider.model]
    if other_models:
        raise ProviderError(
            f"A tabela já contém vetores de {', '.join(other_models)} e o provedor "
            f"atual é '{provider.model}'. Vetores de modelos diferentes não são "
            "comparáveis. Rode com --reset para reindexar tudo com um modelo só."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument(
        "--limit", type=int, default=None, help="Indexa só os N primeiros chunks."
    )
    parser.add_argument(
        "--reset", action="store_true", help="Recria a tabela antes de indexar."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Só relata o que seria feito — não chama a API nem escreve no banco.",
    )
    args = parser.parse_args()

    settings = get_settings()

    try:
        chunks = list(iter_chunks(args.input, args.limit))
    except FileNotFoundError as error:
        print(f"erro: {error}", file=sys.stderr)
        return 1

    if not chunks:
        print("erro: nenhum chunk para indexar.", file=sys.stderr)
        return 1

    try:
        provider = get_embedding_provider(settings)
        check_index_support(provider)
    except ProviderError as error:
        print(f"erro de provedor: {error}", file=sys.stderr)
        return 1

    print(f"{len(chunks)} chunks | provedor: {provider.name} | modelo: {provider.model}")
    print(f"dimensões: {provider.dimensions}")

    if args.dry_run:
        characters = sum(len(chunk.embedding_text) for chunk in chunks)
        print(f"--dry-run: {characters} caracteres seriam enviados ao provedor.")
        print(f"           ~{characters // 4} tokens estimados.")
        return 0

    try:
        with store.connect(settings.resolved_database_url()) as conn:
            if args.reset:
                store.drop_schema(conn)
                print("tabela removida (--reset)")

            info = store.describe_corpus(conn)
            check_model_consistency(info, provider)

            store.create_schema(conn, provider.dimensions)

            print("gerando embeddings...")
            vectors = provider.embed_documents([chunk.embedding_text for chunk in chunks])

            written = store.upsert_chunks(conn, chunks, vectors, provider.model)
            conn.commit()

            final = store.describe_corpus(conn)
    except ProviderError as error:
        print(f"erro de provedor: {error}", file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001 - a mensagem crua do driver é o que ajuda aqui
        print(f"erro: {error}", file=sys.stderr)
        return 1

    print(f"{written} chunks indexados")
    print(f"  total na base: {final.row_count}")
    print(f"  modelo(s): {', '.join(final.models)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
