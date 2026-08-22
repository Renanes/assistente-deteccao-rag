"""Aplica o chunking ao corpus normalizado e grava os chunks em JSONL.

Uso:
    python -m src.chunking.run
    python -m src.chunking.run --input data/normalized/rules.jsonl \
        --output data/normalized/chunks.jsonl

Entrada e saída são JSONL pelo mesmo motivo da Fase 1: o corpus tem milhares de
itens e a Fase 3 consome em streaming, sem carregar tudo em memória.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from ..ingestion.schema import DetectionRule
from .chunk import MAX_QUERY_CHARS, RuleChunk, chunk_rule

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = REPO_ROOT / "data" / "normalized" / "rules.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "normalized" / "chunks.jsonl"


def iter_rules(path: Path) -> Iterator[DetectionRule]:
    """Lê o JSONL da Fase 1, validando cada linha contra o schema."""
    if not path.is_file():
        raise FileNotFoundError(
            f"Corpus normalizado não encontrado em {path}. "
            "Rode `python -m src.ingestion.run` antes do chunking."
        )

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield DetectionRule.model_validate_json(line)


def build_chunks(
    rules: Iterator[DetectionRule], max_query_chars: int = MAX_QUERY_CHARS
) -> tuple[list[RuleChunk], Counter[str]]:
    """Gera os chunks e coleta as estatísticas que valem revisar depois."""
    chunks: list[RuleChunk] = []
    stats: Counter[str] = Counter()

    for rule in rules:
        for chunk in chunk_rule(rule, max_query_chars):
            chunks.append(chunk)
            stats[f"chunks_{chunk.source.value}"] += 1
            if chunk.query_truncated:
                stats["queries_truncadas"] += 1

    return chunks, stats


def write_jsonl(chunks: list[RuleChunk], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for chunk in chunks:
            handle.write(chunk.model_dump_json() + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--max-query-chars",
        type=int,
        default=MAX_QUERY_CHARS,
        help=f"Teto de caracteres da query preservada (padrão: {MAX_QUERY_CHARS}).",
    )
    args = parser.parse_args()

    try:
        chunks, stats = build_chunks(iter_rules(args.input), args.max_query_chars)
    except FileNotFoundError as error:
        print(f"erro: {error}", file=sys.stderr)
        return 1

    write_jsonl(chunks, args.output)

    lengths = sorted(len(chunk.embedding_text) for chunk in chunks)
    print(f"{len(chunks)} chunks -> {args.output}")
    for key in sorted(stats):
        print(f"  {key}: {stats[key]}")
    if lengths:
        print(
            "  texto embeddado (chars): "
            f"p50={lengths[len(lengths) // 2]} "
            f"p99={lengths[min(len(lengths) - 1, int(len(lengths) * 0.99))]} "
            f"max={lengths[-1]}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
