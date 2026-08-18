"""Executa a ingestão das 3 fontes e grava o corpus normalizado em JSONL.

Uso:
    python -m src.ingestion.run
    python -m src.ingestion.run --output data/normalized/rules.jsonl

Saída: um `DetectionRule` serializado por linha. JSONL em vez de um único JSON
porque o corpus tem milhares de regras e as fases seguintes (chunking,
embeddings) consomem em streaming, sem carregar tudo em memória.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .escu import parse_escu_rule
from .schema import DetectionRule, RuleSource
from .sigma import parse_sigma_rule
from .yaral import parse_yaral_rule

REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = REPO_ROOT / "data" / "raw"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "normalized" / "rules.jsonl"


@dataclass(frozen=True)
class SourceSpec:
    """Onde encontrar os arquivos de uma fonte e como interpretá-los."""

    source: RuleSource
    repo_dir: Path
    rules_subdir: str
    file_glob: str
    parser: object
    # Segmentos de caminho que descartam o arquivo. Regras descontinuadas são
    # excluídas de propósito: um assistente que cita uma regra deprecada como
    # recomendação está dando uma resposta ativamente errada.
    excluded_segments: tuple[str, ...] = ()


SOURCE_SPECS: tuple[SourceSpec, ...] = (
    SourceSpec(
        source=RuleSource.SIGMA,
        repo_dir=RAW_DIR / "sigma",
        rules_subdir="rules",
        file_glob="**/*.yml",
        parser=parse_sigma_rule,
        excluded_segments=("deprecated", "unsupported"),
    ),
    SourceSpec(
        source=RuleSource.SPLUNK_ESCU,
        repo_dir=RAW_DIR / "splunk_escu",
        rules_subdir="detections",
        file_glob="**/*.yml",
        parser=parse_escu_rule,
        excluded_segments=("deprecated", "removed", "experimental"),
    ),
    SourceSpec(
        source=RuleSource.YARA_L,
        repo_dir=RAW_DIR / "chronicle_yara_l",
        rules_subdir="rules",
        file_glob="**/*.yaral",
        parser=parse_yaral_rule,
        excluded_segments=("_deprecated",),
    ),
)


def iter_source_rules(spec: SourceSpec) -> Iterator[DetectionRule]:
    """Percorre os arquivos de uma fonte e devolve as regras que parseiam."""
    rules_root = spec.repo_dir / spec.rules_subdir
    if not rules_root.is_dir():
        raise FileNotFoundError(
            f"Fonte '{spec.source.value}' não encontrada em {rules_root}. "
            "Clone as fontes públicas em data/raw/ antes de rodar a ingestão "
            "(ver README, seção de ingestão)."
        )

    for path in sorted(rules_root.glob(spec.file_glob)):
        segments = {segment.lower() for segment in path.relative_to(rules_root).parts}
        if segments & set(spec.excluded_segments):
            continue
        if rule := spec.parser(path, spec.repo_dir):  # type: ignore[operator]
            yield rule


def ingest_all() -> tuple[list[DetectionRule], Counter[str]]:
    """Ingere as 3 fontes, descartando UIDs duplicados.

    Duplicata de `rule_uid` é sinal de problema no parser (ex.: fallback de ID
    colidindo), não algo esperado — por isso é contada e reportada, não
    silenciada.
    """
    rules: list[DetectionRule] = []
    seen_uids: set[str] = set()
    stats: Counter[str] = Counter()

    for spec in SOURCE_SPECS:
        for rule in iter_source_rules(spec):
            if rule.rule_uid in seen_uids:
                stats[f"{spec.source.value}_duplicados"] += 1
                continue
            seen_uids.add(rule.rule_uid)
            rules.append(rule)
            stats[spec.source.value] += 1

    return rules, stats


def write_jsonl(rules: list[DetectionRule], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for rule in rules:
            handle.write(rule.model_dump_json() + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Caminho do JSONL de saída (padrão: {DEFAULT_OUTPUT.relative_to(REPO_ROOT)}).",
    )
    args = parser.parse_args()

    try:
        rules, stats = ingest_all()
    except FileNotFoundError as error:
        print(f"erro: {error}", file=sys.stderr)
        return 1

    write_jsonl(rules, args.output)

    print(f"{len(rules)} regras normalizadas -> {args.output}")
    for key in sorted(stats):
        print(f"  {key}: {stats[key]}")

    with_technique = sum(1 for rule in rules if rule.mitre_techniques)
    with_platform = sum(1 for rule in rules if rule.platforms)
    print(f"  cobertura ATT&CK: {with_technique}/{len(rules)}")
    print(f"  cobertura plataforma: {with_platform}/{len(rules)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
