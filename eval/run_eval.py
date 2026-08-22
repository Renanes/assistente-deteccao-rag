"""Mede a qualidade do retrieval contra o conjunto de perguntas de resposta conhecida.

Uso:
    python eval/run_eval.py                    # métricas de retrieval + ablação
    python eval/run_eval.py --sweep            # varre o k do RRF
    python eval/run_eval.py --with-rag         # inclui ancoragem das respostas (gasta LLM)
    python eval/run_eval.py --output eval/results.md

**Como o conjunto foi montado, e o que isso limita.** As 30 regras-alvo foram
sorteadas do corpus com semente fixa (`20260822`), estratificadas por fonte,
*antes* de qualquer pergunta ser escrita — sem isso, seria fácil escolher depois
só as regras que funcionam e publicar um número bonito. As perguntas foram
escritas a partir da descrição de cada regra, em português, sem copiar o título
(há uma checagem disso). Duas limitações que o número carrega e que nenhum
processo aqui elimina:

1. **É um piso, não a taxa real.** Só um `rule_uid` é aceito como correto por
   pergunta, mas o corpus tem regras equivalentes: uma busca que devolve outra
   regra igualmente válida para dump de LSASS conta como erro aqui.
2. **Quem escreveu as perguntas conhecia o sistema.** O viés é real e não some
   por boa intenção. O que reduz seu efeito é a amostra ter sido fixada antes e
   nenhuma pergunta ter sido descartada depois de ver o resultado.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.embeddings import store  # noqa: E402
from src.providers import (  # noqa: E402
    EmbeddingProvider,
    ProviderError,
    get_embedding_provider,
    get_llm_provider,
    get_settings,
)
from src.rag.pipeline import RagPipeline  # noqa: E402
from src.retrieval.search import HybridRetriever, SearchFilters  # noqa: E402

QUESTIONS_PATH = REPO_ROOT / "eval" / "questions.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "eval" / "results.md"
RECALL_CUTOFFS = (1, 3, 5, 10)
RETRIEVAL_DEPTH = 20


class CachingEmbeddingProvider(EmbeddingProvider):
    """Memoiza `embed_query` para a mesma pergunta não ser embeddada de novo.

    A ablação roda cada pergunta em 4 configurações e a varredura de `k` em
    várias mais. Sem cache seriam centenas de chamadas idênticas — custo e
    latência à toa, e nenhuma variação de medida vem daí.
    """

    def __init__(self, inner: EmbeddingProvider) -> None:
        self._inner = inner
        self.name = inner.name
        self.model = inner.model
        self.dimensions = inner.dimensions
        self._cache: dict[str, list[float]] = {}
        self.calls = 0

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._inner.embed_documents(texts)

    def embed_query(self, text: str) -> list[float]:
        if text not in self._cache:
            self.calls += 1
            self._cache[text] = self._inner.embed_query(text)
        return self._cache[text]


@dataclass
class QuestionResult:
    question_id: str
    category: str
    source: str
    #: Posição (1-indexada) da regra correta, ou None se não apareceu.
    rank: int | None


@dataclass
class Metrics:
    label: str
    total: int
    recall: dict[int, float]
    mrr: float
    misses: list[str]


def load_questions() -> list[dict]:
    if not QUESTIONS_PATH.is_file():
        raise FileNotFoundError(f"conjunto de avaliação não encontrado em {QUESTIONS_PATH}")
    return [
        json.loads(line)
        for line in QUESTIONS_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def find_rank(results, expected_uid: str) -> int | None:
    """Posição da regra esperada nos resultados, 1-indexada."""
    for position, rule in enumerate(results, start=1):
        if rule.rule_uid == expected_uid:
            return position
    return None


def evaluate(
    retriever: HybridRetriever,
    questions: list[dict],
    label: str,
    *,
    use_filters: bool = True,
    rrf_k: int = 60,
    **search_kwargs: object,
) -> tuple[Metrics, list[QuestionResult]]:
    results: list[QuestionResult] = []

    for question in questions:
        response = retriever.search(
            question["question"],
            top_k=RETRIEVAL_DEPTH,
            filters=None if use_filters else SearchFilters(),
            rrf_k=rrf_k,
            **search_kwargs,  # type: ignore[arg-type]
        )
        results.append(
            QuestionResult(
                question_id=question["id"],
                category=question["category"],
                source=question["source"],
                rank=find_rank(response.results, question["expected_rule_uid"]),
            )
        )

    return summarize(results, label), results


def summarize(results: list[QuestionResult], label: str) -> Metrics:
    total = len(results)
    recall = {
        cutoff: sum(1 for r in results if r.rank is not None and r.rank <= cutoff) / total
        for cutoff in RECALL_CUTOFFS
    }
    mrr = sum(1 / r.rank for r in results if r.rank is not None) / total
    misses = [r.question_id for r in results if r.rank is None or r.rank > 5]
    return Metrics(label=label, total=total, recall=recall, mrr=mrr, misses=misses)


def breakdown(results: list[QuestionResult], key: str) -> dict[str, tuple[int, int, float]]:
    """Agrupa por categoria ou fonte: (acertos@5, total, recall@5)."""
    grouped: dict[str, list[QuestionResult]] = defaultdict(list)
    for result in results:
        grouped[getattr(result, key)].append(result)

    return {
        name: (
            sum(1 for r in items if r.rank is not None and r.rank <= 5),
            len(items),
            sum(1 for r in items if r.rank is not None and r.rank <= 5) / len(items),
        )
        for name, items in sorted(grouped.items())
    }


def format_metrics_table(all_metrics: list[Metrics]) -> str:
    header = "| Configuração | " + " | ".join(f"recall@{c}" for c in RECALL_CUTOFFS) + " | MRR |"
    separator = "|" + "---|" * (len(RECALL_CUTOFFS) + 2)
    rows = [
        f"| {m.label} | "
        + " | ".join(f"{m.recall[c]:.0%}" for c in RECALL_CUTOFFS)
        + f" | {m.mrr:.3f} |"
        for m in all_metrics
    ]
    return "\n".join([header, separator, *rows])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--sweep", action="store_true", help="Varre o k do RRF.")
    parser.add_argument(
        "--with-rag",
        action="store_true",
        help="Mede também a ancoragem das respostas geradas (gasta chamadas de LLM).",
    )
    args = parser.parse_args()

    settings = get_settings()
    questions = load_questions()

    try:
        provider = CachingEmbeddingProvider(get_embedding_provider(settings))
    except ProviderError as error:
        print(f"erro de provedor: {error}", file=sys.stderr)
        return 1

    try:
        connection = store.connect(settings.resolved_database_url())
    except Exception as error:  # noqa: BLE001
        print(f"erro ao conectar no Postgres: {error}", file=sys.stderr)
        return 1

    lines: list[str] = []

    def emit(text: str = "") -> None:
        print(text)
        lines.append(text)

    with connection as conn:
        indexed = conn.execute("SELECT count(*) FROM rule_chunks").fetchone()[0]
        models = conn.execute("SELECT DISTINCT embedding_model FROM rule_chunks").fetchall()
        retriever = HybridRetriever(conn, provider)

        emit("# Avaliação de retrieval")
        emit()
        emit(f"- Data: {datetime.now(UTC):%Y-%m-%d}")
        emit(f"- Perguntas: {len(questions)}")
        emit(f"- Corpus indexado: {indexed} chunks")
        emit(f"- Modelo de embedding: {', '.join(row[0] for row in models)}")
        emit(f"- Profundidade de busca: top-{RETRIEVAL_DEPTH}")
        emit()

        # --- Ablação ---
        #
        # A primeira linha é a configuração padrão do sistema. As seguintes
        # ligam de volta, uma a uma, as peças que esta avaliação mandou
        # desligar — é o que sustenta a decisão, e mantê-las na tabela é o que
        # permite alguém refutá-la depois.
        configurations: list[tuple[str, bool, dict]] = [
            ("**Padrão**: filtro ATT&CK + vetorial", True, {}),
            ("+ perna de full-text", True, {"use_fulltext": True}),
            ("+ inferência de plataforma", True, {"infer_platform": True}),
            ("+ ambas (híbrida original da Fase 4)", True,
             {"use_fulltext": True, "infer_platform": True}),
            ("Vetorial pura, sem filtro (linha de base)", False, {}),
        ]

        all_metrics: list[Metrics] = []
        default_results: list[QuestionResult] = []
        for label, use_filters, kwargs in configurations:
            metrics, results = evaluate(
                retriever, questions, label, use_filters=use_filters, **kwargs
            )
            all_metrics.append(metrics)
            if not kwargs and use_filters:
                default_results = results

        emit("## Ablação")
        emit()
        emit(format_metrics_table(all_metrics))
        emit()

        # --- Recortes da configuração padrão ---
        emit("## Recortes da configuração padrão (recall@5)")
        emit()
        for key, title in (("category", "Tipo de pergunta"), ("source", "Fonte da regra")):
            emit(f"**{title}**")
            emit()
            emit("| | acertos | total | recall@5 |")
            emit("|---|---|---|---|")
            for name, (hits, total, rate) in breakdown(default_results, key).items():
                emit(f"| {name} | {hits} | {total} | {rate:.0%} |")
            emit()

        failures = [r for r in default_results if r.rank is None or r.rank > 5]
        emit("## Perguntas fora do top-5 na configuração padrão")
        emit()
        if failures:
            by_id = {q["id"]: q for q in questions}
            emit("| id | posição | categoria | pergunta |")
            emit("|---|---|---|---|")
            for result in failures:
                position = str(result.rank) if result.rank else f">{RETRIEVAL_DEPTH}"
                emit(
                    f"| {result.question_id} | {position} | {result.category} "
                    f"| {by_id[result.question_id]['question'][:70]} |"
                )
        else:
            emit("Nenhuma — todas as 30 regras-alvo apareceram no top-5.")
        emit()

        # --- Varredura do k do RRF ---
        if args.sweep:
            emit("## Varredura do k do RRF")
            emit()
            emit(
                "Medida com a perna de full-text **ligada**. Na configuração padrão a "
                "varredura seria inerte por construção: com uma única lista ranqueada, "
                "o RRF preserva a ordem dela para qualquer `k`. O `k` só passa a "
                "importar quando há duas listas para conciliar."
            )
            emit()
            sweep_metrics = [
                evaluate(retriever, questions, f"k = {k}", rrf_k=k, use_fulltext=True)[0]
                for k in (10, 30, 60, 100)
            ]
            emit(format_metrics_table(sweep_metrics))
            emit()

        # --- Ancoragem das respostas geradas ---
        if args.with_rag:
            try:
                llm = get_llm_provider(settings)
            except ProviderError as error:
                emit(f"(ancoragem não medida: {error})")
            else:
                pipeline = RagPipeline.build(conn, provider, llm, top_k=5)
                grounded = 0
                invalid = 0
                for question in questions:
                    answer = pipeline.answer(question["question"])
                    grounded += answer.citation_check.is_grounded
                    invalid += bool(answer.citation_check.invalid)

                emit("## Ancoragem das respostas geradas")
                emit()
                emit(f"- Modelo de geração: {llm.name}/{llm.model}")
                emit(f"- Respostas ancoradas: {grounded}/{len(questions)}")
                emit(f"- Respostas com citação inexistente: {invalid}/{len(questions)}")
                emit()

        emit(f"_Chamadas de embedding (com cache): {provider.calls}_")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n-> {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
