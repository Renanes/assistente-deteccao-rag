"""Integridade do conjunto de avaliação e das decisões medidas na Fase 6.

Duas coisas sob teste aqui, e as duas protegem números que já foram publicados:

1. **O conjunto de perguntas.** Um `expected_rule_uid` que deixa de existir, um
   id repetido ou uma pergunta que passa a copiar o título da regra corrompem a
   medição sem quebrar nada visivelmente — `run_eval.py` continuaria rodando e
   imprimindo um número, só que errado.
2. **Os defaults que a medição escolheu.** Desligar a inferência de plataforma e
   a perna de full-text foi decisão baseada em dados (ver `eval/results.md`).
   Sem um teste, alguém religa por parecer "mais completo" e o recall cai de
   97% para 83% sem que nada acuse.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.retrieval.query import (
    _looks_like_identifier,
    extract_lexical_terms,
    parse_query,
)
from src.retrieval.search import (
    INFER_PLATFORM_BY_DEFAULT,
    USE_FULLTEXT_BY_DEFAULT,
    SearchFilters,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
QUESTIONS_PATH = REPO_ROOT / "eval" / "questions.jsonl"
CORPUS_PATH = REPO_ROOT / "data" / "normalized" / "rules.jsonl"
VALID_CATEGORIES = {"attack_id", "lexical", "semantic"}


@pytest.fixture(scope="module")
def questions() -> list[dict]:
    lines = QUESTIONS_PATH.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


# --------------------------------------------------------------------------
# Conjunto de avaliação
# --------------------------------------------------------------------------


def test_question_set_has_the_documented_size(questions: list[dict]) -> None:
    """O `CLAUDE.md` pede 20–30 perguntas; `eval/results.md` publica 30."""
    assert len(questions) == 30


def test_every_question_has_the_required_fields(questions: list[dict]) -> None:
    for question in questions:
        for field in ("id", "question", "expected_rule_uid", "category", "source"):
            assert question.get(field), f"{question.get('id')} sem campo {field}"
        assert question["category"] in VALID_CATEGORIES


def test_question_ids_and_targets_are_unique(questions: list[dict]) -> None:
    """Alvo repetido inflaria o peso de uma regra na média."""
    ids = [q["id"] for q in questions]
    targets = [q["expected_rule_uid"] for q in questions]
    assert len(set(ids)) == len(ids)
    assert len(set(targets)) == len(targets)


def test_all_three_sources_are_represented(questions: list[dict]) -> None:
    assert {q["source"] for q in questions} == {"sigma", "splunk_escu", "yara_l"}


def test_every_retrieval_path_is_exercised(questions: list[dict]) -> None:
    """Sem as três categorias, o recorte por tipo de pergunta perde o sentido."""
    counts = {category: 0 for category in VALID_CATEGORIES}
    for question in questions:
        counts[question["category"]] += 1
    for category, count in counts.items():
        assert count >= 5, f"categoria {category} com só {count} perguntas"


@pytest.mark.skipif(not CORPUS_PATH.is_file(), reason="corpus normalizado não gerado")
def test_every_target_rule_exists_in_the_corpus(questions: list[dict]) -> None:
    uids = set()
    with CORPUS_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            uids.add(json.loads(line)["rule_uid"])

    missing = [q["id"] for q in questions if q["expected_rule_uid"] not in uids]
    assert not missing, f"perguntas apontando para regra inexistente: {missing}"


@pytest.mark.skipif(not CORPUS_PATH.is_file(), reason="corpus normalizado não gerado")
def test_no_question_copies_the_rule_title(questions: list[dict]) -> None:
    """Pergunta que repete o título mede casamento de título, não retrieval."""
    targets = {q["expected_rule_uid"] for q in questions}
    titles: dict[str, str] = {}
    with CORPUS_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            rule = json.loads(line)
            if rule["rule_uid"] in targets:
                titles[rule["rule_uid"]] = rule["title"]

    leaking = [
        q["id"]
        for q in questions
        if titles.get(q["expected_rule_uid"], "").lower() in q["question"].lower()
    ]
    assert not leaking, f"perguntas copiando o título da regra: {leaking}"


# --------------------------------------------------------------------------
# Defaults escolhidos pela medição
# --------------------------------------------------------------------------


def test_platform_inference_is_off_by_default() -> None:
    """Regressão da classe de falha q06/q14/q24 (ver `eval/results.md`).

    `infer_platforms` foi escrito para texto de telemetria e dispara demais em
    pergunta corrente: "endereço de e-mail" virava filtro `email`, excluindo uma
    regra marcada como `web`. Religar isto derruba o recall@5 de 97% para 87%.
    """
    assert INFER_PLATFORM_BY_DEFAULT is False


def test_fulltext_leg_is_off_by_default() -> None:
    """Medido em quatro variantes, nenhuma superou não usar a perna.

    A causa é estrutural: `search_text` indexa o mesmo texto que o vetor cobre.
    Religar isto derruba o recall@5 de 97% para 93%.
    """
    assert USE_FULLTEXT_BY_DEFAULT is False


def test_attack_filter_is_still_inferred() -> None:
    """O que a Fase 6 desligou foi a plataforma, não a técnica.

    O filtro ATT&CK é o que dá o ganho sobre a vetorial pura (MRR 0,879 contra
    0,846) e o que sustenta o critério de aceite da Fase 4.
    """
    parsed = parse_query("tem regra pra T1055?")
    assert parsed.mitre_techniques == ["T1055"]
    assert SearchFilters.from_parsed(parsed).mitre_techniques == ("T1055",)


def test_explicit_platform_filter_still_works() -> None:
    """Desligar a inferência não pode ter desligado o filtro em si.

    Quem escolhe "windows" numa faceta de interface quis dizer isso; quem
    escreveu "logs web" numa frase, não. A distinção é a decisão inteira.
    """
    filters = SearchFilters(platforms=("windows",))
    assert not filters.is_empty
    assert filters.platforms == ("windows",)


# --------------------------------------------------------------------------
# Termos lexicais restritos a identificadores
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token", ["T1055", "CVE-2022-42889", "tttracer.exe", "DontShowUI", "4688"]
)
def test_identifier_shaped_tokens_are_recognized(token: str) -> None:
    assert _looks_like_identifier(token)


@pytest.mark.parametrize("token", ["conexao", "identificar", "ferramenta", "memoria"])
def test_plain_words_are_not_identifiers(token: str) -> None:
    """As palavras que a medição apontou como ruído da consulta OR."""
    assert not _looks_like_identifier(token)


def test_identifiers_only_mode_drops_plain_words() -> None:
    text = "identificar conexao com o CMLUA.dll no evento 4688"
    broad = extract_lexical_terms(text)
    narrow = extract_lexical_terms(text, identifiers_only=True)

    assert "cmlua.dll" in narrow
    assert "4688" in narrow
    assert "conexao" in broad and "conexao" not in narrow
    assert set(narrow) < set(broad)
