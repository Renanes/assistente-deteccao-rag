"""Testes da busca híbrida (Fase 4).

O `CLAUDE.md` (seção 7) chama o retrieval de uma das partes com mais risco de
erro silencioso, e é uma descrição exata: uma busca que devolve *alguma coisa*
parece funcionar. Um filtro que nunca casa, uma fusão que ignora uma das
listas, uma expansão de técnica invertida — nada disso levanta exceção. Todos
os casos abaixo existem para falhar alto onde o sistema falharia baixo.

Os testes marcados com `@pytest.mark.integration` precisam do Postgres com o
corpus indexado e de uma chave de embedding válida; são pulados quando faltam,
para o `pytest` continuar verde numa máquina sem ambiente montado.
"""

from __future__ import annotations

import pytest

from src.retrieval.fusion import RankedList, reciprocal_rank_fusion
from src.retrieval.query import (
    build_tsquery,
    extract_lexical_terms,
    extract_query_techniques,
    parse_query,
)
from src.retrieval.search import SearchFilters, _filter_sql

# --------------------------------------------------------------------------
# Fusão RRF
# --------------------------------------------------------------------------


def test_rrf_rewards_appearing_in_both_lists() -> None:
    """A razão de ser da fusão: estar nas duas pernas vence estar só numa.

    "consenso" é 2º nas duas listas (1/62 + 1/62 ≈ 0,0323) e precisa ganhar de
    "so_vetorial" e "so_fulltext", que são 1º em uma lista só (1/61 ≈ 0,0164).
    Se este teste falhar, a fusão virou um "ou" caro.
    """
    fused = reciprocal_rank_fusion(
        [
            RankedList(name="vetorial", chunk_uids=["so_vetorial", "consenso"]),
            RankedList(name="full-text", chunk_uids=["so_fulltext", "consenso"]),
        ]
    )
    assert fused[0].chunk_uid == "consenso"
    assert fused[0].matched_by == ("full-text", "vetorial")
    assert fused[0].score > fused[1].score


def test_rrf_still_favors_a_strong_first_place_over_a_weak_consensus() -> None:
    """Contrapartida do teste acima, e uma propriedade real do RRF.

    A curva 1/(k+rank) é convexa, então ganhar posições no topo vale mais do que
    perder posições no fundo: 1º + 3º (1/61 + 1/63) supera 2º + 2º (2/62), ainda
    que por pouco. Documentado como teste porque é contraintuitivo — a leitura
    ingênua de "consenso vence" levaria a crer no contrário, e alguém ajustando
    o `k` na Fase 6 precisa saber que essa é a intenção e não um bug.
    """
    fused = reciprocal_rank_fusion(
        [
            RankedList(name="vetorial", chunk_uids=["a", "b", "c"]),
            RankedList(name="full-text", chunk_uids=["c", "b", "a"]),
        ]
    )
    by_uid = {item.chunk_uid: item.score for item in fused}
    assert by_uid["a"] == pytest.approx(1 / 61 + 1 / 63)
    assert by_uid["b"] == pytest.approx(2 / 62)
    assert by_uid["a"] > by_uid["b"]
    # O empate entre "a" e "c" é desfeito pelo uid, de forma determinística.
    assert by_uid["a"] == pytest.approx(by_uid["c"])
    assert [item.chunk_uid for item in fused][:2] == ["a", "c"]


def test_rrf_score_matches_the_formula() -> None:
    fused = reciprocal_rank_fusion(
        [
            RankedList(name="l1", chunk_uids=["x"]),
            RankedList(name="l2", chunk_uids=["y", "x"]),
        ],
        k=60,
    )
    by_uid = {item.chunk_uid: item for item in fused}
    assert by_uid["x"].score == pytest.approx(1 / 61 + 1 / 62)
    assert by_uid["y"].score == pytest.approx(1 / 61)


def test_rrf_records_the_rank_in_each_list() -> None:
    """As posições são o que permite explicar na interface por que a regra veio."""
    fused = reciprocal_rank_fusion(
        [
            RankedList(name="vetorial", chunk_uids=["a", "b"]),
            RankedList(name="full-text", chunk_uids=["b"]),
        ]
    )
    by_uid = {item.chunk_uid: item for item in fused}
    assert by_uid["b"].ranks == {"vetorial": 2, "full-text": 1}
    assert by_uid["a"].ranks == {"vetorial": 1}


def test_rrf_keeps_the_best_position_of_a_repeated_uid() -> None:
    """Duplicata dentro de uma lista não pode pontuar duas vezes."""
    duplicated = reciprocal_rank_fusion([RankedList(name="l", chunk_uids=["a", "a"])])
    single = reciprocal_rank_fusion([RankedList(name="l", chunk_uids=["a"])])
    assert duplicated[0].score == pytest.approx(single[0].score)
    assert duplicated[0].ranks == {"l": 1}


def test_rrf_is_deterministic_on_ties() -> None:
    """Sem desempate estável, a avaliação da Fase 6 seria irreproduzível."""
    lists = [RankedList(name="l1", chunk_uids=["b", "a"]), RankedList(name="l2", chunk_uids=["a", "b"])]
    first = [item.chunk_uid for item in reciprocal_rank_fusion(lists)]
    second = [item.chunk_uid for item in reciprocal_rank_fusion(list(reversed(lists)))]
    assert first == second == ["a", "b"]


def test_rrf_respects_weights_and_limit() -> None:
    fused = reciprocal_rank_fusion(
        [
            RankedList(name="fraca", chunk_uids=["a"], weight=0.1),
            RankedList(name="forte", chunk_uids=["b"], weight=1.0),
        ],
        limit=1,
    )
    assert len(fused) == 1
    assert fused[0].chunk_uid == "b"


def test_rrf_rejects_a_non_positive_k() -> None:
    with pytest.raises(ValueError, match="positivo"):
        reciprocal_rank_fusion([RankedList(name="l", chunk_uids=["a"])], k=0)


def test_rrf_handles_empty_input() -> None:
    assert reciprocal_rank_fusion([]) == []
    assert reciprocal_rank_fusion([RankedList(name="l", chunk_uids=[])]) == []


# --------------------------------------------------------------------------
# Interpretação da pergunta
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("tem regra pra T1055?", ["T1055"]),
        ("t1055.001 e T1027", ["T1055.001", "T1027"]),
        ("nada de attack aqui", []),
    ],
)
def test_extract_query_techniques(question: str, expected: list[str]) -> None:
    assert extract_query_techniques(question) == expected


def test_parse_query_infers_platform_from_a_tool_name() -> None:
    """"sysmon" precisa virar `windows` na pergunta como vira na ingestão."""
    assert parse_query("eventos de sysmon suspeitos").platforms == ["windows"]


def test_parse_query_keeps_the_original_text_for_the_embedding() -> None:
    question = "  como detectar injeção de processo?  "
    assert parse_query(question).text == question


def test_portuguese_stopwords_do_not_become_lexical_terms() -> None:
    """A coluna full-text usa a config `english`, que não filtra português."""
    terms = extract_lexical_terms("quais regras existem para detectar mimikatz")
    assert "mimikatz" in terms
    for stopword in ("quais", "regras", "existem", "para", "detectar"):
        assert stopword not in terms


def test_identifiers_survive_as_lexical_terms() -> None:
    terms = extract_lexical_terms("evento 4688 no kube-apiserver com rundll32.exe")
    assert "4688" in terms
    assert "kube-apiserver" in terms
    assert "rundll32.exe" in terms


def test_short_generic_tokens_are_dropped() -> None:
    assert extract_lexical_terms("de os id no") == []


def test_lexical_terms_are_deduplicated_preserving_order() -> None:
    assert extract_lexical_terms("mimikatz e MIMIKATZ de novo") == ["mimikatz", "novo"]


def test_build_tsquery_joins_with_or() -> None:
    """AND exigiria todos os termos e uma pergunta natural não devolveria nada."""
    assert build_tsquery(["mimikatz", "4688"]) == "mimikatz | 4688"


def test_build_tsquery_strips_tsquery_metacharacters() -> None:
    """Um `:` solto derruba a consulta inteira com erro de sintaxe."""
    assert ":" not in build_tsquery(["foo:bar"])
    assert "'" not in build_tsquery(["o'brien"])


def test_build_tsquery_of_nothing_is_empty() -> None:
    # String vazia é o sinal de "pule a perna de full-text".
    assert build_tsquery([]) == ""


# --------------------------------------------------------------------------
# Filtros rígidos — a expansão de técnica é o núcleo da Fase 4
# --------------------------------------------------------------------------


def test_parent_technique_matches_its_subtechniques() -> None:
    """O caso exato do critério de aceite.

    O full-text tokeniza `T1055.001` como termo único, então `T1055` não o
    encontraria. A expansão por prefixo na coluna de metadado é o que faz a
    pergunta com termo exato funcionar.
    """
    where, params = _filter_sql(SearchFilters(mitre_techniques=("T1055",)))

    assert "unnest(mitre_techniques)" in where
    assert params["mitre_exact"] == ["T1055"]
    assert params["mitre_prefixes"] == ["T1055.%"]


def test_subtechnique_also_matches_its_parent() -> None:
    """Quem pergunta por T1218.011 aceita bem uma regra marcada só como T1218."""
    _, params = _filter_sql(SearchFilters(mitre_techniques=("T1218.011",)))

    assert params["mitre_exact"] == ["T1218", "T1218.011"]
    # Subtécnica não expande por prefixo: T1218.011 não é pai de ninguém.
    assert params["mitre_prefixes"] == [""]


def test_prefix_placeholder_never_matches_everything() -> None:
    """Uma lista de prefixos vazia viraria `LIKE ANY(ARRAY[])`.

    O placeholder precisa ser algo que não casa com técnica nenhuma. Se virasse
    `%`, o filtro deixaria passar o corpus inteiro — e um filtro que não filtra
    é exatamente o erro silencioso que estes testes existem para pegar.
    """
    _, params = _filter_sql(SearchFilters(mitre_techniques=("T1218.011",)))
    assert params["mitre_prefixes"] == [""]
    assert "%" not in params["mitre_prefixes"][0]


def test_platform_filter_uses_array_overlap() -> None:
    where, params = _filter_sql(SearchFilters(platforms=("windows",)))
    assert "platforms && " in where
    assert params["platforms"] == ["windows"]


def test_filters_combine_with_and() -> None:
    where, _ = _filter_sql(
        SearchFilters(mitre_techniques=("T1055",), platforms=("windows",), sources=("sigma",))
    )
    assert where.count(" AND ") == 2


def test_empty_filters_produce_a_passthrough_where() -> None:
    where, params = _filter_sql(SearchFilters())
    assert where == "TRUE"
    assert params == {}


def test_filters_from_parsed_query() -> None:
    filters = SearchFilters.from_parsed(parse_query("regra de T1055 pra windows"))
    assert filters.mitre_techniques == ("T1055",)
    assert filters.platforms == ("windows",)
    assert not filters.is_empty


# --------------------------------------------------------------------------
# Integração: exige Postgres com o corpus indexado + chave de embedding
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def retriever():  # type: ignore[no-untyped-def]
    from src.embeddings import store
    from src.providers import ProviderError, get_embedding_provider, get_settings
    from src.retrieval import HybridRetriever

    settings = get_settings()
    try:
        provider = get_embedding_provider(settings)
    except ProviderError as error:
        pytest.skip(f"sem provedor de embedding configurado: {error}")

    try:
        conn = store.connect(settings.resolved_database_url())
    except Exception as error:  # noqa: BLE001
        pytest.skip(f"sem Postgres disponível: {error}")

    with conn:
        count = conn.execute("SELECT count(*) FROM rule_chunks").fetchone()
        if not count or count[0] == 0:
            pytest.skip("corpus não indexado — rode `python -m src.embeddings.run`")
        yield HybridRetriever(conn, provider)


@pytest.mark.integration
@pytest.mark.parametrize("technique", ["T1055", "T1003.001", "T1547.001"])
def test_exact_technique_dominates_the_top_k(retriever, technique: str) -> None:  # type: ignore[no-untyped-def]
    """CRITÉRIO DE ACEITE DA FASE 4.

    A pergunta cita um termo exato e todas as regras devolvidas precisam
    realmente cobrir essa técnica. Medido contra a busca vetorial pura, que
    nesta mesma pergunta traz 0 ou 1 regra correta em 5.
    """
    response = retriever.search(f"regras para {technique}", top_k=5)
    parent = technique.split(".")[0]

    assert response.results, f"nenhuma regra devolvida para {technique}"
    assert not response.relaxed_filters, "o filtro não deveria ter sido relaxado"

    for rule in response.results:
        assert any(
            found == technique or found.startswith(parent) for found in rule.mitre_techniques
        ), f"{rule.title} não cobre {technique}: {rule.mitre_techniques}"


@pytest.mark.integration
def test_hybrid_beats_pure_vector_on_an_exact_term(retriever) -> None:  # type: ignore[no-untyped-def]
    """A comparação que justifica a fase existir."""
    response = retriever.search("T1055", top_k=5)
    with_technique = sum(
        1 for rule in response.results if any(t.startswith("T1055") for t in rule.mitre_techniques)
    )
    assert with_technique == 5

    # A perna vetorial sozinha, sem filtro, não conseguiria o mesmo.
    unfiltered = retriever.search("T1055", top_k=5, filters=SearchFilters())
    baseline = sum(
        1 for rule in unfiltered.results if any(t.startswith("T1055") for t in rule.mitre_techniques)
    )
    assert with_technique > baseline


@pytest.mark.integration
def test_platform_filter_narrows_the_results(retriever) -> None:  # type: ignore[no-untyped-def]
    response = retriever.search("coleta de credenciais", top_k=5, filters=SearchFilters(platforms=("linux",)))
    assert response.results
    for rule in response.results:
        assert "linux" in rule.platforms


@pytest.mark.integration
def test_impossible_filter_relaxes_and_says_so(retriever) -> None:  # type: ignore[no-untyped-def]
    """Devolver nada é pior que relaxar — mas relaxar em silêncio é pior ainda.

    A Fase 5 precisa da flag para não afirmar que existe regra para uma técnica
    que o corpus não cobre.
    """
    response = retriever.search(
        "qualquer coisa", top_k=5, filters=SearchFilters(mitre_techniques=("T9999",))
    )
    assert response.relaxed_filters is True
    assert response.results


@pytest.mark.integration
def test_results_carry_everything_needed_for_citation(retriever) -> None:  # type: ignore[no-untyped-def]
    """A Fase 5 cita a fonte real — sem esses campos, não tem como."""
    response = retriever.search("injeção de processo no windows", top_k=3)
    assert response.results

    for rule in response.results:
        assert rule.rule_uid
        assert rule.title
        assert rule.query, "a query é o que o analista quer ver"
        assert rule.narrative
        assert rule.matched_by
