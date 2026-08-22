"""Testes do pipeline RAG (Fase 5).

O critério de aceite da fase — "a resposta sempre referencia a fonte real
recuperada, nunca texto fora do contexto" — não é verificável só com prompt.
A maior parte destes testes é sobre a *verificação* dessa propriedade:
`check_citations` é o que transforma "pedimos para citar certo" em "sabemos se
citou", e é ele que precisa estar correto.

Os testes unitários usam um LLM e um retriever falsos, então rodam sem API e
sem banco. Isso permite exercitar caminhos que uma chamada real quase nunca
produziria — uma resposta citando `[9]` com 2 regras no contexto, por exemplo.
"""

from __future__ import annotations

import pytest

from src.providers.base import Generation, LLMProvider
from src.rag.pipeline import NO_RULES_ANSWER, RagPipeline, check_citations
from src.rag.prompt import SYSTEM_PROMPT, build_context, build_prompt, format_rule
from src.retrieval.search import RetrievedRule, SearchFilters, SearchResponse


def make_rule(index: int = 1, **overrides: object) -> RetrievedRule:
    defaults: dict[str, object] = {
        "chunk_uid": f"sigma:regra-{index}",
        "rule_uid": f"sigma:regra-{index}",
        "title": f"Regra de Teste {index}",
        "source": "sigma",
        "source_url": f"https://github.com/SigmaHQ/sigma/blob/master/rules/r{index}.yml",
        "narrative": f"Descrição da regra {index}.",
        "query": "detection:\n  condition: selection",
        "query_language": "sigma",
        "query_truncated": False,
        "platforms": ["windows"],
        "mitre_techniques": ["T1055"],
        "severity": "high",
        "score": 0.03,
        "matched_by": ["vetorial"],
    }
    defaults.update(overrides)
    return RetrievedRule(**defaults)  # type: ignore[arg-type]


class FakeLLM(LLMProvider):
    """LLM controlável: devolve o texto que o teste mandar."""

    name = "fake"
    model = "fake-model"

    def __init__(self, text: str = "Resposta [1].", truncated: bool = False) -> None:
        self.text = text
        self.truncated = truncated
        self.calls: list[tuple[str, str, int]] = []

    def generate(self, system: str, prompt: str, max_tokens: int = 2048) -> Generation:
        self.calls.append((system, prompt, max_tokens))
        return Generation(
            text=self.text,
            truncated=self.truncated,
            stop_reason="max_tokens" if self.truncated else "end_turn",
        )


class FakeRetriever:
    """Retriever controlável, com a mesma assinatura de `HybridRetriever.search`."""

    def __init__(self, response: SearchResponse) -> None:
        self.response = response

    def search(self, question, top_k=5, filters=None, rrf_k=60):  # type: ignore[no-untyped-def]
        return self.response


# --------------------------------------------------------------------------
# Verificação de citações — o núcleo da fase
# --------------------------------------------------------------------------


def test_valid_citations_are_collected_in_order() -> None:
    check = check_citations("Ver [2] e também [1].", rule_count=3)
    assert check.cited == (1, 2)
    assert check.invalid == ()
    assert check.is_grounded


def test_citation_out_of_range_is_flagged() -> None:
    """O caso que o prompt não consegue impedir sozinho.

    Nada no prompt impede o modelo de escrever [9] com 2 regras no contexto.
    Se isto passar despercebido, a resposta cita uma fonte que não existe — o
    oposto exato do que a fase promete.
    """
    check = check_citations("Segundo [1] e [9], ...", rule_count=2)
    assert check.cited == (1,)
    assert check.invalid == (9,)
    assert not check.is_grounded


def test_citation_zero_is_invalid() -> None:
    """Índices são 1-indexados; [0] apontaria para o fim da lista em Python."""
    check = check_citations("Ver [0].", rule_count=3)
    assert check.invalid == (0,)
    assert check.cited == ()


def test_answer_without_any_citation_is_flagged() -> None:
    check = check_citations("Existem regras para isso.", rule_count=3)
    assert check.uncited is True
    assert not check.is_grounded


def test_no_rules_in_context_means_nothing_to_cite() -> None:
    """Sem contexto, não citar é o comportamento correto e não um defeito."""
    check = check_citations(NO_RULES_ANSWER, rule_count=0)
    assert check.uncited is False
    assert check.is_grounded


def test_repeated_citations_are_deduplicated() -> None:
    check = check_citations("[1] disse isso, e [1] também aquilo.", rule_count=2)
    assert check.cited == (1,)


def test_bracketed_numbers_that_are_not_citations_still_count() -> None:
    """Documenta uma limitação conhecida, em vez de fingir que não existe.

    Um `[0x40]` numa query citada não vira número; mas um `[10]` literal dentro
    de um trecho de log seria contado como citação. É aceitável: o efeito é um
    falso alarme de citação inválida, que erra para o lado seguro — avisa
    demais, nunca de menos.
    """
    check = check_citations("O evento tem campo [10] no log.", rule_count=3)
    assert check.invalid == (10,)


# --------------------------------------------------------------------------
# Montagem do prompt
# --------------------------------------------------------------------------


def test_rules_are_numbered_from_one() -> None:
    context = build_context([make_rule(1), make_rule(2)])
    assert "[1] Regra de Teste 1" in context
    assert "[2] Regra de Teste 2" in context


def test_rule_block_carries_everything_needed_to_cite() -> None:
    rule = make_rule(1)
    block = format_rule(rule, 1)
    assert rule.rule_uid in block
    assert rule.source_url in block
    assert rule.narrative in block
    assert "condition: selection" in block
    assert "T1055" in block


def test_truncated_query_is_marked_in_the_context() -> None:
    """O modelo precisa saber para não afirmar o que a query faz por inteiro."""
    block = format_rule(make_rule(1, query_truncated=True), 1)
    assert "TRUNCADA" in block


def test_untruncated_query_carries_no_warning() -> None:
    assert "TRUNCADA" not in format_rule(make_rule(1), 1)


def test_relaxed_filter_warning_comes_before_the_context() -> None:
    """Ordem importa: descobrir depois de ler 5 regras plausíveis é tarde demais."""
    response = SearchResponse(
        results=[make_rule(1)],
        filters=SearchFilters(mitre_techniques=("T9999",)),
        relaxed_filters=True,
    )
    prompt = build_prompt("tem regra pra T9999?", response)

    assert "AVISO IMPORTANTE" in prompt
    assert prompt.index("AVISO IMPORTANTE") < prompt.index("[1] Regra de Teste 1")
    assert "T9999" in prompt


def test_no_warning_when_filters_were_honored() -> None:
    response = SearchResponse(results=[make_rule(1)], relaxed_filters=False)
    assert "AVISO IMPORTANTE" not in build_prompt("qualquer coisa", response)


def test_prompt_contains_the_question() -> None:
    response = SearchResponse(results=[make_rule(1)])
    assert "como detectar X?" in build_prompt("como detectar X?", response)


def test_system_prompt_states_the_grounding_rules() -> None:
    """Trava o contrato do prompt contra edição descuidada."""
    assert "SOMENTE" in SYSTEM_PROMPT
    assert "colchetes" in SYSTEM_PROMPT
    assert "truncada" in SYSTEM_PROMPT


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------


def test_pipeline_maps_citations_to_the_real_rules() -> None:
    rules = [make_rule(1), make_rule(2), make_rule(3)]
    llm = FakeLLM("Use a [3] e a [1].")
    pipeline = RagPipeline(FakeRetriever(SearchResponse(results=rules)), llm)  # type: ignore[arg-type]

    result = pipeline.answer("pergunta")

    assert [rule.rule_uid for rule in result.citations] == [
        "sigma:regra-1",
        "sigma:regra-3",
    ]
    assert len(result.retrieved) == 3
    assert result.citation_check.is_grounded


def test_pipeline_does_not_call_the_model_without_context() -> None:
    """Sem regra recuperada, chamar o modelo só abriria espaço para ele inventar."""
    llm = FakeLLM()
    pipeline = RagPipeline(FakeRetriever(SearchResponse(results=[])), llm)  # type: ignore[arg-type]

    result = pipeline.answer("pergunta sem resposta no acervo")

    assert llm.calls == [], "o modelo não deveria ter sido chamado"
    assert result.answered_without_model is True
    assert result.answer == NO_RULES_ANSWER
    assert result.citations == []


def test_pipeline_reports_an_invalid_citation() -> None:
    llm = FakeLLM("Conforme [1] e [7].")
    pipeline = RagPipeline(FakeRetriever(SearchResponse(results=[make_rule(1)])), llm)  # type: ignore[arg-type]

    result = pipeline.answer("pergunta")

    assert result.citation_check.invalid == (7,)
    assert not result.citation_check.is_grounded
    # A citação válida ainda é resolvida — a resposta não é descartada inteira.
    assert len(result.citations) == 1


def test_pipeline_uses_the_provider_stop_reason_for_truncation() -> None:
    """Regressão: a heurística antiga acusava de cortada uma resposta que
    terminava em bloco de código, porque não tinha pontuação final."""
    ends_with_code = "Veja a regra [1]:\n```\ncondition: selection\n```"

    complete = RagPipeline(
        FakeRetriever(SearchResponse(results=[make_rule(1)])),  # type: ignore[arg-type]
        FakeLLM(ends_with_code, truncated=False),
    ).answer("pergunta")
    assert complete.answer_truncated is False
    assert complete.stop_reason == "end_turn"

    cut = RagPipeline(
        FakeRetriever(SearchResponse(results=[make_rule(1)])),  # type: ignore[arg-type]
        FakeLLM(ends_with_code, truncated=True),
    ).answer("pergunta")
    assert cut.answer_truncated is True
    assert cut.stop_reason == "max_tokens"


def test_pipeline_passes_the_system_prompt_and_records_the_provider() -> None:
    llm = FakeLLM()
    pipeline = RagPipeline(FakeRetriever(SearchResponse(results=[make_rule(1)])), llm)  # type: ignore[arg-type]

    result = pipeline.answer("pergunta")

    system, prompt, _ = llm.calls[0]
    assert system == SYSTEM_PROMPT
    assert "Regra de Teste 1" in prompt
    assert result.llm_provider == "fake"
    assert result.llm_model == "fake-model"


# --------------------------------------------------------------------------
# Integração: exige banco indexado e chaves reais dos dois provedores
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rag_environment():  # type: ignore[no-untyped-def]
    from src.embeddings import store
    from src.providers import ProviderError, get_embedding_provider, get_settings

    settings = get_settings()
    try:
        embedding_provider = get_embedding_provider(settings)
    except ProviderError as error:
        pytest.skip(f"sem provedor de embedding: {error}")

    try:
        conn = store.connect(settings.resolved_database_url())
    except Exception as error:  # noqa: BLE001
        pytest.skip(f"sem Postgres disponível: {error}")

    with conn:
        count = conn.execute("SELECT count(*) FROM rule_chunks").fetchone()
        if not count or count[0] == 0:
            pytest.skip("corpus não indexado")
        yield settings, conn, embedding_provider


@pytest.mark.integration
@pytest.mark.parametrize("provider_name", ["anthropic", "openai"])
def test_pipeline_works_with_both_providers(rag_environment, provider_name: str) -> None:  # type: ignore[no-untyped-def]
    """CRITÉRIO DE ACEITE DA FASE 5.

    "Funciona trocando `LLM_PROVIDER` entre `anthropic` e `openai`" — e a
    resposta precisa continuar ancorada nas regras recuperadas nos dois casos.
    """
    from src.providers import ProviderError, get_llm_provider

    settings, conn, embedding_provider = rag_environment
    try:
        llm = get_llm_provider(settings.model_copy(update={"llm_provider": provider_name}))
    except ProviderError as error:
        pytest.skip(f"sem chave para {provider_name}: {error}")

    pipeline = RagPipeline.build(conn, embedding_provider, llm, top_k=3)
    result = pipeline.answer("como detectar injeção de processo no Windows?")

    assert result.llm_provider == provider_name
    assert result.answer.strip()
    assert result.retrieved, "nada recuperado"
    assert result.citation_check.is_grounded, (
        f"citações inválidas: {result.citation_check.invalid}, "
        f"sem citação: {result.citation_check.uncited}"
    )
    # Toda regra citada precisa ser uma das recuperadas — não uma inventada.
    retrieved_uids = {rule.rule_uid for rule in result.retrieved}
    for rule in result.citations:
        assert rule.rule_uid in retrieved_uids
        assert rule.source_url, "citação sem link verificável"
