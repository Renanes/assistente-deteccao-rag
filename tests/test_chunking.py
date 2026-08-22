"""Testes da estratégia de chunking (Fase 2).

As regras vêm dos mesmos parsers e fixtures da Fase 1, e não de objetos
`DetectionRule` montados à mão: um chunk construído sobre uma regra fabricada
testaria o teste, não o corpus. O que interessa aqui é que as peculiaridades
reais de cada fonte (SPL de linha única, YARA-L com bloco `events:`, Sigma com
`logsource` embutido na query) sobrevivam ao chunking.

A exceção é `test_context_line_without_platform_or_technique`: nenhuma fixture
cai nesse caso, porque o parser do Sigma tem fallback de plataforma pelo
caminho do arquivo. Como 181 regras do corpus real ficam sem plataforma e 458
sem técnica, o caso é montado explicitamente — ali o alvo é a função de
contexto, não o parser.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.chunking.chunk import (
    MAX_CONTEXT_DATA_SOURCE_CHARS,
    MAX_QUERY_CHARS,
    TRUNCATION_MARKER,
    build_context_line,
    build_embedding_text,
    chunk_rule,
    select_context_data_sources,
    truncate_query,
)
from src.chunking.run import build_chunks
from src.ingestion.escu import parse_escu_rule
from src.ingestion.schema import DetectionRule, QueryLanguage, RuleSource
from src.ingestion.sigma import parse_sigma_rule
from src.ingestion.yaral import parse_yaral_rule

FIXTURES = Path(__file__).parent / "fixtures"

# Um marcador de sintaxe característico da linguagem de cada fonte. Se algum
# deles aparecer no texto embeddado, a query vazou para o vetor.
SYNTAX_MARKERS: dict[RuleSource, str] = {
    RuleSource.SIGMA: "condition:",
    RuleSource.SPLUNK_ESCU: "tstats",
    RuleSource.YARA_L: "events:",
}


@pytest.fixture
def sigma_rule() -> DetectionRule:
    repo = FIXTURES / "sigma"
    rule = parse_sigma_rule(repo / "rules" / "windows" / "process_creation" / "7zip_dump.yml", repo)
    assert rule is not None
    return rule


@pytest.fixture
def escu_rule() -> DetectionRule:
    repo = FIXTURES / "splunk_escu"
    rule = parse_escu_rule(repo / "detections" / "endpoint" / "7zip_smb.yml", repo)
    assert rule is not None
    return rule


@pytest.fixture
def yaral_rule() -> DetectionRule:
    repo = FIXTURES / "chronicle_yara_l"
    rule = parse_yaral_rule(repo / "rules" / "community" / "geoip_login.yaral", repo)
    assert rule is not None
    return rule


@pytest.fixture
def all_rules(
    sigma_rule: DetectionRule, escu_rule: DetectionRule, yaral_rule: DetectionRule
) -> list[DetectionRule]:
    return [sigma_rule, escu_rule, yaral_rule]


# --------------------------------------------------------------------------
# A invariante central: a query não entra no vetor, mas é preservada
# --------------------------------------------------------------------------


def test_embedding_text_never_contains_the_query(all_rules: list[DetectionRule]) -> None:
    """Premissa da fase inteira, verificada nas 3 fontes de uma vez.

    Se sintaxe de busca vazar para o texto embeddado, o vetor passa a responder
    a tokens que nenhum analista digita numa pergunta.
    """
    for rule in all_rules:
        text = build_embedding_text(rule)
        assert rule.query not in text
        # A primeira linha da query é o que mais denuncia vazamento parcial.
        assert rule.query.strip().splitlines()[0] not in text
        marker = SYNTAX_MARKERS[rule.source]
        assert marker in rule.query, f"fixture de {rule.source.value} perdeu {marker!r}"
        assert marker not in text, f"{marker!r} vazou para o vetor em {rule.rule_uid}"


def test_query_is_preserved_verbatim(all_rules: list[DetectionRule]) -> None:
    """O analista quer ver a regra como ela é escrita na fonte, não parafraseada."""
    for rule in all_rules:
        (chunk,) = chunk_rule(rule)
        assert chunk.query == rule.query
        assert chunk.query_truncated is False


def test_embedding_text_contains_the_narrative(all_rules: list[DetectionRule]) -> None:
    for rule in all_rules:
        text = build_embedding_text(rule)
        assert rule.title in text
        assert rule.narrative_text in text


# --------------------------------------------------------------------------
# Granularidade: um chunk por regra
# --------------------------------------------------------------------------


def test_one_chunk_per_rule(all_rules: list[DetectionRule]) -> None:
    for rule in all_rules:
        chunks = chunk_rule(rule)
        assert len(chunks) == 1
        assert chunks[0].chunk_index == 0
        assert chunks[0].chunk_total == 1
        assert chunks[0].chunk_uid == chunks[0].rule_uid == rule.rule_uid


# --------------------------------------------------------------------------
# Metadados carregados por valor (filtro da Fase 4, citação da Fase 5)
# --------------------------------------------------------------------------


def test_chunk_carries_citation_fields(sigma_rule: DetectionRule) -> None:
    (chunk,) = chunk_rule(sigma_rule)
    assert chunk.title == sigma_rule.title
    assert chunk.source_url == sigma_rule.source_url
    assert chunk.source is RuleSource.SIGMA
    assert chunk.query_language is QueryLanguage.SIGMA


def test_chunk_carries_filter_metadata(all_rules: list[DetectionRule]) -> None:
    for rule in all_rules:
        (chunk,) = chunk_rule(rule)
        assert chunk.platforms == rule.platforms
        assert chunk.mitre_techniques == rule.mitre_techniques
        assert chunk.mitre_tactics == rule.mitre_tactics
        assert chunk.data_sources == rule.data_sources
        assert chunk.severity == rule.severity


def test_metadata_lists_are_copies_not_shared_references(sigma_rule: DetectionRule) -> None:
    """Mutar o chunk não pode alterar a regra de origem, nem o contrário."""
    (chunk,) = chunk_rule(sigma_rule)
    chunk.platforms.append("plataforma_inventada")
    assert "plataforma_inventada" not in sigma_rule.platforms


# --------------------------------------------------------------------------
# Linha de contexto
# --------------------------------------------------------------------------


def test_context_line_names_source_platform_and_technique(sigma_rule: DetectionRule) -> None:
    line = build_context_line(sigma_rule)
    assert line.startswith("Regra Sigma para windows.")
    assert "T1560.001" in line


def test_context_line_puts_technique_in_the_embedded_text(escu_rule: DetectionRule) -> None:
    """A técnica precisa estar no vetor, não só na coluna de metadado.

    O filtro da Fase 4 cobre a busca por termo exato; isto cobre o caso em que o
    analista descreve a técnica sem citar o ID.
    """
    assert escu_rule.mitre_techniques
    text = build_embedding_text(escu_rule)
    for technique in escu_rule.mitre_techniques:
        assert technique in text


def test_context_line_lists_every_platform(yaral_rule: DetectionRule) -> None:
    """Regra multiplataforma não pode perder plataforma na linha de contexto."""
    assert yaral_rule.platforms == ["azure", "okta"]
    assert build_context_line(yaral_rule).startswith("Regra YARA-L para azure, okta.")


def test_context_line_without_platform_or_technique() -> None:
    """181 regras do corpus não têm plataforma e 458 não têm técnica.

    Nenhuma fixture cai nesse caso (o parser do Sigma infere a plataforma pelo
    caminho), então a regra é montada aqui. Sem plataforma o chunk continua
    indexável — só deixa de ser filtrável por ela — e a frase não pode sair
    quebrada ("Regra Sigma para .").
    """
    rule = DetectionRule(
        rule_uid="sigma:sem-metadado",
        source=RuleSource.SIGMA,
        native_id="sem-metadado",
        source_path="rules/generic/sem_metadado.yml",
        title="Suspicious Activity",
        description="Detecta atividade suspeita genérica.",
        query="detection:\n  condition: selection",
        query_language=QueryLanguage.SIGMA,
    )

    line = build_context_line(rule)
    assert line == "Regra Sigma."
    assert " para ." not in line

    text = build_embedding_text(rule)
    assert text.startswith("Regra Sigma.")
    assert "Suspicious Activity" in text


def test_context_line_labels_each_source_in_prose(all_rules: list[DetectionRule]) -> None:
    """O rótulo é texto para embeddar, não o valor do enum."""
    lines = [build_context_line(rule) for rule in all_rules]
    assert lines[0].startswith("Regra Sigma")
    assert lines[1].startswith("Regra Splunk ESCU")
    assert lines[2].startswith("Regra YARA-L")
    for line in lines:
        assert "splunk_escu" not in line
        assert "yara_l" not in line


# --------------------------------------------------------------------------
# Seleção de fontes de dado para o texto embeddado
# --------------------------------------------------------------------------


def test_real_data_sources_survive_the_filter() -> None:
    """As fontes de dado de verdade são curtas — nenhuma pode ser descartada."""
    real = [
        "Sysmon EventID 1",
        "Windows Event Log Security 4688",
        "CrowdStrike ProcessRollup2",
        "category: process_creation",
        "product: windows",
    ]
    assert select_context_data_sources(real) == real


def test_sigma_definition_is_dropped_regardless_of_length() -> None:
    """390 regras do corpus carregam `logsource.definition` — nota, não fonte.

    O filtro é por prefixo e não por tamanho de propósito: o campo é livre e o
    conteúdo vai de um parágrafo de requisito a um GUID solto. Um teto de
    caracteres deixaria o GUID passar, e GUID no texto embeddado é ruído puro.
    """
    long_definition = (
        'definition: Requirements: "Advance" log level is required to receive '
        "these audit events."
    )
    short_definition = "definition: dfd8c0f4-e6ad-4e07-b91b-f2fca0ddef64."
    assert len(long_definition) > MAX_CONTEXT_DATA_SOURCE_CHARS
    assert len(short_definition) <= MAX_CONTEXT_DATA_SOURCE_CHARS

    selected = select_context_data_sources(
        ["Sysmon EventID 1", long_definition, short_definition]
    )
    assert selected == ["Sysmon EventID 1"]


def test_context_line_does_not_end_in_a_double_period() -> None:
    rule = DetectionRule(
        rule_uid="sigma:ponto-duplo",
        source=RuleSource.SIGMA,
        native_id="ponto-duplo",
        source_path="rules/generic/ponto_duplo.yml",
        title="Alguma Regra",
        description="Descrição.",
        query="detection:\n  condition: selection",
        query_language=QueryLanguage.SIGMA,
        data_sources=["Sysmon EventID 1."],
    )

    line = build_context_line(rule)
    assert line.endswith("Fontes de dados: Sysmon EventID 1.")
    assert not line.endswith("..")


def test_data_source_filter_can_empty_the_sentence() -> None:
    """Se sobrar nada, a frase inteira some — não fica 'Fontes de dados: .'."""
    assert select_context_data_sources(["x" * 200]) == []

    rule = DetectionRule(
        rule_uid="sigma:so-prosa",
        source=RuleSource.SIGMA,
        native_id="so-prosa",
        source_path="rules/generic/so_prosa.yml",
        title="Alguma Regra",
        description="Descrição.",
        query="detection:\n  condition: selection",
        query_language=QueryLanguage.SIGMA,
        platforms=["windows"],
        data_sources=["y" * 200],
    )
    assert build_context_line(rule) == "Regra Sigma para windows."


# --------------------------------------------------------------------------
# Truncamento da query
# --------------------------------------------------------------------------


def test_short_query_is_untouched() -> None:
    query = "index=main | stats count by host"
    assert truncate_query(query) == (query, False)


def test_query_at_the_limit_is_untouched() -> None:
    query = "x" * MAX_QUERY_CHARS
    assert truncate_query(query) == (query, False)


def test_long_query_is_cut_on_a_line_boundary() -> None:
    """Meia condição é pior que nenhuma: parece completa e engana quem lê."""
    body = "\n".join(f"    campo_{i} = 'valor_{i}'" for i in range(400))
    truncated, was_truncated = truncate_query(body, max_chars=1000)

    assert was_truncated is True
    assert truncated.endswith(TRUNCATION_MARKER)

    logic = truncated.removesuffix(TRUNCATION_MARKER).rstrip()
    # O corte caiu numa fronteira de linha real, e o prefixo é fiel ao original.
    assert body.startswith(logic)
    assert logic.splitlines()[-1] in body.splitlines()


def test_single_line_query_is_cut_hard_at_the_limit() -> None:
    """SPL costuma vir em uma linha só — não há quebra em que se apoiar."""
    query = "index=main " + "| eval x=1 " * 2000
    truncated, was_truncated = truncate_query(query, max_chars=500)

    assert was_truncated is True
    assert truncated.startswith("index=main")
    assert truncated.endswith(TRUNCATION_MARKER)
    assert len(truncated) < 500 + len(TRUNCATION_MARKER) + 2


def test_truncation_flag_reaches_the_chunk(sigma_rule: DetectionRule) -> None:
    """A Fase 5 precisa saber que cortou, para remeter o analista à fonte."""
    (chunk,) = chunk_rule(sigma_rule, max_query_chars=50)
    assert chunk.query_truncated is True
    assert chunk.query.endswith(TRUNCATION_MARKER)
    # Truncar a query não pode mexer no que é embeddado.
    assert chunk.embedding_text == build_embedding_text(sigma_rule)


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------


def test_build_chunks_counts_per_source_and_truncations(all_rules: list[DetectionRule]) -> None:
    chunks, stats = build_chunks(iter(all_rules), max_query_chars=50)

    assert len(chunks) == 3
    assert stats["chunks_sigma"] == 1
    assert stats["chunks_splunk_escu"] == 1
    assert stats["chunks_yara_l"] == 1
    assert stats["queries_truncadas"] == 3


def test_build_chunks_reports_no_truncation_by_default(all_rules: list[DetectionRule]) -> None:
    _, stats = build_chunks(iter(all_rules))
    assert stats["queries_truncadas"] == 0
