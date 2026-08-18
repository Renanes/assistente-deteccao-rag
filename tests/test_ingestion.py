"""Testes da camada de ingestão (Fase 1).

Os parsers rodam sobre fixtures fixas, não sobre os repositórios clonados: os
clones são gitignored e mudam a cada `git pull` upstream, então um teste que
dependesse deles quebraria por motivo alheio ao código. As fixtures são
recortes reais de cada fonte, preservando as peculiaridades que o parser
precisa tratar.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.escu import parse_escu_rule
from src.ingestion.normalize import (
    PLATFORM_VOCABULARY,
    extract_mitre_tactics,
    extract_mitre_techniques,
    infer_platforms,
    normalize_platform,
    normalize_severity,
)
from src.ingestion.schema import DetectionRule, QueryLanguage, RuleSource, Severity
from src.ingestion.yaral import parse_yaral_rule

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------
# Sigma
# --------------------------------------------------------------------------


@pytest.fixture
def sigma_rule() -> DetectionRule:
    from src.ingestion.sigma import parse_sigma_rule

    repo = FIXTURES / "sigma"
    rule = parse_sigma_rule(repo / "rules" / "windows" / "process_creation" / "7zip_dump.yml", repo)
    assert rule is not None
    return rule


def test_sigma_identity_and_provenance(sigma_rule: DetectionRule) -> None:
    assert sigma_rule.source is RuleSource.SIGMA
    assert sigma_rule.rule_uid == "sigma:ec570e53-4c76-45a9-804d-dc3f355ff7a7"
    assert sigma_rule.source_path == "rules/windows/process_creation/7zip_dump.yml"
    # O link é o que a resposta do RAG cita — precisa apontar para o arquivo real.
    assert sigma_rule.source_url is not None
    assert sigma_rule.source_url.endswith(sigma_rule.source_path)


def test_sigma_narrative_and_query_are_separated(sigma_rule: DetectionRule) -> None:
    """A query não pode vazar para os campos narrativos (premissa da Fase 2)."""
    assert sigma_rule.title == "7Zip Compressing Dump Files"
    assert "dump file exfiltration" in sigma_rule.description
    assert "condition" not in sigma_rule.narrative_text
    # A lógica precisa estar preservada inteira para citação.
    assert "condition: all of selection_*" in sigma_rule.query
    assert "\\7z.exe" in sigma_rule.query
    assert sigma_rule.query_language is QueryLanguage.SIGMA


def test_sigma_metadata(sigma_rule: DetectionRule) -> None:
    # Tag `attack.t1560.001` precisa virar o ID canônico em maiúsculas.
    assert sigma_rule.mitre_techniques == ["T1560.001"]
    assert sigma_rule.mitre_tactics == ["Collection"]
    assert sigma_rule.platforms == ["windows"]
    assert sigma_rule.severity is Severity.MEDIUM
    assert len(sigma_rule.false_positives) == 2


def test_sigma_platform_falls_back_to_path() -> None:
    """Regra sem `logsource.product` ainda deve receber plataforma pelo caminho."""
    from src.ingestion.sigma import parse_sigma_rule

    repo = FIXTURES / "sigma"
    rule = parse_sigma_rule(repo / "rules" / "linux" / "no_product.yml", repo)
    assert rule is not None
    assert rule.platforms == ["linux"]


def test_sigma_ignores_non_rule_yaml() -> None:
    from src.ingestion.sigma import parse_sigma_rule

    repo = FIXTURES / "sigma"
    assert parse_sigma_rule(repo / "rules" / "not_a_rule.yml", repo) is None


# --------------------------------------------------------------------------
# Splunk ESCU
# --------------------------------------------------------------------------


@pytest.fixture
def escu_rule() -> DetectionRule:
    repo = FIXTURES / "splunk_escu"
    rule = parse_escu_rule(repo / "detections" / "endpoint" / "7zip_smb.yml", repo)
    assert rule is not None
    return rule


def test_escu_identity_and_query(escu_rule: DetectionRule) -> None:
    assert escu_rule.source is RuleSource.SPLUNK_ESCU
    assert escu_rule.rule_uid == "splunk_escu:01d29b48-ff6f-11eb-b81e-acde48001123"
    assert escu_rule.query_language is QueryLanguage.SPL
    assert escu_rule.query.startswith("| tstats")
    assert "Endpoint.Processes" in escu_rule.query


def test_escu_infers_platform_from_data_source(escu_rule: DetectionRule) -> None:
    """ESCU não declara plataforma — ela sai de `data_source` ("Sysmon EventID 1")."""
    assert "windows" in escu_rule.platforms


def test_escu_metadata(escu_rule: DetectionRule) -> None:
    assert escu_rule.mitre_techniques == ["T1560.001"]
    # `known_false_positives` é frase corrida na fonte; vira item único da lista.
    assert len(escu_rule.false_positives) == 1
    # `analytic_story` é o eixo mais útil para retrieval e precisa virar tag.
    assert "Ransomware" in escu_rule.tags
    assert "type: Hunting" in escu_rule.tags
    # ESCU não tem severidade por detecção — não inventar uma a partir de `type`.
    assert escu_rule.severity is None


def test_escu_ignores_yaml_without_search() -> None:
    repo = FIXTURES / "splunk_escu"
    assert parse_escu_rule(repo / "detections" / "not_a_detection.yml", repo) is None


# --------------------------------------------------------------------------
# YARA-L (parser textual próprio — maior superfície de erro)
# --------------------------------------------------------------------------


@pytest.fixture
def yaral_rule() -> DetectionRule:
    repo = FIXTURES / "chronicle_yara_l"
    rule = parse_yaral_rule(repo / "rules" / "community" / "geoip_login.yaral", repo)
    assert rule is not None
    return rule


def test_yaral_identity_prefers_meta_rule_id(yaral_rule: DetectionRule) -> None:
    assert yaral_rule.source is RuleSource.YARA_L
    assert yaral_rule.rule_uid == "yara_l:mr_3fa832e4-1ac0-42cd-9f0a-357d6b8fb12f"
    # `rule_name` do meta é o título legível, não o identificador snake_case.
    assert yaral_rule.title == "GeoIP User Login From Multiple States Or Countries"


def test_yaral_logic_excludes_license_and_meta(yaral_rule: DetectionRule) -> None:
    """A query começa em `events:` — cabeçalho de licença e meta ficam fora.

    Repetir o bloco de licença em cada regra gastaria contexto do prompt da
    Fase 5 sem acrescentar informação nenhuma.
    """
    assert "Apache License" not in yaral_rule.query
    assert 'author = "Google Cloud Security"' not in yaral_rule.query
    assert yaral_rule.query.lstrip().startswith("events:")
    assert "condition:" in yaral_rule.query
    # A chave de fechamento da regra é removida (não há a de abertura).
    assert not yaral_rule.query.rstrip().endswith("}")


def test_yaral_metadata(yaral_rule: DetectionRule) -> None:
    assert yaral_rule.severity is Severity.LOW
    assert yaral_rule.description.startswith("Detect multiple user logins")
    assert "geoip enrichment" in yaral_rule.tags


def test_yaral_handles_brace_on_next_line_and_missing_rule_id() -> None:
    """66 regras do repositório abrem com `{` na linha seguinte e sem `rule_id`.

    Nesses casos o identificador do arquivo é o fallback de ID, e o título sai
    do snake_case.
    """
    repo = FIXTURES / "chronicle_yara_l"
    rule = parse_yaral_rule(repo / "rules" / "community" / "legacy_style.yaral", repo)
    assert rule is not None
    assert rule.rule_uid == "yara_l:info_certutil_urlcache"
    assert rule.title == "Info Certutil Urlcache"
    # `mitre = "credential_access, t1003"` — ID solto no meio de texto livre.
    assert rule.mitre_techniques == ["T1003"]
    assert rule.platforms == ["windows"]


def test_yaral_collects_repeated_meta_keys() -> None:
    """`reference` se repete legitimamente na mesma regra — nenhuma pode sumir."""
    repo = FIXTURES / "chronicle_yara_l"
    rule = parse_yaral_rule(repo / "rules" / "community" / "legacy_style.yaral", repo)
    assert rule is not None
    assert len(rule.references) == 2


def test_yaral_ignores_file_without_rule_header() -> None:
    repo = FIXTURES / "chronicle_yara_l"
    assert parse_yaral_rule(repo / "rules" / "community" / "not_a_rule.yaral", repo) is None


# --------------------------------------------------------------------------
# Normalização compartilhada
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Windows", "windows"),
        ("azure_ad", "azure"),
        ("o365", "m365"),
        ("k8s", "kubernetes"),
        # Bitbucket não pode colapsar em GitHub: são filtros distintos.
        ("bitbucket", "bitbucket"),
        ("", None),
        ("plataforma_inexistente", None),
    ],
)
def test_normalize_platform(raw: str, expected: str | None) -> None:
    assert normalize_platform(raw) == expected


def test_every_normalized_platform_is_in_the_vocabulary() -> None:
    """Guarda contra metadado que nenhum filtro da Fase 4 conseguiria casar."""
    candidates = ["windows", "azure_ad", "o365", "bitbucket", "sap", "zeek", "k8s"]
    for candidate in candidates:
        normalized = normalize_platform(candidate)
        assert normalized in PLATFORM_VOCABULARY, candidate


def test_extract_mitre_techniques_canonicalizes_and_dedupes() -> None:
    texts = ["attack.t1055.001", "T1055.001", "see T1003 and TA0004", "no ids here"]
    assert extract_mitre_techniques(texts) == ["T1055.001", "T1003"]


def test_extract_mitre_tactics() -> None:
    assert extract_mitre_tactics(["tactic = TA0004", "TA0004", "T1055"]) == ["TA0004"]


def test_infer_platforms_from_free_text_telemetry() -> None:
    assert "windows" in infer_platforms(["Sysmon EventID 1"])
    assert "aws" in infer_platforms(["ASL AWS CloudTrail"])
    assert infer_platforms(["telemetria desconhecida"]) == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("High", Severity.HIGH), ("info", Severity.INFORMATIONAL), (None, None), ("xyz", None)],
)
def test_normalize_severity(raw: str | None, expected: Severity | None) -> None:
    assert normalize_severity(raw) == expected


def test_narrative_text_omits_the_query() -> None:
    """Contrato central da Fase 2: o que é embedado nunca inclui a query bruta."""
    rule = DetectionRule(
        rule_uid="sigma:x",
        source=RuleSource.SIGMA,
        native_id="x",
        source_path="rules/x.yml",
        title="Título",
        description="Descrição.",
        false_positives=["Uso legítimo."],
        query="detection:\n  selection:\n    Image|endswith: '\\evil.exe'",
        query_language=QueryLanguage.SIGMA,
    )
    narrative = rule.narrative_text
    assert "Título" in narrative
    assert "Descrição." in narrative
    assert "Uso legítimo." in narrative
    assert "evil.exe" not in narrative
