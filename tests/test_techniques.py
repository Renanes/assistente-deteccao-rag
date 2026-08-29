"""Testes do inventário de técnicas ATT&CK do acervo.

O risco que estes testes cobrem é o de erro silencioso, que é onde o
`CLAUDE.md` (seção 7) pede teste: o catálogo pode anunciar "T1055 — 123 regras"
e o clique devolver 411 sem nada quebrar, sem exceção, sem log. O número
simplesmente estaria errado, e ninguém teria como saber sem conferir à mão.

Por isso o teste central aqui (`test_match_count_is_what_the_filter_returns`) é
uma propriedade, e não um caso: para **toda** técnica do acervo, a contagem que
o catálogo exibe tem que ser exatamente a quantidade de regras que casam o
filtro. Roda sem Postgres, sobre o mesmo rollup que a API usa.
"""

from __future__ import annotations

import json

import pytest

from src.retrieval.search import SearchFilters, _filter_sql
from src.retrieval.techniques import (
    ATTACK_NAMES_PATH,
    build_inventory,
    expand_technique,
    is_subtechnique,
    load_attack_names,
    matches_technique,
    parent_of,
)

# Um acervo de brinquedo que reproduz todas as formas que importam:
#   - regra com técnica-pai e subtécnica ao mesmo tempo (r1) — o caso que faria
#     uma contagem ingênua contar a mesma regra duas vezes na família;
#   - família sem o pai declarado por ninguém (T2000, só via T2000.001);
#   - regra com duas famílias distintas (r5);
#   - regras sem técnica nenhuma (r6, r7).
CORPUS: list[tuple[str, list[str]]] = [
    ("r1", ["T1055", "T1055.001"]),
    ("r2", ["T1055.001"]),
    ("r3", ["T1055"]),
    ("r4", ["T2000.001"]),
    ("r5", ["T2000.001", "T1055.002"]),
    ("r6", []),
    ("r7", []),
]

NAMES = {
    "T1055": {"name": "Process Injection", "domain": "enterprise"},
    "T1055.001": {"name": "Dynamic-link Library Injection", "domain": "enterprise"},
    "T1055.002": {"name": "Portable Executable Injection", "domain": "enterprise"},
    "T2000": {"name": "Técnica de Teste", "domain": "enterprise"},
    "T2000.001": {"name": "Subtécnica de Teste", "domain": "enterprise"},
}


@pytest.fixture
def inventory():
    return build_inventory(CORPUS, names=NAMES)


def _todas_entradas(inventory):
    for family in inventory.families:
        yield family.parent
        yield from family.subtechniques


# --------------------------------------------------------------- expansão


def test_expand_is_bidirectional() -> None:
    """Pai casa subtécnicas; subtécnica casa também o pai."""
    exact, prefixes = expand_technique("T1055")
    assert exact == ["T1055"] and prefixes == ["T1055.%"]

    exact, prefixes = expand_technique("T1218.011")
    assert set(exact) == {"T1218.011", "T1218"} and prefixes == []


def test_filter_sql_uses_the_shared_expansion() -> None:
    """O WHERE do filtro e a contagem do catálogo saem da mesma função.

    Se `_filter_sql` voltar a expandir por conta própria, o catálogo passa a
    anunciar um número e o clique a devolver outro — sem erro nenhum.
    """
    _, params = _filter_sql(SearchFilters(mitre_techniques=("T1055", "T1218.011")))
    assert set(params["mitre_exact"]) == {"T1055", "T1218", "T1218.011"}
    assert params["mitre_prefixes"] == ["T1055.%"]


def test_empty_prefix_list_never_becomes_a_wildcard() -> None:
    """Um filtro que deixa passar o corpus inteiro é o erro clássico aqui."""
    _, params = _filter_sql(SearchFilters(mitre_techniques=("T1218.011",)))
    assert params["mitre_prefixes"] == [""]
    assert "%" not in params["mitre_prefixes"][0]


# ------------------------------------------- faceta "Sem técnica declarada"


def test_untagged_facet_is_a_filter_not_an_absence() -> None:
    """Marcar só a faceta tem que restringir, não virar busca sem filtro.

    `is_empty` governa o relaxamento: se ele dissesse "vazio" aqui, a busca
    seguiria sem filtro nenhum e devolveria o acervo inteiro, silenciosamente.
    """
    filtros = SearchFilters(include_untagged=True)
    assert filtros.is_empty is False

    where, _ = _filter_sql(filtros)
    assert where == "cardinality(mitre_techniques) = 0"


def test_untagged_combined_with_a_technique_is_a_union() -> None:
    """"T1055 **ou** sem técnica" — a interseção seria sempre vazia.

    Uma regra não pode ao mesmo tempo declarar T1055 e não declarar nada, então
    combinar por AND devolveria zero resultado para toda seleção do tipo.
    """
    where, params = _filter_sql(
        SearchFilters(mitre_techniques=("T1055",), include_untagged=True)
    )
    assert " OR cardinality(mitre_techniques) = 0)" in where
    assert " AND cardinality" not in where
    assert params["mitre_exact"] == ["T1055"]


def test_untagged_off_leaves_the_where_untouched() -> None:
    """A faceta desligada não pode alterar o caminho que já existia."""
    com, params_com = _filter_sql(SearchFilters(mitre_techniques=("T1055",)))
    assert "cardinality" not in com
    assert params_com["mitre_exact"] == ["T1055"]
    assert _filter_sql(SearchFilters())[0] == "TRUE"


# ----------------------------------------------------------- rollup básico


def test_untagged_rules_are_counted_not_dropped(inventory) -> None:
    """As regras sem técnica são a faceta — precisam existir como número."""
    assert inventory.untagged_count == 2
    assert inventory.tagged_count == 5
    assert inventory.total_rules == 7


def test_untagged_rules_never_appear_as_a_technique(inventory) -> None:
    ids = {entry.id for entry in _todas_entradas(inventory)}
    assert "" not in ids and "__sem__" not in ids
    assert all(entry.id.startswith("T") for entry in _todas_entradas(inventory))


def test_family_count_does_not_double_count_a_rule(inventory) -> None:
    """r1 declara `T1055` **e** `T1055.001`; ainda é uma regra só na família.

    Somar as contagens das subtécnicas com a do pai daria 5 para uma família
    que tem 4 regras distintas. É o erro que o rollup existe para não cometer.
    """
    familia = next(f for f in inventory.families if f.parent.id == "T1055")
    assert familia.rule_count == 4  # r1, r2, r3, r5
    soma_ingenua = familia.parent.rule_count + sum(s.rule_count for s in familia.subtechniques)
    assert soma_ingenua == 5, "a soma ingênua infla — é exatamente o que não fazemos"


def test_parent_only_family_is_listed_and_flagged(inventory) -> None:
    """`T2000` não é declarada por regra nenhuma, mas o filtro por ela funciona."""
    familia = next(f for f in inventory.families if f.parent.id == "T2000")
    assert familia.parent_declared is False
    assert familia.parent.rule_count == 0
    assert familia.parent.match_count == 2  # r4 e r5, via T2000.001
    assert familia.rule_count == 2


def test_families_are_ordered_by_volume_then_id(inventory) -> None:
    """Ordem estável: sem o desempate por ID o teste de contrato oscilaria."""
    chaves = [(-f.rule_count, f.parent.id) for f in inventory.families]
    assert chaves == sorted(chaves)


# ------------------------------------------------- a propriedade central


def test_match_count_is_what_the_filter_returns(inventory) -> None:
    """Para toda técnica: o número exibido == regras que o filtro devolve.

    Esta é a invariante que dá sentido ao catálogo. Foi conferida também contra
    o Postgres real, sobre as 473 técnicas do acervo e as 5.664 regras, com zero
    divergência; aqui ela fica travada sem depender de banco.
    """
    divergentes = []
    for entry in _todas_entradas(inventory):
        esperado = sum(
            1 for _, declared in CORPUS if declared and matches_technique(declared, entry.id)
        )
        if entry.match_count != esperado:
            divergentes.append((entry.id, entry.match_count, esperado))

    assert not divergentes, f"catálogo diverge do filtro: {divergentes}"


def test_subtechnique_match_includes_rules_tagged_only_with_the_parent(inventory) -> None:
    """O caso concreto que a propriedade acima generaliza.

    `T1055.002` é declarada só por r5. Mas o filtro por ela também devolve r1 e
    r3, marcadas com o pai `T1055` — então exibir "1" seria mentir sobre o que
    o clique faz.
    """
    entry = next(e for e in _todas_entradas(inventory) if e.id == "T1055.002")
    assert entry.rule_count == 1
    assert entry.match_count == 3


def test_matches_technique_does_not_match_a_sibling() -> None:
    """`T1055.001` não pode casar `T1055.002` — famílias irmãs são distintas."""
    assert not matches_technique(["T1055.002"], "T1055.001")
    assert not matches_technique(["T10550"], "T1055")


# ------------------------------------------------ estado no ATT&CK real


def test_attack_names_file_is_committed_and_parses() -> None:
    """O mapa é dado de referência versionado, não artefato derivado.

    Sem ele o catálogo degrada para IDs nus — funciona, mas ilegível. O arquivo
    fica fora de `data/raw/` e `data/normalized/`, que são gitignored.
    """
    assert ATTACK_NAMES_PATH.is_file(), "rode `python -m src.ingestion.attack_names`"
    payload = json.loads(ATTACK_NAMES_PATH.read_text(encoding="utf-8"))
    assert payload["techniques"]["T1055"]["name"] == "Process Injection"
    assert payload["versoes"]["enterprise"].split(".")[0].isdigit()


def test_known_ids_of_the_corpus_resolve_to_names() -> None:
    """Amostra do acervo real: nomes que o catálogo precisa exibir."""
    names = load_attack_names()
    assert names["T1003.001"]["name"] == "LSASS Memory"
    assert names["T1059.001"]["name"] == "PowerShell"
    # T1685 parecia ID inválido pelo volume (276 regras) até o mapa resolver:
    # é a renumeração de T1562 no ATT&CK v19, e T1562 consta como revogada.
    assert names["T1685"]["name"] == "Disable or Modify Tools"
    assert names["T1562"]["revoked"] is True
    assert names["T1562"]["superseded_by"] == "T1685"


def test_status_is_derived_for_revoked_and_unknown_ids() -> None:
    inventory = build_inventory(
        [("a", ["T1562"]), ("b", ["T9999"])],
        names={"T1562": {"name": "Impair Defenses", "revoked": True, "superseded_by": "T1685"}},
    )
    entradas = {entry.id: entry for entry in _todas_entradas(inventory)}

    assert entradas["T1562"].status == "revoked"
    assert entradas["T1562"].superseded_by == "T1685"
    # ID que o ATT&CK não conhece é exposto, não escondido: é achado sobre a
    # qualidade das fontes públicas.
    assert entradas["T9999"].status == "unknown"
    assert inventory.unknown_ids == ["T9999"]
    assert inventory.revoked_ids == ["T1562"]


def test_helpers_agree_on_what_a_subtechnique_is() -> None:
    assert is_subtechnique("T1055.001") and not is_subtechnique("T1055")
    assert parent_of("T1055.001") == "T1055"
    assert parent_of("T1055") == "T1055"
