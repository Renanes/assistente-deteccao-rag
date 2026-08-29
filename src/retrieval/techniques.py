"""Inventário de técnicas ATT&CK do acervo indexado.

Este módulo existe para responder uma pergunta que o pipeline de busca não
responde: *o que o acervo cobre?* Até aqui só dava para descobrir perguntando e
vendo o que voltava, o que faz do corpus uma caixa preta — inclusive para quem
avalia o projeto.

Três decisões sustentam o desenho:

1. **A expansão de técnica é uma função só, compartilhada com o filtro.**
   `expand_technique` é usada tanto por `_filter_sql` (que monta o WHERE) quanto
   pela contagem exibida aqui. Se fossem duas implementações, o catálogo diria
   "T1055 — 123 regras" e clicar devolveria 411, porque o filtro expande para as
   subtécnicas e a contagem não. Um número que não corresponde ao que o clique
   faz é pior que número nenhum.

2. **O rollup é feito em Python, não em SQL.** O SQL faz a parte barata e
   inequívoca (trazer os pares chunk/técnica, ~9 mil linhas); a matemática de
   família, contagem própria e contagem com expansão fica em código testável
   sem banco. É a parte com risco de erro silencioso, que é onde o `CLAUDE.md`
   pede teste.

3. **Agrupamento por família de técnica, não por tática.** Medido antes de
   decidir: a coluna `mitre_tactics` tem 67 valores distintos para as 14 táticas
   reais do ATT&CK — inclui ID de tática cru (`TA0006`), **ID de software**
   (`S0029`), variantes de grafia da mesma tática e um valor único com quatro
   táticas separadas por vírgula. 39% dos chunks não têm tática nenhuma.
   Agrupar por ali produziria uma taxonomia quebrada. A família sai do próprio
   ID (`T1055.001` → `T1055`), não depende de dado externo, e é exatamente o
   eixo que o filtro já expande.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import psycopg
from pydantic import BaseModel, Field

TABLE_NAME = "rule_chunks"

ATTACK_NAMES_PATH = Path(__file__).resolve().parents[2] / "data" / "attack" / "techniques.json"

#: Rótulo da faceta "regras sem técnica declarada". Não é um ID ATT&CK e nunca
#: entra na lista de técnicas — é um valor booleano à parte no filtro. Fica aqui
#: para a API e a interface nomearem a mesma coisa do mesmo jeito.
UNTAGGED_LABEL = "Sem técnica declarada"

TechniqueStatus = Literal["ok", "deprecated", "revoked", "unknown"]


def parent_of(technique_id: str) -> str:
    """`T1055.001` → `T1055`. Um ID sem ponto é o próprio pai."""
    return technique_id.split(".", 1)[0]


def is_subtechnique(technique_id: str) -> bool:
    return "." in technique_id


def expand_technique(technique_id: str) -> tuple[list[str], list[str]]:
    """Traduz uma técnica pedida no conjunto que deve casar.

    Devolve `(ids_exatos, prefixos_like)`. A expansão é bidirecional, e cada
    sentido tem um motivo diferente:

    - **Pai casa as subtécnicas** (`T1055` → `T1055.%`): resolve a limitação
      medida na Fase 3, em que o full-text tokeniza `T1055.001` como termo único
      e `T1055` não o alcança.
    - **Subtécnica casa também o pai** (`T1218.011` → `T1218`): quem pergunta
      por uma subtécnica aceita bem uma regra marcada só com o pai.

    Esta é a única definição da regra no projeto. `_filter_sql` e o inventário
    do acervo chamam esta função para não poderem divergir.
    """
    exact = [technique_id]
    prefixes: list[str] = []
    if is_subtechnique(technique_id):
        exact.append(parent_of(technique_id))
    else:
        prefixes.append(f"{technique_id}.%")
    return exact, prefixes


def matches_technique(declared: list[str] | tuple[str, ...], requested: str) -> bool:
    """Se um chunk que declara `declared` casaria o filtro por `requested`.

    O equivalente em Python do WHERE que `_filter_sql` monta, para o rollup
    contar exatamente o que o filtro devolveria.
    """
    exact, prefixes = expand_technique(requested)
    exact_set = set(exact)
    for technique in declared:
        if technique in exact_set:
            return True
        if any(technique.startswith(prefix[:-1]) for prefix in prefixes):
            return True
    return False


@lru_cache(maxsize=1)
def _load_attack_file() -> dict[str, Any]:
    """Lê o mapa gerado por `python -m src.ingestion.attack_names`.

    Ausência do arquivo não é erro fatal: o catálogo degrada para IDs sem nome,
    que é feio mas funciona. Quem clona o repositório recebe o arquivo
    commitado, então o caminho degradado só aparece se alguém o apagar.
    """
    if not ATTACK_NAMES_PATH.is_file():
        return {"versoes": {}, "techniques": {}}
    return json.loads(ATTACK_NAMES_PATH.read_text(encoding="utf-8"))


def load_attack_names() -> dict[str, dict[str, Any]]:
    """Mapa `T1055` → `{"name": ..., "domain": ..., "deprecated": ...}`."""
    return _load_attack_file().get("techniques", {})


def attack_version() -> str:
    versions = _load_attack_file().get("versoes", {})
    return str(versions.get("enterprise", "desconhecida"))


class TechniqueEntry(BaseModel):
    """Uma técnica presente no acervo, com as duas contagens que importam."""

    id: str
    #: Nome oficial do ATT&CK. `None` quando o ID não consta no mapa.
    name: str | None = None
    status: TechniqueStatus = "ok"
    #: Para técnica revogada, o ID que a substitui no ATT&CK.
    superseded_by: str | None = None
    is_subtechnique: bool = False

    #: Regras que declaram **exatamente** este ID.
    rule_count: int = 0
    #: Regras que o filtro devolve ao selecionar este ID — inclui a expansão
    #: bidirecional. É este o número que o clique honra.
    match_count: int = 0


class TechniqueFamily(BaseModel):
    """Uma técnica-pai e suas subtécnicas presentes no acervo."""

    parent: TechniqueEntry
    subtechniques: list[TechniqueEntry] = Field(default_factory=list)
    #: Regras distintas em qualquer ponto da família. Igual ao `match_count` do
    #: pai por construção, repetido aqui porque é o número que ordena a lista.
    rule_count: int = 0
    #: True quando nenhuma regra declara o ID do pai — a família existe só pelas
    #: subtécnicas. O pai continua listado (o filtro por ele funciona), mas a
    #: interface precisa poder dizer que ninguém o declarou diretamente.
    parent_declared: bool = True


class CorpusTechniques(BaseModel):
    """O inventário completo, como a API o entrega."""

    families: list[TechniqueFamily] = Field(default_factory=list)

    total_rules: int = 0
    #: Regras sem nenhuma técnica declarada — a faceta "Sem técnica".
    untagged_count: int = 0
    #: Regras com pelo menos uma técnica.
    tagged_count: int = 0
    distinct_techniques: int = 0

    attack_version: str = ""
    #: IDs que o acervo usa e o ATT&CK não conhece. Fica exposto de propósito:
    #: é achado sobre a qualidade das fontes, não sujeira a esconder.
    unknown_ids: list[str] = Field(default_factory=list)
    deprecated_ids: list[str] = Field(default_factory=list)
    revoked_ids: list[str] = Field(default_factory=list)


def _entry(technique_id: str, names: dict[str, dict[str, Any]]) -> TechniqueEntry:
    card = names.get(technique_id)
    status: TechniqueStatus = "unknown"
    name = None
    superseded = None
    if card is not None:
        name = card.get("name")
        if card.get("revoked"):
            status = "revoked"
            superseded = card.get("superseded_by")
        elif card.get("deprecated"):
            status = "deprecated"
        else:
            status = "ok"
    return TechniqueEntry(
        id=technique_id,
        name=name,
        status=status,
        superseded_by=superseded,
        is_subtechnique=is_subtechnique(technique_id),
    )


def build_inventory(
    rows: list[tuple[str, list[str]]], names: dict[str, dict[str, Any]] | None = None
) -> CorpusTechniques:
    """Monta o inventário a partir dos pares `(chunk_uid, técnicas)`.

    Separado da consulta ao banco de propósito: é aqui que mora a matemática de
    rollup, e ela precisa ser testável sem Postgres.
    """
    names = load_attack_names() if names is None else names

    total_rules = len(rows)
    untagged_count = sum(1 for _, techniques in rows if not techniques)

    # Contagem própria: quantas regras declaram exatamente cada ID.
    own_counts: dict[str, int] = {}
    for _, techniques in rows:
        for technique in set(techniques):
            own_counts[technique] = own_counts.get(technique, 0) + 1

    # Contagem por família: regras **distintas** em qualquer ponto da família.
    # Somar as subtécnicas daria número inflado — uma regra pode declarar
    # `T1055` e `T1055.001` ao mesmo tempo e seria contada duas vezes.
    family_counts: dict[str, int] = {}
    for _, techniques in rows:
        for family in {parent_of(technique) for technique in techniques}:
            family_counts[family] = family_counts.get(family, 0) + 1

    # Contagem de match por subtécnica: o filtro por `T1055.001` também devolve
    # as regras marcadas só com `T1055`, então a contagem exibida tem que
    # incluí-las — senão o número não corresponde ao que o clique faz.
    #
    # O laço é invertido de propósito. A versão direta — para cada regra, testar
    # cada uma das 286 subtécnicas do acervo — são 1,6 milhão de iterações e
    # levou 604 ms medidos. Aqui cada regra só visita as subtécnicas da família
    # que ela própria declara, o que derruba o custo em uma ordem de grandeza.
    subs_by_parent: dict[str, list[str]] = {}
    for technique_id in own_counts:
        if is_subtechnique(technique_id):
            subs_by_parent.setdefault(parent_of(technique_id), []).append(technique_id)

    sub_match_counts: dict[str, int] = {}
    for _, techniques in rows:
        if not techniques:
            continue
        matched: set[str] = set()
        for declared in techniques:
            if is_subtechnique(declared):
                matched.add(declared)
            else:
                # Regra marcada só com o pai casa o filtro de qualquer
                # subtécnica dele — é o segundo sentido da expansão.
                matched.update(subs_by_parent.get(declared, ()))
        for subtechnique in matched:
            sub_match_counts[subtechnique] = sub_match_counts.get(subtechnique, 0) + 1

    families: list[TechniqueFamily] = []
    for family_id in sorted(family_counts):
        parent = _entry(family_id, names)
        parent.rule_count = own_counts.get(family_id, 0)
        parent.match_count = family_counts[family_id]

        children: list[TechniqueEntry] = []
        for technique_id in sorted(own_counts):
            if not is_subtechnique(technique_id) or parent_of(technique_id) != family_id:
                continue
            child = _entry(technique_id, names)
            child.rule_count = own_counts[technique_id]
            child.match_count = sub_match_counts.get(technique_id, child.rule_count)
            children.append(child)

        families.append(
            TechniqueFamily(
                parent=parent,
                subtechniques=children,
                rule_count=family_counts[family_id],
                parent_declared=family_id in own_counts,
            )
        )

    # Ordenação por volume: quem abre o catálogo quer ver primeiro o que o
    # acervo mais cobre. Desempate por ID para a saída ser estável entre
    # execuções — sem isso, o teste de contrato ficaria intermitente.
    families.sort(key=lambda item: (-item.rule_count, item.parent.id))

    all_ids = sorted(own_counts)
    return CorpusTechniques(
        families=families,
        total_rules=total_rules,
        untagged_count=untagged_count,
        tagged_count=total_rules - untagged_count,
        distinct_techniques=len(all_ids),
        attack_version=attack_version(),
        unknown_ids=[t for t in all_ids if t not in names],
        deprecated_ids=[t for t in all_ids if names.get(t, {}).get("deprecated")],
        revoked_ids=[t for t in all_ids if names.get(t, {}).get("revoked")],
    )


def load_corpus_techniques(conn: psycopg.Connection) -> CorpusTechniques:
    """Lê o acervo indexado e devolve o inventário completo.

    Uma varredura da tabela, sem cache. Medido em ~70 ms sobre as 5.664 linhas,
    quase tudo no rollup e não no SQL. Cachear compraria pouco e custaria uma
    invalidação a cada reindexação — servir contagem velha depois de reindexar
    seria um defeito bem pior que 70 ms.
    """
    rows = conn.execute(
        f"SELECT chunk_uid, mitre_techniques FROM {TABLE_NAME}"
    ).fetchall()
    return build_inventory([(row[0], list(row[1] or [])) for row in rows])
