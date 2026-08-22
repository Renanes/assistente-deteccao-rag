"""Converte uma `DetectionRule` na unidade que vai para o índice vetorial.

A pergunta central desta fase é o que exatamente entra no vetor. A resposta aqui
tem três partes, e cada uma foi decidida olhando o corpus real (5.664 regras),
não por convenção:

1. **Um chunk por regra.** Medido o corpus normalizado, o texto narrativo mais
   longo tem 1.897 caracteres e o p99 fica em 1.455 — nenhuma regra chega perto
   do limite em que dividir passaria a valer a pena. Dividir aqui só criaria
   chunks irmãos competindo pelo mesmo top-k e uma citação ambígua ("qual
   pedaço da regra?"). `chunk_index`/`chunk_total` ficam no contrato mesmo
   valendo sempre 0/1: se a Fase 6 mostrar perda de recall em descrições longas,
   dividir passa a ser mudança de código, não migração de banco.

2. **A query não é embeddada.** Sintaxe de linguagem de busca (`EventID=1`,
   `| stats count by`, `$e.metadata.event_type`) domina o vetor com tokens que
   não têm relação com a intenção do analista, que pergunta em linguagem
   natural. A query é preservada literal como contexto para a resposta da
   Fase 5 — o analista quer ver a regra, não uma paráfrase dela.

3. **O narrativo ganha uma linha de contexto.** Título e descrição sozinhos não
   dizem plataforma nem técnica. Uma pergunta como "detecção de injeção de
   processo no Windows" casa muito melhor quando "windows" e "T1055" estão no
   texto embeddado. Isso não substitui o filtro por metadado da Fase 4 — que
   continua sendo o caminho para casar termo exato — mas evita depender só dele.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..ingestion.schema import DetectionRule, QueryLanguage, RuleSource, Severity

# Teto de caracteres da query levada no contexto do prompt.
#
# A distribuição é bem concentrada (p90 = 1.268 caracteres), mas a cauda é
# extrema: a regra "Vulnerable Driver Load" do Sigma tem 250 KB de query, quase
# tudo lista de hash do LOLDrivers. Sem teto, uma única regra recuperada estoura
# o contexto do prompt da Fase 5 e empurra as outras para fora. Com 4.000, o
# corte atinge 41 das 5.664 regras (0,7%) e nenhuma delas perde a lógica de
# detecção em si — o que é cortado é lista de indicador, que o analista consulta
# na fonte original de qualquer forma.
MAX_QUERY_CHARS = 4_000

TRUNCATION_MARKER = "[... query truncada — ver a regra completa na fonte original ...]"

# `data_sources` guarda fielmente o que cada fonte declarou (trabalho da Fase 1)
# e continua íntegro no chunk, para o filtro da Fase 4. Mas nem tudo que está lá
# serve para embeddar, e dois filtros diferentes são necessários.
#
# Prefixos que nunca são fonte de dado. `logsource.definition` do Sigma (390
# regras) é campo livre para nota de operação, e o conteúdo real varia demais
# para ter um tamanho típico: vai de um GUID solto
# ("definition: dfd8c0f4-e6ad-4e07-b91b-f2fca0ddef64") a um parágrafo de
# requisito de logging. Filtrar por tamanho deixaria os curtos passar, e um
# GUID no texto embeddado é ruído puro — o critério certo aqui é o prefixo.
EXCLUDED_DATA_SOURCE_PREFIXES: tuple[str, ...] = ("definition:",)

# Teto de caracteres para o que sobrou. Medido o corpus, as fontes de dado
# reais são curtas — "Sysmon EventID 1" (16), "Windows Event Log Security 4688"
# (31), "category: process_creation" (26) — com p90 em 31 caracteres. O teto
# pega a prosa que não vem prefixada, sem tocar em fonte de dado legítima.
MAX_CONTEXT_DATA_SOURCE_CHARS = 60

# Como cada fonte é chamada em português corrente, para a linha de contexto.
# O valor do enum (`splunk_escu`) é identificador, não texto para embeddar.
SOURCE_LABELS: dict[RuleSource, str] = {
    RuleSource.SIGMA: "Sigma",
    RuleSource.SPLUNK_ESCU: "Splunk ESCU",
    RuleSource.YARA_L: "YARA-L",
}


class RuleChunk(BaseModel):
    """Uma unidade indexável: o texto que vira vetor mais tudo que a cita.

    Carrega os metadados por valor em vez de guardar só o `rule_uid` e fazer
    join com a tabela de regras. O retrieval da Fase 4 filtra por plataforma e
    técnica no mesmo passo da busca vetorial, e a citação da Fase 5 precisa de
    título e URL — todos disponíveis sem uma segunda consulta.
    """

    # --- Identidade ---
    chunk_uid: str = Field(
        description="Identificador do chunk. Com um chunk por regra, igual ao `rule_uid`."
    )
    rule_uid: str = Field(description="A regra de origem, para citação e deduplicação.")
    chunk_index: int = Field(
        default=0,
        description="Posição do chunk dentro da regra. Sempre 0 enquanto a divisão for 1:1.",
    )
    chunk_total: int = Field(
        default=1, description="Quantos chunks a regra gerou. Sempre 1 enquanto a divisão for 1:1."
    )

    # --- O que é embeddado ---
    embedding_text: str = Field(description="Texto que vira vetor: contexto + narrativa.")

    # --- O que é preservado como contexto, sem virar vetor ---
    query: str = Field(description="A lógica de detecção, literal (possivelmente truncada).")
    query_truncated: bool = Field(
        default=False,
        description="Se True, a query foi cortada e a resposta deve remeter à fonte.",
    )
    query_language: QueryLanguage

    # --- Metadados para filtro (Fase 4) e citação (Fase 5) ---
    source: RuleSource
    title: str
    source_url: str | None = None
    platforms: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    severity: Severity | None = None


def truncate_query(query: str, max_chars: int = MAX_QUERY_CHARS) -> tuple[str, bool]:
    """Corta a query no teto de caracteres, devolvendo (texto, foi_truncada).

    O corte procura a última quebra de linha antes do limite para não terminar
    no meio de uma condição — meia linha de lógica de detecção é pior que
    nenhuma, porque parece completa. Se não houver quebra de linha razoável
    (query de linha única, comum no SPL), corta seco no limite.
    """
    if len(query) <= max_chars:
        return query, False

    cut = query[:max_chars]
    # Só respeita a quebra de linha se ela não jogar fora mais da metade do
    # que cabia — numa query de linha única, `rfind` devolveria algo perto de 0.
    if (last_newline := cut.rfind("\n")) > max_chars // 2:
        cut = cut[:last_newline]

    return f"{cut.rstrip()}\n{TRUNCATION_MARKER}", True


def build_context_line(rule: DetectionRule) -> str:
    """Monta a frase de contexto que precede a narrativa no texto embeddado.

    Escrita como frase em linguagem natural, não como cabeçalho de campos
    (`source=sigma | platform=windows`): o modelo de embedding é treinado em
    prosa, e pares chave-valor viram tokens soltos que ancoram mal.
    """
    label = SOURCE_LABELS[rule.source]
    platforms = ", ".join(rule.platforms)
    sentences = [f"Regra {label} para {platforms}." if platforms else f"Regra {label}."]

    if rule.mitre_techniques:
        sentences.append(f"Técnicas MITRE ATT&CK: {', '.join(rule.mitre_techniques)}.")

    if data_sources := select_context_data_sources(rule.data_sources):
        sentences.append(f"Fontes de dados: {', '.join(data_sources)}.")

    return " ".join(sentences)


def select_context_data_sources(
    data_sources: list[str], max_chars: int = MAX_CONTEXT_DATA_SOURCE_CHARS
) -> list[str]:
    """Filtra as fontes de dado que valem entrar no texto embeddado.

    Descarta o que não é fonte de dado pelo prefixo (ver
    `EXCLUDED_DATA_SOURCE_PREFIXES`), depois o que é prosa longa demais (ver
    `MAX_CONTEXT_DATA_SOURCE_CHARS`), e apara o ponto final do que sobra para a
    frase não terminar em `..`.
    """
    selected: list[str] = []
    for source in data_sources:
        normalized = source.strip()
        if normalized.lower().startswith(EXCLUDED_DATA_SOURCE_PREFIXES):
            continue
        if len(normalized) > max_chars:
            continue
        if stripped := normalized.rstrip(". "):
            selected.append(stripped)

    return selected


def build_embedding_text(rule: DetectionRule) -> str:
    """Devolve o texto que efetivamente vira vetor.

    Contexto + narrativa, sem a query. Ver o docstring do módulo para o porquê
    de a query ficar de fora.
    """
    narrative = rule.narrative_text
    context = build_context_line(rule)
    return f"{context}\n\n{narrative}" if narrative else context


def chunk_rule(rule: DetectionRule, max_query_chars: int = MAX_QUERY_CHARS) -> list[RuleChunk]:
    """Converte uma regra em seus chunks indexáveis.

    Devolve lista — hoje sempre de um elemento — para que a divisão de regras
    longas, se a Fase 6 justificar, não mude a assinatura nem quem a chama.
    """
    query, truncated = truncate_query(rule.query, max_query_chars)

    return [
        RuleChunk(
            chunk_uid=rule.rule_uid,
            rule_uid=rule.rule_uid,
            chunk_index=0,
            chunk_total=1,
            embedding_text=build_embedding_text(rule),
            query=query,
            query_truncated=truncated,
            query_language=rule.query_language,
            source=rule.source,
            title=rule.title,
            source_url=rule.source_url,
            platforms=list(rule.platforms),
            mitre_techniques=list(rule.mitre_techniques),
            mitre_tactics=list(rule.mitre_tactics),
            data_sources=list(rule.data_sources),
            severity=rule.severity,
        )
    ]
