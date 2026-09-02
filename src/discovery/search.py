"""Do prompt do analista até propostas de regra, com a procedência junto.

O caminho tem quatro passos, e o segundo é o que carrega a maior parte das
decisões:

1. **Plano de busca.** O prompt vem em português ("quero detectar exfiltração
   por DNS") e os repositórios são escritos em inglês. Quando há chave de
   geração, o modelo traduz o pedido em termos de busca; quando não há, um
   extrator determinístico aproveita o que já existe em `retrieval/query.py`.
   A busca nunca *depende* do modelo — sem chave ela fica pior, não indisponível.

2. **Candidatos.** Duas estratégias, complementares:

   - *árvore*: os caminhos de arquivo da origem, pontuados por casamento de
     termo. Funciona sem token e é surpreendentemente boa, porque repositório
     de detecção nomeia arquivo pelo que a regra faz
     (`proc_creation_win_lsass_dump.yml`).
   - *busca de código*: procura dentro do conteúdo, mas exige `GITHUB_TOKEN`.

   O que uma acha e a outra não é justamente o ponto de ter as duas: a árvore
   erra quando o nome do arquivo é opaco, a busca de código erra quando o termo
   aparece em contexto irrelevante.

3. **Leitura e normalização.** Os arquivos candidatos são baixados e passam
   pelos parsers da Fase 1 — os mesmos, não uma segunda implementação. Regra que
   não parseia é descartada com contagem, não em silêncio.

4. **Pontuação e corte.** A ordenação final olha o conteúdo normalizado, não o
   caminho: técnica ATT&CK pedida vale mais que palavra no título, que vale mais
   que palavra na descrição. Cada proposta carrega os termos que a fizeram subir
   — quem aprova precisa ver *por que* aquilo foi proposto.

O que este módulo deliberadamente **não** faz: decidir. Nada aqui escreve no
acervo. A saída é uma lista de propostas pendentes; a indexação só acontece em
`proposals.approve`, depois de um clique humano.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from ..ingestion.escu import parse_escu_text
from ..ingestion.normalize import PLATFORM_VOCABULARY, infer_platforms
from ..ingestion.schema import DetectionRule
from ..ingestion.sigma import parse_sigma_text
from ..ingestion.yaral import parse_yaral_text
from ..providers.base import LLMProvider
from ..retrieval.query import extract_lexical_terms, extract_query_techniques
from .github import DiscoveryError, GitHubClient, NotAllowedError
from .sources import RuleFormat, TrustedSource

#: Quantos arquivos, no máximo, são baixados por origem numa busca. É o teto de
#: custo da ferramenta: 7 origens × 20 arquivos = 140 leituras no pior caso.
#: Acima disso a busca deixa de ser interativa e o ganho de recall é marginal —
#: o que decide o resultado é a qualidade do plano, não a quantidade de leitura.
MAX_FILES_PER_SOURCE = 20
#: Quantas propostas voltam para a tela. Uma lista que ninguém revisa inteira
#: não é aprovação humana, é carimbo.
MAX_PROPOSALS = 12

#: Teto de tempo da busca inteira, em segundos.
#:
#: O endpoint é síncrono e alguém está olhando a tela: uma busca que demore
#: minutos é indistinguível de uma travada. Medido, o caso normal fica em ~20 s
#: para 7 origens. O teto existe para o caso anormal — uma origem lenta, uma
#: árvore enorme — e ele **interrompe com o que já achou**, em vez de falhar:
#: meia busca com procedência é útil; um erro depois de 90 s não é.
MAX_SEARCH_SECONDS = 90.0

_TERM_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")

PARSERS = {
    RuleFormat.SIGMA: parse_sigma_text,
    RuleFormat.SPLUNK_ESCU: parse_escu_text,
    RuleFormat.YARA_L: parse_yaral_text,
}

_PLAN_SYSTEM = """Você traduz pedidos de analistas de segurança em termos de \
busca para repositórios públicos de regras de detecção, escritos em inglês.

Responda SÓ com termos separados por vírgula, em inglês, minúsculos, no máximo 8.

Cada termo deve ser **uma palavra** sempre que possível — é assim que ele casa \
com o nome de um arquivo de regra (`proc_creation_win_lsass_dump.yml`) e com \
o título dela. Use duas palavras apenas quando a expressão for indivisível \
(`comsvcs.dll`, `pass-the-hash`). Prefira nome próprio a categoria: o binário, \
a ferramenta, o serviço, o campo de log, o número do evento. Evite palavras \
genéricas do domínio (detection, suspicious, malicious, activity, process, \
event, windows) — elas casam com tudo e não separam nada.

Sem frases, sem explicação, sem pontuação além das vírgulas."""

#: Palavras que aparecem em quase toda regra de detecção e por isso não separam
#: nada. Ficam fora do casamento — mas continuam podendo aparecer dentro de uma
#: expressão de duas palavras, onde carregam sentido ("process hollowing").
#:
#: Não é uma stoplist de idioma: é a lista das palavras que, medidas contra o
#: corpus, casariam com metade dele. Sem ela, "detecção de processo suspeito no
#: Windows" pontua igual para 5.000 regras.
GENERIC_TOKENS = frozenset(
    """
    detection detections rule rules event events log logs logging activity
    suspicious malicious anomalous unusual abnormal process processes file files
    command commands execution executed attack attacks technique techniques
    security monitor monitoring alert alerts detect detecting behavior behaviour
    system data user users account accounts network service services
    """.split()
) | frozenset(
    # O bloco em português existe porque o caminho sem chave de geração extrai
    # os termos do pedido original, que é escrito em português. Essas palavras
    # não casariam com repositório nenhum (que é escrito em inglês), mas os
    # termos aparecem na tela: exibir "detec · processo · suspeito" faz a busca
    # parecer quebrada mesmo quando ela funcionou.
    #
    # `detec`, `exfiltra` e afins são truncamentos, não erros de digitação: o
    # tokenizador de `retrieval/query.py` é ASCII e corta a palavra no acento
    # ("detecção" vira "detec"). Corrigir o tokenizador mexeria na busca lexical
    # da Fase 4, que depende dele estar assim.
    """
    deteccao deteccoes detec detectar regra regras evento eventos
    atividade suspeito suspeita suspeitos maliciosa malicioso
    processo processos arquivo arquivos comando comandos execucao execu
    ataque ataques tecnica tecnicas seguranca monitorar alerta alertas
    comportamento sistema dados usuario usuarios conta contas rede servico
    exfiltra exfiltracao credenciais detectando
    """.split()
)


class SearchPlan(BaseModel):
    """O que a busca vai procurar, e como esses termos foram obtidos."""

    prompt: str
    terms: list[str] = Field(
        default_factory=list,
        description="Os termos como saíram do plano — é o que a interface mostra.",
    )
    tokens: list[str] = Field(
        default_factory=list,
        description=(
            "Os termos quebrados em palavras isoladas, sem as genéricas. É com "
            "estes que caminho e conteúdo são casados; ver `GENERIC_TOKENS`."
        ),
    )
    mitre_techniques: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    expanded_by_model: bool = Field(
        default=False,
        description="Se um LLM traduziu o pedido. Falso significa extração determinística.",
    )
    model: str = ""


class Proposal(BaseModel):
    """Uma regra encontrada, ainda **fora** do acervo, esperando decisão.

    Carrega a regra normalizada inteira mais a procedência. As duas coisas
    juntas são o que torna a aprovação uma decisão informada: sem a regra, quem
    aprova não sabe o que entra; sem a procedência, não sabe de onde veio.
    """

    rule_uid: str
    rule: DetectionRule
    source_slug: str = Field(description="O repositório confiável onde a regra foi encontrada.")
    source_label: str
    source_path: str
    source_url: str
    score: float
    matched_terms: list[str] = Field(default_factory=list)
    matched_techniques: list[str] = Field(default_factory=list)
    found_by: list[str] = Field(
        default_factory=list, description="Estratégias que trouxeram o arquivo: árvore, código."
    )
    status: str = Field(
        default="pending", description="pending | approved | rejected, como está no banco."
    )


@dataclass
class DiscoveryResult:
    """As propostas mais a contabilidade de como se chegou nelas."""

    plan: SearchPlan
    proposals: list[Proposal] = field(default_factory=list)
    sources_searched: list[str] = field(default_factory=list)
    files_read: int = 0
    parsed: int = 0
    unparsed: int = 0
    already_indexed: int = 0
    requests: int = 0
    cached_trees: int = 0
    rate_limit_remaining: int | None = None
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 1. Plano de busca
# ---------------------------------------------------------------------------


def plan_search(prompt: str, llm: LLMProvider | None = None) -> SearchPlan:
    """Converte o pedido em termos de busca, com o modelo quando houver um.

    O fallback determinístico não é decorativo: é o caminho de quem clonou o
    repositório sem chave de geração, e de qualquer chamada em que o modelo
    falhe. Ele perde a tradução PT→EN, e é por isso que os identificadores
    (T1055, 4688, mimikatz) — que atravessam idioma — entram sempre.
    """
    techniques = extract_query_techniques(prompt)
    platforms = infer_platforms([prompt])
    lowered_techniques = {technique.lower() for technique in techniques}
    baseline = [
        term
        for term in [*extract_lexical_terms(prompt), *_acronyms(prompt)]
        if term not in lowered_techniques
    ]

    expanded: list[str] = []
    if llm is not None:
        try:
            # 400 e não 120: a resposta útil tem ~40 tokens, mas modelos que
            # raciocinam antes de responder gastam o orçamento nisso e devolvem
            # texto vazio com `truncated=True`. Medido com claude-opus-5: em
            # 120 a chamada voltava vazia de forma intermitente e a busca caía
            # no plano determinístico sem ninguém perceber — a falha aparecia
            # como resultado pior, não como erro.
            generation = llm.generate(_PLAN_SYSTEM, prompt, max_tokens=400)
            expanded = _parse_terms(generation.text)
        except Exception:  # noqa: BLE001 - chave, rede, cota: tudo cai no determinístico
            expanded = []

    if not expanded:
        terms = _dedupe(baseline)[:8]
        return SearchPlan(
            prompt=prompt,
            terms=terms,
            tokens=_match_tokens(terms),
            mitre_techniques=techniques,
            platforms=platforms,
        )

    # Os termos do modelo vêm primeiro (são os que atravessam o idioma), mas os
    # identificadores extraídos do texto original ficam: um número de evento ou
    # nome de binário que o analista digitou é sinal forte demais para depender
    # de o modelo ter repetido.
    identifiers = extract_lexical_terms(prompt, identifiers_only=True)
    terms = _dedupe([*expanded, *identifiers])[:10]
    return SearchPlan(
        prompt=prompt,
        terms=terms,
        tokens=_match_tokens(terms),
        mitre_techniques=techniques,
        platforms=platforms,
        expanded_by_model=True,
        model=llm.model,
    )


#: Sigla de três a cinco letras, em maiúsculas, no pedido: DNS, SMB, RDP, LSASS.
_ACRONYM_RE = re.compile(r"\b[A-Z]{3,5}\b")


def _acronyms(prompt: str) -> list[str]:
    """Siglas curtas escritas em maiúsculas, que o extrator lexical descarta.

    `extract_lexical_terms` exige 4 caracteres para palavra corrente, porque na
    busca full-text da Fase 4 um termo de 3 letras casa com meio corpus. Aqui o
    critério certo é outro: "DNS" é o assunto inteiro de um pedido como
    "exfiltração por DNS", e sem esta função esse pedido ficava sem termo
    nenhum no caminho sem chave de geração.

    Exige maiúsculas justamente para não reabrir a porta que o outro extrator
    fechou: "por" e "com" não são siglas.
    """
    return [match.lower() for match in _ACRONYM_RE.findall(prompt)]


def _match_tokens(terms: list[str]) -> list[str]:
    """Quebra os termos em palavras de casamento, descartando as genéricas.

    Existe porque as duas coisas têm usos diferentes: o termo inteiro
    ("lsass memory dump") é o que a busca de código do GitHub entende e o que a
    interface mostra; o token isolado é o que casa com um nome de arquivo
    (`..._lsass_dump.yml`) e com um título. Sem essa quebra, um plano bom vira
    zero casamento — foi exatamente o que aconteceu na primeira execução real:
    os oito termos eram todos frases, nenhuma delas aparecia literal em título
    nenhum, e o que sobrou pontuando foi a plataforma, que casa com metade do
    acervo.
    """
    tokens: list[str] = []
    for term in terms:
        for token in term.split():
            cleaned = token.strip(".,;:()[]\"'").lower()
            if len(cleaned) < 3 or cleaned in GENERIC_TOKENS:
                continue
            # Nome de plataforma sai daqui porque já é representado em
            # `plan.platforms`, que pontua à parte. Deixá-lo nos dois lugares
            # contaria "windows" duas vezes numa regra do Windows — e o acervo
            # é majoritariamente Windows.
            if cleaned in PLATFORM_VOCABULARY:
                continue
            tokens.append(cleaned)
    return _dedupe(tokens)


def _parse_terms(text: str) -> list[str]:
    """Lê a lista de termos que o modelo devolveu, tolerando formatação extra."""
    terms: list[str] = []
    for piece in re.split(r"[,\n]", text.lower()):
        cleaned = piece.strip().strip("-*•. \"'`")
        if not cleaned or len(cleaned) > 40:
            continue
        # O modelo às vezes devolve "termo (explicação)" apesar da instrução.
        cleaned = cleaned.split("(", 1)[0].strip()
        if cleaned and len(cleaned.split()) <= 3:
            terms.append(cleaned)
    return _dedupe(terms)[:10]


def _dedupe(values: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        cleaned = value.strip().lower()
        if cleaned:
            seen.setdefault(cleaned, None)
    return list(seen)


# ---------------------------------------------------------------------------
# 2. Candidatos
# ---------------------------------------------------------------------------


def _path_tokens(path: str) -> set[str]:
    """Tokens do caminho, já separados pelas convenções de nome de regra.

    `rules/windows/proc_creation_win_lsass_dump.yml` vira
    {rules, windows, proc, creation, win, lsass, dump}. É o que permite casar
    "lsass" com um arquivo cujo nome ninguém escreveria numa pergunta.
    """
    return set(_TERM_RE.findall(path.lower().replace("_", " ").replace("-", " ")))


def score_path(path: str, plan: SearchPlan) -> float:
    """Quão promissor é um caminho, antes de gastar uma requisição nele.

    A plataforma **não qualifica sozinha**: ela só entra depois de algum termo
    ter casado. Deixá-la pontuar por conta própria fazia todo arquivo com
    "windows" no nome virar candidato, e a busca gastava suas 20 leituras por
    origem em ordem alfabética — foi o defeito da primeira execução real.
    """
    tokens = _path_tokens(path)
    lowered = path.lower()
    score = 0.0

    for token in plan.tokens:
        if token in tokens:
            score += 2.0
        elif token in lowered:
            # Casa "cloudtrail" dentro de "aws_cloudtrail_...", que a tokenização
            # por separador não separa.
            score += 1.0

    if score <= 0:
        return 0.0

    for platform in plan.platforms:
        if platform in tokens:
            score += 0.5
    return score


def select_candidates(
    source: TrustedSource, client: GitHubClient, plan: SearchPlan, limit: int
) -> list[tuple[str, list[str]]]:
    """Escolhe os caminhos que valem uma leitura, com a estratégia que os achou.

    A busca de código entra primeiro na lista quando existe: ela olhou o
    conteúdo, o que é evidência mais forte que casar o nome do arquivo.
    """
    found: dict[str, list[str]] = {}

    for path in client.search_code(source, plan.terms, limit=limit):
        found.setdefault(path, []).append("código")

    tree = client.list_tree(source)
    ranked = sorted(
        ((score_path(path, plan), path) for path in tree),
        key=lambda item: (-item[0], item[1]),
    )
    for score, path in ranked:
        if score <= 0 or len(found) >= limit:
            break
        found.setdefault(path, []).append("árvore")

    return [(path, strategies) for path, strategies in list(found.items())[:limit]]


# ---------------------------------------------------------------------------
# 3. Normalização
# ---------------------------------------------------------------------------


def rule_from_file(source: TrustedSource, path: str, raw: str) -> DetectionRule | None:
    """Normaliza um arquivo lido do GitHub com o parser do formato da origem.

    Depois do parse, dois campos são reescritos: `source_url`, que os parsers da
    Fase 1 montam apontando para o repositório canônico do formato, e
    `source_path`. Sem isso uma regra achada no `tsale/Sigma_rules` seria citada
    com um link para o `SigmaHQ/sigma`, onde ela não existe — uma citação que
    parece boa e leva a lugar nenhum é pior que nenhuma citação.
    """
    parser = PARSERS[source.rule_format]
    rule = parser(raw, path)
    if rule is None:
        return None
    return rule.model_copy(update={"source_url": source.blob_url(path), "source_path": path})


# ---------------------------------------------------------------------------
# 4. Pontuação final
# ---------------------------------------------------------------------------

#: Pesos da ordenação. Técnica pedida explicitamente domina: quem escreveu
#: "T1055" no prompt não quer uma regra parecida de outra técnica.
WEIGHT_TECHNIQUE = 6.0
WEIGHT_TITLE = 3.0
WEIGHT_DESCRIPTION = 1.0
WEIGHT_PLATFORM = 1.0


#: Sufixos que ainda são a mesma palavra. A lista é curta e inglesa de
#: propósito: os repositórios são escritos em inglês, e o objetivo é casar
#: flexão ("dump" com "dumping"), não fazer stemming.
_INFLECTIONS: tuple[str, ...] = ("s", "es", "ed", "ing", "er", "ers", "ion", "ions")


def _matches_token(token: str, words: set[str], text: str) -> bool:
    """Se um token de busca casa com o texto de uma regra.

    Casa palavra inteira e flexão dela — mas só flexão. Um prefixo livre faria
    "dump" casar "dumpbin", que é outro binário para outra finalidade: numa
    busca por dump de credenciais, a regra do Dumpbin subia junto com a do
    LSASS. Aconteceu na primeira execução real desta ferramenta.

    O casamento dentro do texto fica reservado a tokens longos e pontuados
    ("comsvcs.dll"), onde a coincidência é improvável.
    """
    if token in words:
        return True
    for word in words:
        if word.startswith(token) and word[len(token) :] in _INFLECTIONS:
            return True
    return len(token) > 6 and "." in token and token in text


def score_rule(rule: DetectionRule, plan: SearchPlan) -> tuple[float, list[str], list[str]]:
    """Pontua a regra já normalizada. Devolve (nota, termos casados, técnicas).

    Diferente de `score_path`, aqui o que é pontuado é o conteúdo: título,
    descrição e as técnicas declaradas. Uma proposta só sobrevive se casar
    termo ou técnica — plataforma continua sendo desempate, nunca ingresso.
    """
    title_words = set(_TERM_RE.findall(rule.title.lower()))
    description = rule.description.lower()
    description_words = set(_TERM_RE.findall(description))
    matched_terms: list[str] = []
    score = 0.0

    wanted = {technique.upper() for technique in plan.mitre_techniques}
    declared = {technique.upper() for technique in rule.mitre_techniques}
    matched_techniques = sorted(
        technique
        for technique in declared
        # Casa pai com subtécnica nos dois sentidos: pedir T1055 deve casar
        # T1055.001, e pedir T1055.001 deve casar uma regra marcada só com T1055.
        if any(
            technique == item
            or technique.startswith(f"{item}.")
            or item.startswith(f"{technique}.")
            for item in wanted
        )
    )
    score += WEIGHT_TECHNIQUE * len(matched_techniques)

    # Frase inteira no título é o sinal mais forte que existe aqui: quem escreve
    # uma regra chamada "LSASS Memory Dump" está falando exatamente do pedido.
    lowered_title = rule.title.lower()
    for term in plan.terms:
        if " " in term and term in lowered_title:
            score += WEIGHT_TITLE
            matched_terms.append(term)

    for token in plan.tokens:
        if _matches_token(token, title_words, lowered_title):
            score += WEIGHT_TITLE
            matched_terms.append(token)
        elif _matches_token(token, description_words, description):
            score += WEIGHT_DESCRIPTION
            matched_terms.append(token)

    if not matched_terms and not matched_techniques:
        # Nada do pedido aparece na regra. Plataforma sozinha não é relevância:
        # "é do Windows" descreve metade do acervo.
        return 0.0, [], []

    for platform in plan.platforms:
        if platform in rule.platforms:
            score += WEIGHT_PLATFORM

    return score, _dedupe(matched_terms), matched_techniques


# ---------------------------------------------------------------------------
# Orquestração
# ---------------------------------------------------------------------------


def discover(
    prompt: str,
    sources: list[TrustedSource],
    client: GitHubClient,
    known_uids: set[str] | None = None,
    llm: LLMProvider | None = None,
    max_files_per_source: int = MAX_FILES_PER_SOURCE,
    limit: int = MAX_PROPOSALS,
    max_seconds: float = MAX_SEARCH_SECONDS,
) -> DiscoveryResult:
    """Roda a busca ponta a ponta nas origens habilitadas.

    `known_uids` são as regras já indexadas. Elas continuam sendo lidas — é
    assim que se sabe que a regra já está no acervo — mas saem da lista de
    propostas e viram um número: "8 das 14 encontradas já estão indexadas" é
    informação útil sobre a cobertura do acervo, não ruído a esconder.
    """
    plan = plan_search(prompt, llm)
    known = known_uids or set()
    result = DiscoveryResult(plan=plan)

    if not plan.tokens and not plan.mitre_techniques:
        result.warnings.append(
            "O pedido não tem termo aproveitável para busca. Descreva o comportamento "
            "a detectar (ferramenta, técnica, evento) em vez de fazer uma pergunta genérica."
        )
        return result

    proposals: list[Proposal] = []
    seen_uids: set[str] = set()
    deadline = time.monotonic() + max_seconds

    def esgotou() -> bool:
        # `>=` e não `>`: com orçamento zero a busca tem que parar na primeira
        # checagem. Com `>`, a resolução do relógio no Windows (~15 ms) deixava
        # a primeira origem passar, e o teto virava uma sugestão.
        return time.monotonic() >= deadline

    for source in sources:
        if not source.enabled:
            continue
        if esgotou():
            result.warnings.append(
                f"A busca parou em {max_seconds:.0f}s com o que já tinha encontrado; "
                f"{source.slug} e as origens seguintes não foram consultadas."
            )
            break
        result.sources_searched.append(source.slug)

        try:
            candidates = select_candidates(source, client, plan, max_files_per_source)
        except NotAllowedError:
            raise
        except DiscoveryError as error:
            result.warnings.append(f"{source.slug}: {error}")
            continue

        for path, strategies in candidates:
            if esgotou():
                result.warnings.append(
                    f"A busca parou em {max_seconds:.0f}s no meio de {source.slug}."
                )
                break
            try:
                raw = client.fetch_file(source, path)
            except DiscoveryError as error:
                result.warnings.append(f"{source.slug}/{path}: {error}")
                continue

            rule = rule_from_file(source, path, raw)
            if rule is None:
                result.unparsed += 1
                continue
            result.parsed += 1

            if rule.rule_uid in known:
                result.already_indexed += 1
                continue
            if rule.rule_uid in seen_uids:
                # A mesma regra em duas origens (repositórios de comunidade se
                # copiam). Fica a primeira, que é a de maior prioridade na lista.
                continue

            score, matched_terms, matched_techniques = score_rule(rule, plan)
            if score <= 0:
                continue

            seen_uids.add(rule.rule_uid)
            proposals.append(
                Proposal(
                    rule_uid=rule.rule_uid,
                    rule=rule,
                    source_slug=source.slug,
                    source_label=source.label,
                    source_path=path,
                    source_url=source.blob_url(path),
                    score=round(score, 2),
                    matched_terms=matched_terms,
                    matched_techniques=matched_techniques,
                    found_by=strategies,
                )
            )

    proposals.sort(key=lambda proposal: (-proposal.score, proposal.rule.title))
    result.proposals = proposals[:limit]
    result.files_read = client.stats.files_read
    result.requests = client.stats.requests
    result.cached_trees = client.stats.cached_trees
    result.rate_limit_remaining = client.stats.rate_limit_remaining
    result.warnings.extend(client.stats.errors)
    return result
