"""Contratos de entrada e saída da API.

A resposta expõe deliberadamente mais do que o texto gerado. Tudo que o
pipeline sabe sobre *como* chegou à resposta — qual perna trouxe cada regra, em
que posição, se o filtro foi relaxado, se a citação foi verificada — é material
da interface, não detalhe interno. É o que separa esta demo de um chat que pede
confiança cega.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    top_k: int = Field(default=5, ge=1, le=20)
    #: Id de um modelo do catálogo. Ausente, usa o padrão do `.env`. O provedor
    #: não é pedido junto de propósito: ele é derivado do modelo, e assim não
    #: existe requisição com par provedor/modelo contraditório.
    model: str | None = Field(default=None, max_length=100)

    #: Filtro explícito por técnica, escolhido no catálogo. Quando vem, **vence**
    #: a técnica que seria inferida do texto da pergunta: quem clicou numa
    #: técnica disse o que queria, e adivinhar por cima disso só poderia piorar.
    mitre_techniques: list[str] = Field(default_factory=list, max_length=20)
    #: Faceta "Sem técnica declarada". Separada da lista acima porque não é um
    #: ID ATT&CK — ver `SearchFilters.include_untagged`.
    include_untagged: bool = False


class RuleOut(BaseModel):
    """Uma regra recuperada, como a interface precisa dela."""

    index: int = Field(description="O número da citação: `[1]`, `[2]`.")
    cited: bool = Field(description="Se a resposta gerada realmente a citou.")

    rule_uid: str
    title: str
    source: str
    source_url: str | None = None

    query: str
    query_language: str
    query_truncated: bool

    platforms: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: str | None = None

    similarity: float | None = Field(
        default=None, description="Similaridade de cosseno com a pergunta."
    )
    matched_by: list[str] = Field(default_factory=list)
    ranks: dict[str, int] = Field(default_factory=dict)


class GroundingOut(BaseModel):
    """O resultado da verificação de citação — a tese do projeto, medida."""

    is_grounded: bool
    cited: list[int] = Field(default_factory=list)
    invalid: list[int] = Field(
        default_factory=list, description="Índices citados que não existem no contexto."
    )
    uncited: bool = Field(description="A resposta não citou nenhuma regra.")


class AskResponse(BaseModel):
    question: str
    answer: str
    rules: list[RuleOut] = Field(default_factory=list)
    grounding: GroundingOut

    #: Nenhuma regra casou o filtro deduzido — os resultados são apenas
    #: relacionados, e a interface precisa dizer isso.
    relaxed_filters: bool = False
    filtered_techniques: list[str] = Field(default_factory=list)
    #: A busca foi restrita às regras sem técnica declarada.
    filtered_untagged: bool = False
    answered_without_model: bool = False
    answer_truncated: bool = False

    llm_provider: str = ""
    llm_model: str = ""
    embedding_model: str = ""
    elapsed_ms: int = 0


class HealthResponse(BaseModel):
    status: str
    indexed_chunks: int
    embedding_model: str
    llm_provider: str
    llm_model: str


class ModelOut(BaseModel):
    """Um modelo ofertado no seletor de geração."""

    id: str
    provider: str
    label: str
    note: str
    price_in: float = Field(description="US$ por 1M de tokens de entrada.")
    price_out: float = Field(description="US$ por 1M de tokens de saída.")
    available: bool = Field(description="Se há chave configurada para o provedor.")
    is_default: bool = Field(description="Se é o modelo que o `.env` define como padrão.")


class ModelsResponse(BaseModel):
    models: list[ModelOut] = Field(default_factory=list)
    default_model: str


class ProviderStatusOut(BaseModel):
    """O estado da chave de um provedor — nunca o valor dela.

    `configured_in_env` é booleano de propósito. A tentação seria devolver os
    últimos caracteres da chave "para conferir", e isso transformaria este
    endpoint num vazamento parcial de credencial numa aplicação sem
    autenticação. Quem quiser conferir troca a chave.
    """

    provider: str
    configured_in_env: bool = Field(description="Se o `.env` do servidor tem chave para ele.")
    roles: list[str] = Field(description="O que essa chave habilita: embedding, geração ou ambos.")
    header: str = Field(description="Cabeçalho em que a chave de quem usa deve viajar.")


class SettingsResponse(BaseModel):
    """Diagnóstico de configuração, para a interface dizer o que falta."""

    providers: list[ProviderStatusOut] = Field(default_factory=list)

    embedding_provider: str
    embedding_model: str
    #: Com que modelo o corpus foi **realmente** indexado. É o dado que evita o
    #: modo de falha mais confuso do "traga sua chave": vetores de modelos
    #: diferentes não são comparáveis, então uma chave que cubra outro modelo
    #: devolve vizinhos errados em vez de erro.
    corpus_embedding_model: str = ""

    embedding_ready: bool = Field(description="Há chave de embedding no `.env`.")
    llm_ready: bool = Field(description="Há chave de geração no `.env`.")


class TechniqueOut(BaseModel):
    """Uma técnica do acervo, como o catálogo a exibe."""

    id: str
    name: str | None = Field(default=None, description="Nome oficial do ATT&CK, se conhecido.")
    status: str = Field(description="ok | deprecated | revoked | unknown.")
    superseded_by: str | None = None
    is_subtechnique: bool = False

    rule_count: int = Field(description="Regras que declaram exatamente este ID.")
    match_count: int = Field(
        description="Regras que o filtro devolve ao selecionar este ID, já com a expansão."
    )


class TechniqueFamilyOut(BaseModel):
    """Uma técnica-pai com as subtécnicas presentes no acervo."""

    parent: TechniqueOut
    subtechniques: list[TechniqueOut] = Field(default_factory=list)
    rule_count: int
    parent_declared: bool = Field(
        description="False quando nenhuma regra declara o pai — a família existe só pelas subtécnicas."
    )


class TechniquesResponse(BaseModel):
    """O inventário de técnicas do acervo indexado.

    Expõe os IDs problemáticos (`unknown_ids`, `deprecated_ids`, `revoked_ids`)
    em vez de filtrá-los. São achados sobre a qualidade das fontes públicas, e
    esconder é o que tornaria o catálogo uma vitrine em vez de um inventário.
    """

    families: list[TechniqueFamilyOut] = Field(default_factory=list)

    total_rules: int
    untagged_count: int = Field(description="Regras sem nenhuma técnica declarada.")
    untagged_label: str
    tagged_count: int
    distinct_techniques: int

    attack_version: str
    unknown_ids: list[str] = Field(default_factory=list)
    deprecated_ids: list[str] = Field(default_factory=list)
    revoked_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Descoberta de novos casos de uso (src/discovery/)
# --------------------------------------------------------------------------


class TrustedSourceOut(BaseModel):
    """Um repositório confiável, como o menu de origens o exibe."""

    slug: str
    ref: str
    label: str
    rule_format: str
    path_prefixes: list[str] = Field(default_factory=list)
    note: str = ""
    enabled: bool = True
    is_seed: bool = Field(description="Veio pré-cadastrado com a ferramenta.")


class SourcesResponse(BaseModel):
    sources: list[TrustedSourceOut] = Field(default_factory=list)
    #: Formatos que os parsers da Fase 1 sabem ler. A interface usa isto para
    #: montar o seletor em vez de repetir a lista — um formato acrescentado no
    #: backend aparece no menu sem tocar no JavaScript.
    formats: list[str] = Field(default_factory=list)
    #: Se o servidor tem `GITHUB_TOKEN`. Muda o que a busca consegue fazer, e
    #: por isso é dito na tela em vez de virar uma diferença silenciosa de
    #: qualidade dos resultados.
    has_github_token: bool = False


class AddSourceRequest(BaseModel):
    slug: str = Field(min_length=3, max_length=140, description="dono/repo, ou a URL do GitHub.")
    rule_format: str = Field(description="sigma | splunk_escu | yara_l.")
    #: Ausente, o branch padrão do repositório é descoberto no GitHub. Pedir que
    #: quem cadastra saiba de cor se é `main` ou `master` seria uma pegadinha.
    ref: str | None = Field(default=None, max_length=100)
    label: str | None = Field(default=None, max_length=80)
    path_prefixes: list[str] = Field(default_factory=list, max_length=10)
    note: str | None = Field(default=None, max_length=400)


class ProposalOut(BaseModel):
    """Uma regra encontrada, com o bastante para decidir sem sair da página."""

    rule_uid: str
    status: str = Field(description="pending | approved | rejected.")

    title: str
    description: str = ""
    query: str
    query_language: str
    #: A lógica exibida passa pelo mesmo teto da indexação. Quando corta, a
    #: ficha remete à fonte em vez de fingir que mostrou a regra inteira.
    query_truncated: bool = False
    platforms: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: str | None = None
    author: str | None = None
    references: list[str] = Field(default_factory=list)

    #: Procedência — a razão de a proposta ser auditável. Sem o repositório e o
    #: caminho, aprovar é confiar num texto que apareceu na tela.
    source_slug: str
    source_label: str
    source_path: str
    source_url: str
    rule_source: str = Field(description="O formato/fonte no schema comum: sigma, splunk_escu…")

    score: float
    matched_terms: list[str] = Field(default_factory=list)
    matched_techniques: list[str] = Field(default_factory=list)
    found_by: list[str] = Field(default_factory=list)


class DiscoverRequest(BaseModel):
    prompt: str = Field(min_length=3, max_length=500)
    #: Restringe a busca a algumas das origens cadastradas. Vazio significa
    #: todas as habilitadas — nunca "qualquer repositório".
    sources: list[str] = Field(default_factory=list, max_length=20)
    limit: int = Field(default=12, ge=1, le=30)


class DiscoverResponse(BaseModel):
    prompt: str
    proposals: list[ProposalOut] = Field(default_factory=list)

    #: Como o pedido virou termos de busca. Exposto porque é a decisão que mais
    #: explica um resultado ruim: termo errado acha regra errada.
    terms: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    expanded_by_model: bool = False
    model: str = ""

    sources_searched: list[str] = Field(default_factory=list)
    files_read: int = 0
    rules_parsed: int = 0
    already_indexed: int = Field(
        default=0, description="Encontradas, mas já presentes no acervo indexado."
    )
    requests: int = 0
    rate_limit_remaining: int | None = None
    warnings: list[str] = Field(default_factory=list)
    elapsed_ms: int = 0


class DecideRequest(BaseModel):
    rule_uid: str = Field(min_length=1, max_length=200)
    decision: str = Field(description="approve | reject.")


class DecideResponse(BaseModel):
    rule_uid: str
    status: str
    title: str
    indexed_chunks: int = Field(default=0, description="Chunks escritos no acervo.")
    message: str


class ProposalsResponse(BaseModel):
    proposals: list[ProposalOut] = Field(default_factory=list)
    pending: int = 0
    approved: int = 0
    rejected: int = 0
