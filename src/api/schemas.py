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
