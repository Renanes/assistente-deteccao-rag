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
