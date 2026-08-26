"""Catálogo dos modelos de geração que a aplicação oferece para escolha.

Existe porque "qual modelo responde" deixou de ser uma decisão de arquivo de
configuração e virou uma decisão de quem usa a interface. Um Opus 5 respondendo
toda pergunta de demonstração custa 25 dólares por milhão de tokens de saída; a
mesma pergunta no nano da OpenAI custa 1,25. Para uma ferramenta de portfólio,
que roda muito mais demonstração do que trabalho crítico, essa diferença é o
custo inteiro do projeto.

Três decisões de forma:

1. **Este módulo é a fonte única de verdade.** A API valida contra ele, o CLI
   valida contra ele e a interface monta o seletor a partir dele. Acrescentar um
   modelo é acrescentar uma linha aqui — não editar três lugares e descobrir o
   quarto em produção.

2. **Preço é metadado de exibição, nunca entra em lógica.** Nada no código
   ramifica por preço; ele existe para que a escolha seja informada na hora de
   escolher, e não uma surpresa na fatura. Os valores são US$ por 1 milhão de
   tokens, conferidos em 2026-08-26 (Anthropic e OpenAI). Preço de tabela muda:
   se divergir da fatura, a tabela aqui é que está velha.

3. **O provedor é derivado do modelo, não pedido junto.** Quem escolhe
   `claude-haiku-4-5` não deveria ter que informar também que isso é Anthropic —
   o par redundante só cria a chance de chegarem contraditórios. `LLM_PROVIDER`
   segue decidindo o *padrão*; a escolha explícita traz o provedor consigo.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Provedores de geração suportados. Fonte única também deste nome: o registry
#: reexporta daqui para que catálogo e resolução não possam divergir.
LLM_PROVIDERS = ("anthropic", "openai")


@dataclass(frozen=True)
class ModelCard:
    """Um modelo de geração ofertado, com o que a escolha precisa saber."""

    id: str
    provider: str
    #: Nome curto, como aparece no seletor.
    label: str
    #: Uma frase sobre o compromisso que o modelo representa.
    note: str
    #: US$ por 1M de tokens de entrada.
    price_in: float
    #: US$ por 1M de tokens de saída. É o que domina o custo de uma resposta
    #: de RAG: o contexto recuperado é grande, mas a resposta é o que se paga
    #: caro por token.
    price_out: float


# Ordenado do mais barato para o mais caro dentro de cada provedor, que é a
# ordem em que a escolha é feita quando o motivo da escolha é custo.
CATALOG: tuple[ModelCard, ...] = (
    ModelCard(
        id="claude-haiku-4-5",
        provider="anthropic",
        label="Haiku 4.5",
        note="O mais barato da Anthropic. Resume e cita bem — suficiente para a demonstração.",
        price_in=1.00,
        price_out=5.00,
    ),
    ModelCard(
        id="claude-sonnet-5",
        provider="anthropic",
        label="Sonnet 5",
        note="Equilíbrio entre custo e qualidade de redação técnica.",
        price_in=3.00,
        price_out=15.00,
    ),
    ModelCard(
        id="claude-opus-5",
        provider="anthropic",
        label="Opus 5",
        note="O mais capaz da Anthropic — e o mais caro. Pensa por padrão, o que soma tokens.",
        price_in=5.00,
        price_out=25.00,
    ),
    ModelCard(
        id="gpt-5.4-nano",
        provider="openai",
        label="GPT-5.4 nano",
        note="O mais barato do catálogo inteiro. Bom para exercitar o fluxo sem gastar.",
        price_in=0.20,
        price_out=1.25,
    ),
    ModelCard(
        id="gpt-5.4-mini",
        provider="openai",
        label="GPT-5.4 mini",
        note="Barato e competente para resposta curta com citação.",
        price_in=0.75,
        price_out=4.50,
    ),
    ModelCard(
        id="gpt-5.4",
        provider="openai",
        label="GPT-5.4",
        note="O padrão da linha 5.4, para respostas mais longas e articuladas.",
        price_in=2.50,
        price_out=15.00,
    ),
    ModelCard(
        id="gpt-5.5",
        provider="openai",
        label="GPT-5.5",
        note="O mais capaz da OpenAI aqui — e o de saída mais cara do catálogo.",
        price_in=5.00,
        price_out=30.00,
    ),
)

# Um `id` repetido faria `by_id` devolver silenciosamente o primeiro e a
# interface mostrar duas entradas idênticas. Barrar no import é mais barato que
# investigar isso depois.
assert len({card.id for card in CATALOG}) == len(CATALOG), "ids duplicados no CATALOG"
assert all(card.provider in LLM_PROVIDERS for card in CATALOG), (
    "há ModelCard com provider fora de LLM_PROVIDERS"
)

_BY_ID: dict[str, ModelCard] = {card.id: card for card in CATALOG}


def by_id(model_id: str) -> ModelCard | None:
    """Devolve a ficha do modelo, ou `None` se não estiver no catálogo."""
    return _BY_ID.get(model_id.strip())


def known_ids() -> tuple[str, ...]:
    """Os ids ofertados, na ordem do catálogo."""
    return tuple(card.id for card in CATALOG)


def provider_of(model_id: str) -> str | None:
    """Descobre a que provedor um modelo pertence."""
    card = by_id(model_id)
    return card.provider if card else None
