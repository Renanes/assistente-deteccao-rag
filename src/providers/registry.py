"""Resolve a variável de ambiente no provedor concreto.

É o único ponto do projeto que sabe quais implementações existem. Quem consome
recebe `EmbeddingProvider` / `LLMProvider` e não conhece o nome de nenhuma
classe concreta.

Os SDKs são importados dentro das funções, e não no topo do módulo, de
propósito: importar `openai`, `anthropic` e `voyageai` de uma vez custa quase um
segundo de arranque, e nenhuma execução usa os três. Assim, rodar com
`EMBEDDING_PROVIDER=openai` não exige que os outros SDKs estejam sequer
instalados.
"""

from __future__ import annotations

from .base import EmbeddingProvider, LLMProvider, ProviderError
from .config import Settings, get_settings

EMBEDDING_PROVIDERS = ("openai", "voyage")
LLM_PROVIDERS = ("anthropic", "openai")


def get_embedding_provider(settings: Settings | None = None) -> EmbeddingProvider:
    """Instancia o provedor de embedding indicado por `EMBEDDING_PROVIDER`."""
    settings = settings or get_settings()
    choice = settings.embedding_provider.strip().lower()

    if choice == "openai":
        from .openai_provider import OpenAIEmbeddingProvider

        return OpenAIEmbeddingProvider(settings)

    if choice == "voyage":
        from .voyage_provider import VoyageEmbeddingProvider

        return VoyageEmbeddingProvider(settings)

    if choice == "anthropic":
        # Erro dedicado, e não um "provedor desconhecido" genérico: "anthropic"
        # é a resposta intuitiva e errada aqui, e vale explicar o porquê uma vez
        # em vez de deixar quem configura procurar.
        raise ProviderError(
            "EMBEDDING_PROVIDER=anthropic não existe: a Anthropic não tem API de "
            "embeddings própria. O caminho recomendado por eles é a Voyage AI — "
            "use EMBEDDING_PROVIDER=voyage com VOYAGE_API_KEY, ou "
            "EMBEDDING_PROVIDER=openai. (LLM_PROVIDER=anthropic segue válido: a "
            "restrição é só de embedding.)"
        )

    raise ProviderError(
        f"EMBEDDING_PROVIDER='{settings.embedding_provider}' desconhecido. "
        f"Valores aceitos: {', '.join(EMBEDDING_PROVIDERS)}."
    )


def get_llm_provider(settings: Settings | None = None) -> LLMProvider:
    """Instancia o provedor de geração indicado por `LLM_PROVIDER`."""
    settings = settings or get_settings()
    choice = settings.llm_provider.strip().lower()

    if choice == "anthropic":
        from .anthropic_provider import AnthropicLLMProvider

        return AnthropicLLMProvider(settings)

    if choice == "openai":
        from .openai_provider import OpenAILLMProvider

        return OpenAILLMProvider(settings)

    raise ProviderError(
        f"LLM_PROVIDER='{settings.llm_provider}' desconhecido. "
        f"Valores aceitos: {', '.join(LLM_PROVIDERS)}."
    )
