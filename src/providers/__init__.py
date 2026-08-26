"""Abstração de provedores de LLM e de embedding (CLAUDE.md, seção 3).

Nenhum módulo fora deste pacote deve importar `openai`, `anthropic` ou
`voyageai` diretamente.
"""

from .base import EmbeddingProvider, Generation, LLMProvider, ProviderError
from .catalog import CATALOG, ModelCard
from .config import (
    EMBEDDING_DIMENSIONS,
    PGVECTOR_INDEX_MAX_DIMENSIONS,
    Settings,
    get_settings,
)
from .registry import (
    EMBEDDING_PROVIDERS,
    LLM_PROVIDERS,
    get_embedding_provider,
    get_llm_provider,
)

__all__ = [
    "CATALOG",
    "EMBEDDING_DIMENSIONS",
    "EMBEDDING_PROVIDERS",
    "LLM_PROVIDERS",
    "PGVECTOR_INDEX_MAX_DIMENSIONS",
    "EmbeddingProvider",
    "Generation",
    "LLMProvider",
    "ModelCard",
    "ProviderError",
    "Settings",
    "get_embedding_provider",
    "get_llm_provider",
    "get_settings",
]
