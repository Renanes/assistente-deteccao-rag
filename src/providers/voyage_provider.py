"""Implementação Voyage AI: embeddings.

É o caminho que a Anthropic recomenda para embeddings, já que não tem API
própria — ver `anthropic_provider.py`. Fica como provedor de primeira classe,
com chave própria, e não escondido atrás do nome "anthropic".

Este é o único módulo autorizado a importar o SDK da Voyage.
"""

from __future__ import annotations

from .base import EmbeddingProvider, ProviderError
from .config import EMBEDDING_DIMENSIONS, Settings

# Menor que o lote da OpenAI: a Voyage tem limite de tokens por requisição mais
# apertado, e o texto embeddado deste corpus chega a ~2.000 caracteres.
EMBEDDING_BATCH_SIZE = 64


class VoyageEmbeddingProvider(EmbeddingProvider):
    """Embeddings via `voyageai.Client.embed`."""

    name = "voyage"

    def __init__(self, settings: Settings) -> None:
        if not settings.voyage_api_key:
            raise ProviderError(
                "EMBEDDING_PROVIDER=voyage exige VOYAGE_API_KEY preenchida no .env. "
                "A chave da Anthropic não serve: a Voyage é um serviço separado."
            )

        self.model = settings.voyage_embedding_model
        if self.model not in EMBEDDING_DIMENSIONS:
            raise ProviderError(
                f"Dimensão desconhecida para o modelo de embedding '{self.model}'. "
                f"Modelos conhecidos: {', '.join(sorted(EMBEDDING_DIMENSIONS))}. "
                "Acrescente o modelo em EMBEDDING_DIMENSIONS (src/providers/config.py)."
            )
        self.dimensions = EMBEDDING_DIMENSIONS[self.model]

        import voyageai

        self._client = voyageai.Client(api_key=settings.voyage_api_key)

    def _embed(self, texts: list[str], input_type: str) -> list[list[float]]:
        vectors: list[list[float]] = []
        for start in range(0, len(texts), EMBEDDING_BATCH_SIZE):
            batch = texts[start : start + EMBEDDING_BATCH_SIZE]
            result = self._client.embed(batch, model=self.model, input_type=input_type)
            vectors.extend(result.embeddings)
        return self._validate_dimensions(vectors)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        # `input_type` é o motivo de `embed_documents` e `embed_query` serem
        # métodos separados no contrato: a Voyage embeda pergunta e documento
        # em espaços levemente diferentes, e ignorar isso custa recall.
        return self._embed(texts, input_type="document") if texts else []

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text], input_type="query")[0]
