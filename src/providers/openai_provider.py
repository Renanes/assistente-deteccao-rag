"""Implementações OpenAI: embedding e geração.

Este é um dos poucos módulos autorizados a importar o SDK da OpenAI. Se um
`from openai import ...` aparecer fora de `src/providers/`, a abstração exigida
pelo `CLAUDE.md` (seção 3) foi furada.
"""

from __future__ import annotations

from .base import EmbeddingProvider, LLMProvider, ProviderError
from .config import EMBEDDING_DIMENSIONS, Settings

# Quantos textos por requisição de embedding.
#
# A API aceita bem mais, mas lotes grandes têm dois custos práticos: uma falha
# de rede joga fora o lote inteiro, e o corpo da requisição cresce sem
# necessidade. Com 5.664 chunks, 128 por lote dá 45 requisições — suficiente
# para não pagar latência por chunk e pequeno o bastante para uma retentativa
# ser barata.
EMBEDDING_BATCH_SIZE = 128


class OpenAIEmbeddingProvider(EmbeddingProvider):
    """Embeddings via `client.embeddings.create`."""

    name = "openai"

    def __init__(self, settings: Settings) -> None:
        if not settings.openai_api_key:
            raise ProviderError(
                "EMBEDDING_PROVIDER=openai exige OPENAI_API_KEY preenchida no .env."
            )

        self.model = settings.openai_embedding_model
        if self.model not in EMBEDDING_DIMENSIONS:
            raise ProviderError(
                f"Dimensão desconhecida para o modelo de embedding '{self.model}'. "
                f"Modelos conhecidos: {', '.join(sorted(EMBEDDING_DIMENSIONS))}. "
                "Acrescente o modelo em EMBEDDING_DIMENSIONS (src/providers/config.py)."
            )
        self.dimensions = EMBEDDING_DIMENSIONS[self.model]

        from openai import OpenAI

        self._client = OpenAI(api_key=settings.openai_api_key)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        vectors: list[list[float]] = []
        for start in range(0, len(texts), EMBEDDING_BATCH_SIZE):
            batch = texts[start : start + EMBEDDING_BATCH_SIZE]
            response = self._client.embeddings.create(model=self.model, input=batch)
            # A API documenta a ordem preservada, mas o campo `index` existe
            # justamente para não depender disso — ordenar é barato e remove a
            # classe inteira de bug "vetor associado ao chunk errado".
            ordered = sorted(response.data, key=lambda item: item.index)
            vectors.extend(item.embedding for item in ordered)

        return self._validate_dimensions(vectors)

    def embed_query(self, text: str) -> list[float]:
        # Na OpenAI pergunta e documento usam a mesma chamada — a distinção
        # existe no contrato por causa da Voyage (ver `base.py`).
        return self.embed_documents([text])[0]


class OpenAILLMProvider(LLMProvider):
    """Geração de texto via Responses API."""

    name = "openai"

    def __init__(self, settings: Settings) -> None:
        if not settings.openai_api_key:
            raise ProviderError("LLM_PROVIDER=openai exige OPENAI_API_KEY preenchida no .env.")

        self.model = settings.openai_llm_model

        from openai import OpenAI

        self._client = OpenAI(api_key=settings.openai_api_key)

    def generate(self, system: str, prompt: str, max_tokens: int = 2048) -> str:
        response = self._client.chat.completions.create(
            model=self.model,
            max_completion_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content or ""
