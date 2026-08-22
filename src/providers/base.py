"""Interfaces comuns de geração e de embedding.

O `CLAUDE.md` (seção 3) exige que nenhuma outra parte do código dependa do SDK
de um provedor específico. Este módulo é o contrato que sustenta isso: o
retrieval, o pipeline RAG e a API conhecem só as classes abstratas daqui, e a
troca de provedor é uma variável de ambiente, não uma mudança de código.

Duas decisões de forma valem registro:

1. **Geração e embedding são interfaces separadas, escolhidas por variáveis
   independentes.** Não é simetria decorativa: a Anthropic não expõe API de
   embedding própria (o caminho recomendado por eles é a Voyage AI), então o
   par "gerar com uma, embeddar com outra" é o caso normal e não a exceção.
   Uma interface única de provedor forçaria implementações mancas.

2. **`embed_documents` e `embed_query` são métodos distintos**, mesmo sendo
   idênticos na OpenAI. A Voyage distingue `input_type="document"` de
   `"query"` e a qualidade de retrieval piora sem essa distinção; se o contrato
   tivesse um método só, o provedor da Voyage teria que adivinhar o contexto da
   chamada.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ProviderError(RuntimeError):
    """Falha de configuração ou de chamada de um provedor.

    Existe para que quem chama distinga um erro nosso (chave ausente, provedor
    desconhecido, dimensão inesperada) de um erro do SDK do provedor.
    """


class EmbeddingProvider(ABC):
    """Gera vetores para o texto dos chunks e para a pergunta do analista."""

    #: Nome curto do provedor, como aparece em `EMBEDDING_PROVIDER`.
    name: str
    #: Identificador do modelo, gravado junto com o vetor no banco.
    model: str
    #: Dimensão do vetor. Precisa ser conhecida antes da primeira chamada,
    #: porque é o que define a coluna `vector(N)` no schema do pgvector.
    dimensions: int

    @abstractmethod
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Embeda textos do corpus, na mesma ordem em que foram passados."""

    @abstractmethod
    def embed_query(self, text: str) -> list[float]:
        """Embeda uma pergunta de busca."""

    def _validate_dimensions(self, vectors: list[list[float]]) -> list[list[float]]:
        """Confere que o provedor devolveu a dimensão que este objeto declara.

        Sem essa checagem, um modelo trocado por engano no `.env` produziria um
        erro de inserção obscuro lá no pgvector, a milhares de linhas de
        distância da causa — ou pior, passaria batido e envenenaria o índice.
        """
        for vector in vectors:
            if len(vector) != self.dimensions:
                raise ProviderError(
                    f"{self.name}/{self.model} devolveu vetor de {len(vector)} "
                    f"dimensões, mas o provedor declara {self.dimensions}. "
                    "Confira o modelo configurado no .env."
                )
        return vectors


class LLMProvider(ABC):
    """Gera a resposta em linguagem natural a partir do contexto recuperado."""

    #: Nome curto do provedor, como aparece em `LLM_PROVIDER`.
    name: str
    #: Identificador do modelo, para registrar em log e na avaliação.
    model: str

    @abstractmethod
    def generate(self, system: str, prompt: str, max_tokens: int = 2048) -> str:
        """Devolve o texto gerado para um par (instrução de sistema, pergunta).

        `system` é separado de `prompt` porque os dois provedores tratam a
        instrução de sistema como campo próprio, e é nela que a Fase 5 vai
        ancorar a regra de não responder fora do contexto recuperado.
        """
