"""Implementação Anthropic: apenas geração.

Não há `AnthropicEmbeddingProvider` neste módulo, e a ausência é deliberada: a
Anthropic não expõe uma API de embeddings própria. O caminho que eles
recomendam é a Voyage AI, implementada em `voyage_provider.py` como um provedor
de embedding próprio, com chave própria (`VOYAGE_API_KEY`).

A alternativa seria criar um `AnthropicEmbeddingProvider` que por baixo chama a
Voyage. Foi descartada: o nome mentiria sobre qual serviço recebe o texto e
qual chave é cobrada. Um provedor por serviço mantém a configuração honesta.

Este é um dos poucos módulos autorizados a importar o SDK da Anthropic.
"""

from __future__ import annotations

from .base import Generation, LLMProvider, ProviderError
from .config import Settings


class AnthropicLLMProvider(LLMProvider):
    """Geração de texto via Messages API."""

    name = "anthropic"

    def __init__(self, settings: Settings, model: str | None = None) -> None:
        if not settings.anthropic_api_key:
            raise ProviderError(
                "LLM_PROVIDER=anthropic exige ANTHROPIC_API_KEY preenchida no .env."
            )

        # `model` sobrescreve o `.env` quando a escolha vem da requisição (o
        # seletor da interface) ou da linha de comando. Sem escolha explícita,
        # o padrão continua sendo o do ambiente.
        self.model = model or settings.anthropic_llm_model

        import anthropic

        self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    def generate(self, system: str, prompt: str, max_tokens: int = 2048) -> Generation:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        # `content` é uma lista de blocos tipados; só os de texto interessam
        # aqui. Indexar `content[0].text` direto quebraria se a resposta viesse
        # com um bloco de outro tipo à frente.
        text = "".join(block.text for block in response.content if block.type == "text")

        return Generation(
            text=text,
            truncated=response.stop_reason == "max_tokens",
            stop_reason=response.stop_reason,
        )
