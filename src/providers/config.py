"""Configuração de provedores e de banco, lida do ambiente.

Uma fonte única de verdade para o que o `.env` define. O resto do código pede a
configuração aqui em vez de ler `os.environ` espalhado — assim uma variável
faltando falha num lugar só, com mensagem útil, e não no meio de um batch de
embedding.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]

# Dimensão do vetor de cada modelo de embedding suportado.
#
# Fica numa tabela em vez de ser descoberto com uma chamada de sondagem porque a
# dimensão é necessária *antes* da primeira chamada: é ela que define a coluna
# `vector(N)` do schema. O valor é conferido contra a resposta real na primeira
# chamada (`EmbeddingProvider._validate_dimensions`), então um erro aqui aparece
# como erro claro e não como índice envenenado.
EMBEDDING_DIMENSIONS: dict[str, int] = {
    # OpenAI
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
    "text-embedding-ada-002": 1536,
    # Voyage AI (caminho recomendado pela Anthropic para embeddings)
    "voyage-3": 1024,
    "voyage-3-lite": 512,
    "voyage-3-large": 1024,
    "voyage-code-3": 1024,
}

# Teto de dimensão dos índices HNSW e IVFFlat do pgvector.
#
# O tipo `vector` armazena até 16.000 dimensões, mas os índices aproximados
# param em 2.000. Acima disso a busca vetorial vira varredura sequencial sobre
# o corpus inteiro. É por isso que o padrão do projeto é o `text-embedding-
# 3-small` (1536) e não o `3-large` (3072).
PGVECTOR_INDEX_MAX_DIMENSIONS = 2000


class Settings(BaseSettings):
    """Variáveis de ambiente do projeto, validadas na leitura."""

    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Escolha de provedor ---
    llm_provider: str = "openai"
    embedding_provider: str = "openai"

    # --- Chaves (nenhuma é obrigatória: só a do provedor escolhido) ---
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    voyage_api_key: str = ""

    # --- Modelos ---
    # Estes são apenas os *padrões*: a interface e o `--model` do CLI escolhem
    # por requisição dentro do catálogo (`src/providers/catalog.py`).
    anthropic_llm_model: str = "claude-opus-5"
    openai_llm_model: str = "gpt-5.4-mini"
    openai_embedding_model: str = "text-embedding-3-small"
    voyage_embedding_model: str = "voyage-3"

    # --- Banco ---
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "detection_rag"
    postgres_user: str = "detection_rag"
    postgres_password: str = ""
    database_url: str = ""

    # --- API (Fase 7) ---
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # --- Retrieval ---
    retrieval_top_k: int = Field(default=5, ge=1)

    # --- Descoberta de novas regras (src/discovery/) ---
    #
    # Opcional, e opcional de verdade: sem token a descoberta usa a árvore do
    # repositório, que a API pública serve a 60 requisições por hora e por IP.
    # Com token, o teto sobe e a busca de código do GitHub — que é autenticada —
    # passa a procurar dentro do conteúdo dos arquivos, não só no nome deles.
    # Um token de leitura pública (`public_repo`, ou nenhum escopo) basta.
    github_token: str = ""

    def has_key_for(self, provider: str) -> bool:
        """Se há chave configurada para um provedor de geração.

        O seletor de modelos usa isto para mostrar como indisponível o que não
        tem chave, em vez de deixar a escolha falhar só na hora de perguntar.
        """
        return bool(
            {
                "anthropic": self.anthropic_api_key,
                "openai": self.openai_api_key,
            }.get(provider, "")
        )

    def resolved_database_url(self) -> str:
        """Devolve a URL de conexão, montando-a se não vier pronta do ambiente.

        O `.env` traz `DATABASE_URL` já montada por conveniência, mas manter o
        fallback evita que mudar só a porta no `.env` (e esquecer a URL) aponte
        silenciosamente para o banco errado.
        """
        if self.database_url:
            return self.database_url
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


def get_settings() -> Settings:
    """Carrega a configuração do `.env` na raiz do repositório."""
    return Settings()
