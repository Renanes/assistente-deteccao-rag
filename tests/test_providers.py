"""Testes da camada de provedores e das guardas de indexação (Fase 3).

Nada aqui chama a API de ninguém nem abre conexão com o banco. O que está sob
teste é a lógica que decide *qual* provedor usar e as guardas que recusam uma
configuração incoerente — justamente o que, se falhar em silêncio, produz uma
base de vetores inutilizável sem nenhum erro visível.

As `Settings` são construídas com `_env_file=None` **e com as três chaves
explicitamente vazias**. As duas coisas são necessárias: em `pydantic-settings`
a precedência é argumento > variável de ambiente > arquivo `.env` > default,
então zerar só o `.env` não basta — uma `ANTHROPIC_API_KEY` exportada no
ambiente do desenvolvedor continuaria vazando para dentro do teste e faria a
asserção de "chave ausente" passar ou falhar conforme a máquina. Isso não é
hipotético: foi exatamente o que aconteceu na primeira execução destes testes.
"""

from __future__ import annotations

import pytest

from src.embeddings.run import check_index_support, check_model_consistency
from src.embeddings.store import IndexedCorpusInfo
from src.providers import (
    EMBEDDING_DIMENSIONS,
    PGVECTOR_INDEX_MAX_DIMENSIONS,
    EmbeddingProvider,
    ProviderError,
    Settings,
    get_embedding_provider,
    get_llm_provider,
)


def make_settings(**overrides: object) -> Settings:
    """Settings isoladas do `.env` e do ambiente do SO (ver docstring do módulo)."""
    isolated: dict[str, object] = {
        "anthropic_api_key": "",
        "openai_api_key": "",
        "voyage_api_key": "",
    }
    isolated.update(overrides)
    return Settings(_env_file=None, **isolated)  # type: ignore[arg-type]


def test_make_settings_is_not_contaminated_by_the_os_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guarda do próprio harness de teste.

    Se esta asserção quebrar, todos os testes de "chave ausente" abaixo viram
    falso-positivos silenciosos na máquina de quem tiver a variável exportada.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-do-ambiente")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-do-ambiente")

    settings = make_settings()
    assert settings.anthropic_api_key == ""
    assert settings.openai_api_key == ""


# --------------------------------------------------------------------------
# Escolha de provedor
# --------------------------------------------------------------------------


def test_embedding_provider_openai() -> None:
    provider = get_embedding_provider(
        make_settings(embedding_provider="openai", openai_api_key="sk-teste")
    )
    assert provider.name == "openai"
    assert provider.dimensions == 1536


def test_embedding_provider_voyage() -> None:
    provider = get_embedding_provider(
        make_settings(embedding_provider="voyage", voyage_api_key="pa-teste")
    )
    assert provider.name == "voyage"
    assert provider.dimensions == EMBEDDING_DIMENSIONS["voyage-3"]


def test_llm_provider_switches_between_the_two() -> None:
    """O critério de aceite da Fase 5 exige trocar de provedor sem mexer em código."""
    anthropic = get_llm_provider(
        make_settings(llm_provider="anthropic", anthropic_api_key="sk-ant-teste")
    )
    openai = get_llm_provider(make_settings(llm_provider="openai", openai_api_key="sk-teste"))

    assert anthropic.name == "anthropic"
    assert openai.name == "openai"
    assert type(anthropic) is not type(openai)


def test_provider_choice_is_case_and_space_insensitive() -> None:
    provider = get_embedding_provider(
        make_settings(embedding_provider="  OpenAI ", openai_api_key="sk-teste")
    )
    assert provider.name == "openai"


# --------------------------------------------------------------------------
# Erros de configuração
# --------------------------------------------------------------------------


def test_embedding_provider_anthropic_explains_why_it_does_not_exist() -> None:
    """"anthropic" é a resposta intuitiva e errada — o erro precisa ensinar."""
    with pytest.raises(ProviderError) as error:
        get_embedding_provider(
            make_settings(embedding_provider="anthropic", anthropic_api_key="sk-ant-teste")
        )

    message = str(error.value)
    assert "não tem API de embeddings própria" in message
    assert "voyage" in message.lower()
    # Precisa deixar claro que a restrição é só de embedding.
    assert "LLM_PROVIDER=anthropic segue válido" in message


def test_unknown_embedding_provider_lists_the_valid_ones() -> None:
    with pytest.raises(ProviderError, match="desconhecido"):
        get_embedding_provider(make_settings(embedding_provider="cohere"))


def test_unknown_llm_provider_lists_the_valid_ones() -> None:
    with pytest.raises(ProviderError, match="desconhecido"):
        get_llm_provider(make_settings(llm_provider="llama"))


@pytest.mark.parametrize(
    ("overrides", "expected_key"),
    [
        ({"embedding_provider": "openai"}, "OPENAI_API_KEY"),
        ({"embedding_provider": "voyage"}, "VOYAGE_API_KEY"),
    ],
)
def test_missing_key_names_the_variable_to_fill(
    overrides: dict[str, str], expected_key: str
) -> None:
    with pytest.raises(ProviderError, match=expected_key):
        get_embedding_provider(make_settings(**overrides))


def test_missing_anthropic_key_names_the_variable_to_fill() -> None:
    with pytest.raises(ProviderError, match="ANTHROPIC_API_KEY"):
        get_llm_provider(make_settings(llm_provider="anthropic"))


def test_unknown_embedding_model_is_rejected_before_any_call() -> None:
    """Sem dimensão conhecida não há como criar a coluna `vector(N)`."""
    with pytest.raises(ProviderError, match="Dimensão desconhecida"):
        get_embedding_provider(
            make_settings(
                embedding_provider="openai",
                openai_api_key="sk-teste",
                openai_embedding_model="modelo-que-nao-existe",
            )
        )


# --------------------------------------------------------------------------
# Validação de dimensão
# --------------------------------------------------------------------------


class FakeProvider(EmbeddingProvider):
    """Provedor mínimo para exercitar a validação de dimensão."""

    name = "fake"
    model = "fake-model"
    dimensions = 4

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._validate_dimensions([[0.0] * len(text) for text in texts])

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


def test_validate_dimensions_accepts_the_declared_size() -> None:
    provider = FakeProvider()
    assert provider.embed_documents(["abcd"]) == [[0.0, 0.0, 0.0, 0.0]]


def test_validate_dimensions_rejects_a_mismatch() -> None:
    """Um modelo trocado por engano no .env falha aqui, não lá no pgvector."""
    provider = FakeProvider()
    with pytest.raises(ProviderError) as error:
        provider.embed_documents(["abc"])

    assert "3 dimensões" in str(error.value)
    assert "declara 4" in str(error.value)
    assert ".env" in str(error.value)


# --------------------------------------------------------------------------
# Guardas de indexação
# --------------------------------------------------------------------------


class SizedProvider(FakeProvider):
    def __init__(self, dimensions: int, model: str = "fake-model") -> None:
        self.dimensions = dimensions
        self.model = model


def test_index_support_accepts_a_model_under_the_pgvector_limit() -> None:
    check_index_support(SizedProvider(1536))  # text-embedding-3-small


def test_index_support_rejects_a_model_over_the_pgvector_limit() -> None:
    """3072 dimensões (3-large) não entram num índice HNSW — falhar antes de gastar API."""
    assert EMBEDDING_DIMENSIONS["text-embedding-3-large"] > PGVECTOR_INDEX_MAX_DIMENSIONS

    with pytest.raises(ProviderError) as error:
        check_index_support(SizedProvider(3072, "text-embedding-3-large"))

    assert "varredura sequencial" in str(error.value)
    assert "halfvec" in str(error.value)


def test_model_consistency_allows_an_empty_table() -> None:
    check_model_consistency(IndexedCorpusInfo(exists=False), SizedProvider(1536))
    check_model_consistency(
        IndexedCorpusInfo(exists=True, row_count=0), SizedProvider(1536)
    )


def test_model_consistency_allows_reindexing_with_the_same_model() -> None:
    info = IndexedCorpusInfo(
        exists=True, row_count=10, dimensions=1536, models=("text-embedding-3-small",)
    )
    check_model_consistency(info, SizedProvider(1536, "text-embedding-3-small"))


def test_model_consistency_rejects_a_dimension_change() -> None:
    info = IndexedCorpusInfo(
        exists=True, row_count=10, dimensions=1024, models=("voyage-3",)
    )
    with pytest.raises(ProviderError, match="--reset"):
        check_model_consistency(info, SizedProvider(1536, "text-embedding-3-small"))


def test_model_consistency_rejects_mixing_models_of_the_same_size() -> None:
    """Mesma dimensão não significa mesmo espaço vetorial.

    `text-embedding-3-small` e `ada-002` têm 1536 dimensões os dois. Misturá-los
    não dá erro em lugar nenhum — só devolve vizinhos errados.
    """
    info = IndexedCorpusInfo(
        exists=True, row_count=10, dimensions=1536, models=("text-embedding-ada-002",)
    )
    with pytest.raises(ProviderError) as error:
        check_model_consistency(info, SizedProvider(1536, "text-embedding-3-small"))

    assert "não são comparáveis" in str(error.value)


# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------


def test_database_url_is_built_when_absent() -> None:
    settings = make_settings(
        database_url="",
        postgres_user="u",
        postgres_password="p",
        postgres_host="h",
        postgres_port=1234,
        postgres_db="d",
    )
    assert settings.resolved_database_url() == "postgresql://u:p@h:1234/d"


def test_explicit_database_url_wins() -> None:
    settings = make_settings(database_url="postgresql://explicita/aqui")
    assert settings.resolved_database_url() == "postgresql://explicita/aqui"


def test_default_embedding_model_fits_the_pgvector_index_limit() -> None:
    """Trava a decisão de arquitetura: o padrão precisa ser indexável."""
    default_model = make_settings().openai_embedding_model
    assert EMBEDDING_DIMENSIONS[default_model] <= PGVECTOR_INDEX_MAX_DIMENSIONS


# --------------------------------------------------------------------------
# A invariante de arquitetura do projeto
# --------------------------------------------------------------------------


def test_no_provider_sdk_is_imported_outside_the_providers_package() -> None:
    """O requisito central do CLAUDE.md (seção 3), verificado em vez de confiado.

    "Nenhuma outra parte do código deve depender diretamente do SDK de um
    provedor específico — só essa camada." Sem este teste, a regra sobrevive
    enquanto alguém lembrar dela; um `from openai import OpenAI` no pipeline RAG
    da Fase 5 passaria despercebido e o lock-in voltaria pela porta dos fundos.
    """
    import re
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    providers_package = repo_root / "src" / "providers"
    sdk_import = re.compile(r"^\s*(?:from|import)\s+(openai|anthropic|voyageai)\b", re.MULTILINE)

    offenders: list[str] = []
    for path in sorted((repo_root / "src").rglob("*.py")):
        if providers_package in path.parents:
            continue
        for match in sdk_import.finditer(path.read_text(encoding="utf-8")):
            line = path.read_text(encoding="utf-8")[: match.start()].count("\n") + 1
            offenders.append(f"{path.relative_to(repo_root)}:{line} -> {match.group(1)}")

    assert not offenders, (
        "SDK de provedor importado fora de src/providers/: " + "; ".join(offenders)
    )
