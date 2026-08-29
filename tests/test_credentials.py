"""Testes da camada de chaves trazidas por quem usa.

Este é código de segurança, e as propriedades que ele precisa ter não falham
de forma visível quando quebram — falham vazando credencial. Os três riscos
que estes testes cobrem:

1. **A chave de um visitante vazar para outro.** Aconteceria se `apply_keys`
   mutasse o `Settings` compartilhado, ou se um provedor construído com chave
   de visitante entrasse no cache que as requisições compartilham.
2. **A chave voltar numa resposta HTTP.** Aconteceria por mensagem de erro de
   SDK repassada crua, ou por um endpoint de diagnóstico "conveniente" demais.
3. **A chave não chegar.** Menos grave, mas é o que produz "minha chave não
   funciona" sem erro nenhum: cabeçalho com nome divergente entre as pontas.
"""

from __future__ import annotations

import pytest

from src.api.credentials import (
    MAX_KEY_LENGTH,
    PROVIDER_HEADERS,
    PROVIDER_ROLES,
    PROVIDER_SETTINGS_FIELD,
    InvalidKeyError,
    apply_keys,
    keys_from_headers,
    redact,
)
from src.providers import Settings

FAKE = {
    "anthropic": "sk-ant-api03-chave-falsa-de-teste-0123456789",
    "openai": "sk-proj-chave-falsa-de-teste-0123456789",
    "voyage": "pa-chave-falsa-de-teste-0123456789",
}


def make_settings(**overrides: object) -> Settings:
    isolated: dict[str, object] = {
        "anthropic_api_key": "",
        "openai_api_key": "",
        "voyage_api_key": "",
    }
    isolated.update(overrides)
    return Settings(_env_file=None, **isolated)  # type: ignore[arg-type]


# ------------------------------------------------ isolamento entre visitantes


def test_apply_keys_never_mutates_the_shared_settings() -> None:
    """`Runtime.settings` é lido por toda requisição.

    Se `apply_keys` escrevesse nele, a chave de um visitante passaria a valer
    para os seguintes — e a conta dele pagaria as perguntas dos outros. É o
    modo de falha mais grave deste desenho e não tem sintoma visível.
    """
    compartilhado = make_settings()
    efetivo = apply_keys(compartilhado, {"openai": FAKE["openai"]})

    assert compartilhado.openai_api_key == "", "o Settings compartilhado foi mutado"
    assert efetivo.openai_api_key == FAKE["openai"]
    assert efetivo is not compartilhado


def test_apply_keys_without_keys_returns_the_same_object() -> None:
    """Sem chave de visitante, o caminho é o de sempre — sem cópia inútil."""
    compartilhado = make_settings(openai_api_key="do-env")
    assert apply_keys(compartilhado, {}) is compartilhado


def test_visitor_key_overrides_the_env_key_only_for_that_copy() -> None:
    compartilhado = make_settings(openai_api_key="chave-do-env")
    efetivo = apply_keys(compartilhado, {"openai": FAKE["openai"]})

    assert efetivo.openai_api_key == FAKE["openai"]
    assert compartilhado.openai_api_key == "chave-do-env"


def test_providers_built_with_a_visitor_key_are_not_cached() -> None:
    """O cache de provedores é compartilhado entre requisições.

    Guardar ali um cliente construído com a chave de um visitante o entregaria
    ao próximo. O teste exercita `_providers_for` pelo caminho com chave e
    exige que o cache não tenha crescido.
    """
    from src.api import main

    main.runtime.settings = make_settings()
    main.runtime.llm = None
    main.runtime.embedding = None
    main.runtime.llm_by_model = {}

    # Chave falsa basta: os SDKs não chamam a rede ao construir o cliente.
    embedding, llm = main._providers_for({"openai": FAKE["openai"]}, "gpt-5.4-mini")

    assert embedding is not None and llm is not None
    assert main.runtime.llm_by_model == {}, "provedor com chave de visitante foi cacheado"
    assert main.runtime.llm is None and main.runtime.embedding is None


# ------------------------------------------------------ a chave não pode voltar


@pytest.mark.parametrize("provider", sorted(FAKE))
def test_redact_removes_key_shapes(provider: str) -> None:
    """Mensagem de erro de SDK viaja para a resposta HTTP."""
    chave = FAKE[provider]
    limpo = redact(f"AuthenticationError: chave invalida {chave} recusada")

    assert chave not in limpo
    assert "[chave redigida]" in limpo
    assert "AuthenticationError" in limpo, "a redação não pode comer a mensagem inteira"


def test_redact_leaves_ordinary_text_alone() -> None:
    texto = "banco indisponível: connection refused em 127.0.0.1:5432"
    assert redact(texto) == texto


def test_redact_handles_bearer_headers() -> None:
    limpo = redact("Authorization: Bearer abcdef0123456789 rejeitado")
    assert "abcdef0123456789" not in limpo


@pytest.mark.parametrize("provider", sorted(FAKE))
def test_validation_errors_never_echo_the_key(provider: str) -> None:
    """A mensagem de recusa não pode conter o valor recebido.

    Ela vai para a resposta HTTP e possivelmente para um log — repetir a chave
    ali anularia o cuidado de não persisti-la.
    """
    corrompida = FAKE[provider][:10] + "\n" + FAKE[provider][10:]
    with pytest.raises(InvalidKeyError) as erro:
        keys_from_headers({PROVIDER_HEADERS[provider]: corrompida})

    assert FAKE[provider] not in str(erro.value)
    assert corrompida not in str(erro.value)


# ------------------------------------------------------- extração e validação


def test_headers_carry_every_provider() -> None:
    """Os três provedores precisam de cabeçalho e de campo em Settings."""
    assert set(PROVIDER_HEADERS) == set(PROVIDER_SETTINGS_FIELD) == set(PROVIDER_ROLES)
    assert all(header == header.lower() for header in PROVIDER_HEADERS.values())


def test_roles_cover_both_stages_of_the_pipeline() -> None:
    """Alguém precisa cobrir embedding e alguém precisa cobrir geração.

    Se nenhum provedor declarasse "embedding", a interface nunca conseguiria
    dizer a quem trouxe só chave da Anthropic por que a consulta não roda.
    """
    papeis = {papel for lista in PROVIDER_ROLES.values() for papel in lista}
    assert papeis == {"embedding", "geração"}
    # A Anthropic não tem API de embeddings — decisão da Fase 3.
    assert PROVIDER_ROLES["anthropic"] == ["geração"]


def test_keys_are_extracted_from_the_declared_headers() -> None:
    headers = {PROVIDER_HEADERS[provider]: chave for provider, chave in FAKE.items()}
    assert keys_from_headers(headers) == FAKE


def test_absent_or_empty_headers_are_not_an_error() -> None:
    """Cabeçalho ausente significa "use o `.env`", que é o caso normal."""
    assert keys_from_headers({}) == {}
    assert keys_from_headers({PROVIDER_HEADERS["openai"]: "   "}) == {}


@pytest.mark.parametrize("volta", ["  {}  ", "{}\n", "\r\n{}\r\n", "\t{}"])
def test_whitespace_around_a_pasted_key_is_trimmed_not_refused(volta: str) -> None:
    """Colar uma chave costuma trazer espaço e quebra de linha junto.

    Recusar por isso seria hostil sem ganhar segurança nenhuma: o valor é o
    mesmo. O que não pode passar é caractere de controle no *meio* da chave —
    ver o teste abaixo.
    """
    extraida = keys_from_headers({PROVIDER_HEADERS["openai"]: volta.format(FAKE["openai"])})
    assert extraida["openai"] == FAKE["openai"]


@pytest.mark.parametrize("ruim", ["curta", "x" * (MAX_KEY_LENGTH + 1)])
def test_keys_outside_the_length_range_are_refused(ruim: str) -> None:
    with pytest.raises(InvalidKeyError):
        keys_from_headers({PROVIDER_HEADERS["openai"]: ruim})


@pytest.mark.parametrize("controle", ["\n", "\r", "\x00", "\x1b", "\x7f"])
def test_control_characters_inside_the_key_are_refused(controle: str) -> None:
    """Controle no meio da chave é corrupção ou tentativa de injeção.

    Não dá para aparar: o valor está errado. Recusar com mensagem é melhor que
    deixar a chamada ao provedor falhar de um jeito que não aponta para a causa.
    """
    corrompida = FAKE["openai"][:10] + controle + FAKE["openai"][10:]
    with pytest.raises(InvalidKeyError):
        keys_from_headers({PROVIDER_HEADERS["openai"]: corrompida})


@pytest.mark.parametrize("controle", ["\x00", "\x1b", "\x7f"])
def test_trailing_control_characters_that_are_not_whitespace_are_refused(controle: str) -> None:
    """`strip()` só apara espaço em branco — o resto continua sendo recusa."""
    with pytest.raises(InvalidKeyError):
        keys_from_headers({PROVIDER_HEADERS["openai"]: FAKE["openai"] + controle})


def test_unknown_headers_are_ignored() -> None:
    assert keys_from_headers({"x-api-key-gemini": "sk-qualquer-coisa-longa"}) == {}
