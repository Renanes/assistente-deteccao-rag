"""Chaves de API trazidas por quem usa, válidas por requisição.

O modelo é deliberado e a alternativa foi recusada: a chave **nunca toca o
disco do servidor**. Ela vive no `localStorage` do navegador de quem usa, viaja
num cabeçalho por requisição, é usada naquela chamada e descartada. Não vai
para o `.env`, não fica em memória entre requisições, e nenhum endpoint a
devolve.

O motivo é que esta aplicação não tem autenticação — o `CLAUDE.md` (seção 2)
põe auth e multi-tenant fora do escopo da v1. Um endpoint que gravasse a chave
no `.env` seria, sem auth, um jeito de qualquer um que alcance a porta trocar a
chave do operador e gastar o dinheiro dele. Com a chave no navegador, hospedar
a demo publicamente continua seguro: cada visitante traz e paga a própria.

O `.env` do operador continua valendo como padrão. A chave do visitante o
sobrepõe, e só para a requisição dela.

**A regra que não pode ser quebrada:** um provedor construído com chave de
visitante *nunca* entra em cache. O cache de provedores por modelo
(`Runtime.llm_by_model`) existe para reaproveitar conexão HTTP, e guardar ali
um cliente com a chave de um visitante o entregaria ao próximo — a pior falha
possível neste desenho.
"""

from __future__ import annotations

import re
from typing import Mapping

from ..providers.config import Settings

#: Cabeçalho por provedor. Um cabeçalho por chave, e não um único campo
#: composto, porque cada provedor cobre um papel diferente: a chave da OpenAI
#: serve para embedding e geração, a da Anthropic só para geração, a da Voyage
#: só para embedding. Separados, quem traz uma chave só não precisa saber disso.
PROVIDER_HEADERS: dict[str, str] = {
    "anthropic": "x-api-key-anthropic",
    "openai": "x-api-key-openai",
    "voyage": "x-api-key-voyage",
}

#: Campo de `Settings` que cada provedor preenche.
PROVIDER_SETTINGS_FIELD: dict[str, str] = {
    "anthropic": "anthropic_api_key",
    "openai": "openai_api_key",
    "voyage": "voyage_api_key",
}

#: O que a chave de cada provedor habilita. A interface precisa disto para não
#: entregar um app quebrado a quem trouxe só uma chave: uma pergunta vira vetor
#: **antes** de virar resposta, então quem tem só chave da Anthropic não
#: consegue nem consultar — a Anthropic não tem API de embeddings (decisão
#: registrada na Fase 3). Sem esse aviso, o sintoma seria um erro obscuro na
#: primeira pergunta.
PROVIDER_ROLES: dict[str, list[str]] = {
    "anthropic": ["geração"],
    "openai": ["embedding", "geração"],
    "voyage": ["embedding"],
}

MIN_KEY_LENGTH = 8
MAX_KEY_LENGTH = 500

#: Formas de segredo que podem aparecer numa mensagem de erro de SDK. A lista
#: é propositalmente ampla: redigir demais custa legibilidade de log, redigir
#: de menos vaza credencial para dentro de uma resposta HTTP.
_SECRET_SHAPES = re.compile(
    r"""
    (sk-[A-Za-z0-9_\-]{8,})        # OpenAI e Anthropic (sk-, sk-ant-, sk-proj-)
    | (pa-[A-Za-z0-9_\-]{8,})      # Voyage
    | (Bearer\s+[A-Za-z0-9_\-\.]{8,})
    """,
    re.VERBOSE,
)


class InvalidKeyError(ValueError):
    """A chave enviada não tem forma utilizável. Nunca inclui a chave."""


def redact(text: str) -> str:
    """Remove qualquer coisa com forma de segredo de um texto.

    Aplicado nas mensagens de erro que a API devolve. O erro de um SDK viaja
    para a resposta HTTP, e é barato demais garantir que uma credencial não vá
    junto para deixar isso ao acaso.
    """
    return _SECRET_SHAPES.sub("[chave redigida]", text)


def _validate(provider: str, key: str) -> str:
    """Confere a forma da chave. A mensagem nunca ecoa o valor recebido."""
    key = key.strip()

    if not (MIN_KEY_LENGTH <= len(key) <= MAX_KEY_LENGTH):
        raise InvalidKeyError(
            f"A chave de {provider} tem {len(key)} caracteres — fora da faixa "
            f"aceita ({MIN_KEY_LENGTH}–{MAX_KEY_LENGTH}). Confira se colou o valor inteiro."
        )

    # Caractere de controle em cabeçalho é tentativa de injeção ou, muito mais
    # provável, um copiar-e-colar que trouxe quebra de linha junto. Os dois
    # casos merecem recusa com mensagem, não uma chamada que falha estranho.
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in key):
        raise InvalidKeyError(
            f"A chave de {provider} tem caractere de controle (quebra de linha, "
            "provavelmente). Cole apenas o valor da chave."
        )

    return key


def keys_from_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Extrai as chaves de visitante presentes nos cabeçalhos.

    Devolve `{provedor: chave}` só com o que veio preenchido. Cabeçalho ausente
    ou vazio é o caso normal — significa "use o `.env`", não erro.
    """
    found: dict[str, str] = {}
    for provider, header in PROVIDER_HEADERS.items():
        raw = headers.get(header)
        if raw and raw.strip():
            found[provider] = _validate(provider, raw)
    return found


def apply_keys(settings: Settings, keys: Mapping[str, str]) -> Settings:
    """Devolve uma cópia de `Settings` com as chaves do visitante aplicadas.

    Cópia, e nunca mutação do objeto compartilhado: `Runtime.settings` é lido
    por todas as requisições, e escrever nele faria a chave de um visitante
    valer para os outros.
    """
    if not keys:
        return settings

    overrides = {
        PROVIDER_SETTINGS_FIELD[provider]: key
        for provider, key in keys.items()
        if provider in PROVIDER_SETTINGS_FIELD
    }
    return settings.model_copy(update=overrides) if overrides else settings
