"""Extrai da pergunta do analista os sinais que viram filtro e busca lexical.

A pergunta chega como texto livre ("tem regra pra T1055 no Windows?"). Três
sinais diferentes saem daí, e cada um alimenta uma perna diferente da busca
híbrida:

- **Técnica ATT&CK** vira filtro rígido. Se o analista digitou `T1055`, uma
  regra de `T1027` está errada por mais parecida que o vetor a considere.
- **Plataforma** vira filtro rígido pelo mesmo motivo.
- **Termos lexicais** viram a consulta de full-text, que existe para casar
  identificador exato (`4688`, `mimikatz`, `rundll32`) — justamente o que o
  embedding borra.

O que *não* sai daqui é a busca semântica: essa usa a pergunta inteira, sem
processamento, porque é para isso que o embedding serve.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from ..ingestion.normalize import infer_platforms
from ..ingestion.schema import MITRE_TECHNIQUE_RE

# Stopwords em português.
#
# Só as portuguesas: a coluna `search_text` usa a configuração `english` do
# Postgres, que já descarta as stopwords inglesas sozinha. As do português
# passariam batido e virariam ruído numa consulta OR — "como" e "detectar" não
# ajudam a encontrar regra nenhuma.
_PORTUGUESE_STOPWORDS = frozenset(
    """
    a as ao aos com como da das de do dos e em entre essa esse esta este eu foi
    for há isso isto já la lhe mais mas me mesmo meu minha muito na nas nem no
    nos nossa nosso num numa o os ou para pela pelas pelo pelos por qual quando
    que quem se sem ser seu sua são só tem ter teu tua um uma vos à às é
    detectar detecta deteccao detecção regra regras alguma algum tenho quero
    preciso existe existem sobre quais qual mostrar mostre ache achar encontrar
    """.split()
)

# Tokens aproveitáveis para full-text: letras, dígitos, ponto, hífen e
# underscore. O recorte é deliberadamente conservador porque o resultado vai
# montar um `to_tsquery`, que é sensível a pontuação solta.
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

# Comprimento mínimo de um termo lexical que não seja identificador óbvio.
# Abaixo disso ("os", "de", "id") o termo casa com meio corpus e só polui.
_MIN_TERM_LENGTH = 4


class ParsedQuery(BaseModel):
    """Os sinais extraídos de uma pergunta."""

    text: str = Field(description="A pergunta original, usada inteira no embedding.")
    mitre_techniques: list[str] = Field(
        default_factory=list, description="IDs ATT&CK citados explicitamente."
    )
    platforms: list[str] = Field(
        default_factory=list, description="Plataformas do vocabulário controlado."
    )
    lexical_terms: list[str] = Field(
        default_factory=list, description="Termos de alto sinal para o full-text."
    )

    @property
    def has_filters(self) -> bool:
        return bool(self.mitre_techniques or self.platforms)


def _is_high_signal(token: str) -> bool:
    """Decide se um token merece entrar na consulta de full-text.

    O full-text aqui não é para fazer trabalho semântico — é para casar termo
    exato que o vetor borra. Então o critério favorece o que parece
    identificador: mistura de letra e dígito (`T1055`, `4688`,
    `ProcessRollup2`), nome pontuado (`kube-apiserver`, `os.path`), ou uma
    palavra longa que não é stopword (`mimikatz`, `powershell`).
    """
    lowered = token.lower()
    if lowered in _PORTUGUESE_STOPWORDS:
        return False

    has_digit = any(character.isdigit() for character in token)
    has_alpha = any(character.isalpha() for character in token)
    if has_digit and has_alpha:
        return True
    if has_digit and len(token) >= 3:  # IDs de evento: "4688", "1102"
        return True
    if any(separator in token for separator in "._-"):
        return True

    return len(token) >= _MIN_TERM_LENGTH


def _looks_like_identifier(token: str) -> bool:
    """Token com forma de identificador, não de palavra corrente.

    Critério mais estreito que `_is_high_signal`: exige dígito, pontuação
    interna ou maiúscula no meio (`T1055`, `CVE-2022-42889`, `tttracer.exe`,
    `DontShowUI`). Palavra comum longa não passa.
    """
    if any(character.isdigit() for character in token):
        return True
    if any(separator in token for separator in "._-"):
        return True
    return any(character.isupper() for character in token[1:])


def extract_lexical_terms(text: str, identifiers_only: bool = False) -> list[str]:
    """Termos de alto sinal, sem repetição, na ordem em que aparecem.

    Com `identifiers_only`, aceita apenas tokens com forma de identificador.
    A medição da Fase 6 mostrou que palavras correntes longas ("conexao",
    "identificar", "ferramenta") viravam ruído na consulta OR e empurravam a
    regra certa para baixo — ver `eval/results.md`.
    """
    predicate = _looks_like_identifier if identifiers_only else _is_high_signal
    found: dict[str, None] = {}
    for token in _TOKEN_RE.findall(text):
        cleaned = token.strip("._-")
        if cleaned and cleaned.lower() not in _PORTUGUESE_STOPWORDS and predicate(cleaned):
            found.setdefault(cleaned.lower(), None)
    return list(found)


def extract_query_techniques(text: str) -> list[str]:
    """IDs ATT&CK citados na pergunta, canonicalizados para maiúsculas."""
    found: dict[str, None] = {}
    for match in MITRE_TECHNIQUE_RE.findall(text):
        found.setdefault(match.upper(), None)
    return list(found)


def parse_query(
    text: str, infer_platform: bool = True, identifiers_only: bool = False
) -> ParsedQuery:
    """Analisa a pergunta do analista e devolve os sinais de busca."""
    return ParsedQuery(
        text=text,
        mitre_techniques=extract_query_techniques(text),
        # `infer_platforms` é a mesma função da ingestão, de propósito: se
        # "sysmon" mapeia para `windows` ao classificar uma regra, precisa
        # mapear igual ao interpretar a pergunta. Duas tabelas de sinônimos
        # divergiriam com o tempo e o filtro passaria a errar em silêncio.
        platforms=infer_platforms([text]) if infer_platform else [],
        lexical_terms=extract_lexical_terms(text, identifiers_only=identifiers_only),
    )


def build_tsquery(terms: list[str]) -> str:
    """Monta a expressão `to_tsquery` a partir dos termos lexicais.

    Junta com OR, e não com AND: numa pergunta em linguagem natural exigir
    todos os termos não devolveria nada. O ranqueamento fica com o `ts_rank`, e
    a lista resultante entra na fusão como uma entre duas — se vier ruim, o RRF
    limita o estrago (ver `fusion.py`).
    """
    # Os termos já vêm saneados por `_TOKEN_RE`, mas o `:` e o `'` são
    # metacaracteres de tsquery e um deles escapando aqui derrubaria a consulta
    # inteira com erro de sintaxe.
    safe = [term.replace(":", "").replace("'", "") for term in terms]
    return " | ".join(term for term in safe if term)
