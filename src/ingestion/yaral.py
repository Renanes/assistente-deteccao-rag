"""Parser das regras YARA-L da comunidade Google SecOps.

Fonte: https://github.com/chronicle/detection-rules

Diferente das outras duas fontes, YARA-L não é YAML — é uma linguagem própria,
com um bloco `meta:` de pares `chave = "valor"` e seções `events:`/`match:`/
`outcome:`/`condition:` com a lógica. Por isso este módulo tem um parser
textual próprio em vez de reaproveitar PyYAML.

O parser é deliberadamente tolerante: extrai o bloco `meta:` e o corpo da
regra sem tentar validar a gramática YARA-L completa. Validar sintaxe não é
objetivo deste projeto — o objetivo é recuperar título, descrição, metadados e
o texto da lógica para citação.
"""

from __future__ import annotations

import re
from pathlib import Path

from .normalize import (
    collapse_whitespace,
    extract_mitre_tactics,
    extract_mitre_techniques,
    infer_platforms,
    normalize_platform,
    normalize_severity,
)
from .schema import DetectionRule, QueryLanguage, RuleSource

GITHUB_BLOB_BASE = "https://github.com/chronicle/detection-rules/blob/main"

# `rule <identificador>` — a chave `{` pode estar na mesma linha ou na seguinte.
_RULE_HEADER_RE = re.compile(r"^\s*rule\s+([A-Za-z_]\w*)\s*\{?\s*$", re.MULTILINE)
# Par `chave = "valor"` dentro do bloco meta.
_META_PAIR_RE = re.compile(r'^\s*(\w+)\s*=\s*"(.*)"\s*,?\s*$')
# Início de qualquer seção da regra (`meta:`, `events:`, `condition:`, ...).
_SECTION_RE = re.compile(r"^\s*(meta|events|match|outcome|condition|options)\s*:\s*$")

# Chaves de meta que podem carregar um ID ATT&CK, em qualquer formato.
_MITRE_META_KEYS = (
    "mitre",
    "mitre_attack_technique",
    "mitre_attack_technique_id",
    "mitre_attack_tactic",
    "mitre_attack_url",
    "technique",
    "tactic",
)
# Chaves de meta que indicam plataforma/telemetria.
_PLATFORM_META_KEYS = ("platform", "product", "data_source", "service")


def parse_yaral_rule(path: Path, repo_root: Path) -> DetectionRule | None:
    """Converte um arquivo `.yaral` para o schema comum.

    Retorna `None` se o arquivo não tiver um cabeçalho `rule <nome>` — há
    arquivos auxiliares (listas de referência, READMEs renomeados) na árvore.
    """
    raw = path.read_text(encoding="utf-8", errors="replace")
    return parse_yaral_text(raw, path.relative_to(repo_root).as_posix())


def parse_yaral_text(raw: str, relative_path: str) -> DetectionRule | None:
    """Mesma conversão, a partir do conteúdo em memória (ver `sigma.parse_sigma_text`)."""
    header = _RULE_HEADER_RE.search(raw)
    if not header:
        return None
    rule_identifier = header.group(1)

    meta = _parse_meta_block(raw)

    # `rule_name` é o título legível quando existe; senão, o identificador
    # snake_case vira título ("dns_lookup_exact" -> "Dns Lookup Exact").
    title = _first(meta, "rule_name") or rule_identifier.replace("_", " ").title()

    # `rule_id` só existe em parte das regras — o identificador do arquivo é o
    # fallback estável (é único no repositório, já que nomeia a regra).
    native_id = _first(meta, "rule_id") or rule_identifier

    mitre_texts = [value for key in _MITRE_META_KEYS for value in meta.get(key, [])]
    platform_texts = [value for key in _PLATFORM_META_KEYS for value in meta.get(key, [])]

    return DetectionRule(
        rule_uid=f"{RuleSource.YARA_L.value}:{native_id}",
        source=RuleSource.YARA_L,
        native_id=native_id,
        source_path=relative_path,
        source_url=f"{GITHUB_BLOB_BASE}/{relative_path}",
        title=collapse_whitespace(title),
        description=collapse_whitespace(" ".join(meta.get("description", []))),
        false_positives=[
            collapse_whitespace(value) for value in meta.get("assumption", []) if value.strip()
        ],
        query=_extract_logic(raw),
        query_language=QueryLanguage.YARA_L,
        platforms=_platforms(platform_texts),
        mitre_techniques=extract_mitre_techniques(mitre_texts),
        mitre_tactics=extract_mitre_tactics(mitre_texts) or _tactic_names(meta),
        data_sources=meta.get("data_source", []),
        tags=_tags(meta),
        author=collapse_whitespace(" ".join(meta.get("author", []))) or None,
        status=_first(meta, "type"),
        severity=normalize_severity(_first(meta, "severity")),
        references=[
            value
            for key in ("reference", "mitre_attack_url")
            for value in meta.get(key, [])
            if value.startswith("http")
        ],
    )


def _parse_meta_block(raw: str) -> dict[str, list[str]]:
    """Extrai os pares `chave = "valor"` do bloco `meta:`.

    Devolve `dict[str, list[str]]` porque chaves se repetem legitimamente —
    `reference` costuma aparecer várias vezes na mesma regra.
    """
    meta: dict[str, list[str]] = {}
    inside_meta = False

    for line in raw.splitlines():
        section = _SECTION_RE.match(line)
        if section:
            # Qualquer outra seção encerra o bloco meta.
            inside_meta = section.group(1) == "meta"
            continue
        if not inside_meta:
            continue
        if pair := _META_PAIR_RE.match(line):
            key, value = pair.group(1).lower(), pair.group(2).strip()
            if value:
                meta.setdefault(key, []).append(value)

    return meta


def _extract_logic(raw: str) -> str:
    """Recorta a lógica de detecção: de `events:` até o fim da regra.

    O cabeçalho de licença e o bloco `meta:` ficam de fora de propósito — já
    estão representados nos campos narrativos, e repeti-los na query só
    gastaria contexto do prompt na Fase 5 sem acrescentar informação.
    """
    lines = raw.splitlines()
    start: int | None = None

    for index, line in enumerate(lines):
        section = _SECTION_RE.match(line)
        if section and section.group(1) == "events":
            start = index
            break

    if start is None:
        return ""

    logic = "\n".join(lines[start:]).rstrip()
    # A chave de fechamento da regra não acrescenta nada sem a de abertura.
    if logic.endswith("}"):
        logic = logic[:-1].rstrip()
    return logic


def _platforms(platform_texts: list[str]) -> list[str]:
    """Normaliza plataformas declaradas, caindo para inferência por palavra-chave.

    `platform`/`product` costumam trazer o valor limpo ("windows"), mas
    `data_source` é texto livre ("microsoft ad, azure ad, okta") — daí as duas
    estratégias em sequência.
    """
    platforms: dict[str, None] = {}
    for text in platform_texts:
        for candidate in re.split(r"[,;/]", text):
            if normalized := normalize_platform(candidate):
                platforms.setdefault(normalized, None)

    if not platforms:
        for inferred in infer_platforms(platform_texts):
            platforms.setdefault(inferred, None)

    return list(platforms)


def _tags(meta: dict[str, list[str]]) -> list[str]:
    """Monta tags a partir dos eixos de classificação do YARA-L."""
    tags: list[str] = []
    for key in ("tags", "category", "priority"):
        for value in meta.get(key, []):
            tags.extend(part.strip() for part in value.split(",") if part.strip())
    return tags


def _tactic_names(meta: dict[str, list[str]]) -> list[str]:
    """Usa nomes de tática quando a regra não declara o ID TAxxxx."""
    return [
        collapse_whitespace(value)
        for key in ("mitre_attack_tactic", "tactic")
        for value in meta.get(key, [])
        if value.strip() and not value.upper().startswith("TA")
    ]


def _first(meta: dict[str, list[str]], key: str) -> str | None:
    values = meta.get(key)
    return values[0] if values else None
