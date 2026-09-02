"""Parser das regras do SigmaHQ (https://github.com/SigmaHQ/sigma).

Formato: um arquivo YAML por regra, com `detection`/`condition` estruturados em
vez de uma string de query. A lógica de detecção é serializada de volta para
YAML aqui — é assim que um analista lê uma regra Sigma, e é o formato que faz
sentido citar na resposta do RAG.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .normalize import (
    as_str_list,
    collapse_whitespace,
    extract_mitre_tactics,
    extract_mitre_techniques,
    normalize_platform,
    normalize_severity,
)
from .schema import DetectionRule, QueryLanguage, RuleSource

GITHUB_BLOB_BASE = "https://github.com/SigmaHQ/sigma/blob/master"

# Diretórios de primeiro nível sob `rules/` que já indicam a plataforma. Serve
# de fallback quando `logsource.product` está ausente (regras organizadas por
# categoria, como `rules/category/`, não declaram produto).
_DIR_PLATFORM_HINTS = {
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
    "network": "network",
    "web": "web",
    "cloud": None,  # ambíguo: cloud/aws, cloud/azure, ... — resolvido pelo subdiretório
}


def parse_sigma_rule(path: Path, repo_root: Path) -> DetectionRule | None:
    """Converte um arquivo de regra Sigma para o schema comum.

    Retorna `None` para arquivos YAML que não são regras (sem `title` ou `id`),
    como os arquivos de configuração e de metadados espalhados no repositório.
    """
    raw = path.read_text(encoding="utf-8", errors="replace")
    return parse_sigma_text(raw, path.relative_to(repo_root).as_posix())


def parse_sigma_text(raw: str, relative_path: str) -> DetectionRule | None:
    """Mesma conversão, a partir do conteúdo em memória.

    Separado do caminho de arquivo porque a descoberta (`src/discovery/`) lê a
    regra do GitHub, não do disco. Uma segunda implementação do parser para o
    caminho de rede divergiria da do disco na primeira correção — e a
    divergência apareceria como metadado diferente para a mesma regra conforme
    de onde ela veio.
    """
    try:
        document: Any = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None

    if not isinstance(document, dict):
        return None

    title = document.get("title")
    native_id = document.get("id")
    if not title or not native_id:
        return None

    tags = as_str_list(document.get("tags"))

    # Tags do Sigma carregam ATT&CK no formato `attack.t1055.001` /
    # `attack.defense_evasion`. As técnicas saem por regex; as táticas vêm por
    # nome (o Sigma não usa IDs TAxxxx), então preservamos o nome legível.
    mitre_techniques = extract_mitre_techniques(tags)
    mitre_tactics = extract_mitre_tactics(tags) or _tactic_names_from_tags(tags)

    logsource = document.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {}

    return DetectionRule(
        rule_uid=f"{RuleSource.SIGMA.value}:{native_id}",
        source=RuleSource.SIGMA,
        native_id=str(native_id),
        source_path=relative_path,
        source_url=f"{GITHUB_BLOB_BASE}/{relative_path}",
        title=collapse_whitespace(str(title)),
        description=collapse_whitespace(str(document.get("description") or "")),
        false_positives=[
            collapse_whitespace(item) for item in as_str_list(document.get("falsepositives"))
        ],
        query=_serialize_detection(document),
        query_language=QueryLanguage.SIGMA,
        platforms=_platforms(logsource, relative_path),
        mitre_techniques=mitre_techniques,
        mitre_tactics=mitre_tactics,
        data_sources=_data_sources(logsource),
        tags=tags,
        author=collapse_whitespace(str(document.get("author") or "")) or None,
        status=str(document.get("status")) if document.get("status") else None,
        severity=normalize_severity(document.get("level")),
        references=as_str_list(document.get("references")),
    )


def _serialize_detection(document: dict[str, Any]) -> str:
    """Reserializa o bloco `detection` (mais `logsource`) como YAML legível.

    Guardar o bloco estruturado como texto — em vez de um resumo — é o que
    permite ao RAG mostrar a lógica exata da regra citada.
    """
    payload = {
        key: document[key] for key in ("logsource", "detection") if key in document
    }
    if not payload:
        return ""
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=100).strip()


def _platforms(logsource: dict[str, Any], relative_path: str) -> list[str]:
    """Deriva plataformas de `logsource.product`, caindo para o caminho do arquivo."""
    platforms: list[str] = []
    for key in ("product", "service"):
        normalized = normalize_platform(str(logsource.get(key) or ""))
        if normalized:
            platforms.append(normalized)

    if not platforms:
        # `rules/windows/...` e `rules/cloud/aws/...` carregam a plataforma no
        # próprio caminho quando o campo `product` não está preenchido.
        for segment in relative_path.split("/")[1:3]:
            hint = _DIR_PLATFORM_HINTS.get(segment, ...)
            candidate = normalize_platform(segment) if hint is ... else hint
            if candidate:
                platforms.append(candidate)
                break

    return platforms


def _data_sources(logsource: dict[str, Any]) -> list[str]:
    """Descreve a telemetria exigida no vocabulário do Sigma (`logsource`)."""
    return [
        f"{key}: {value}"
        for key, value in logsource.items()
        if value and key in ("category", "product", "service", "definition")
    ]


def _tactic_names_from_tags(tags: list[str]) -> list[str]:
    """Extrai nomes de tática das tags `attack.<tatica>` do Sigma.

    Filtra as tags que são técnicas (`attack.t1055`) e as de outros namespaces
    (`cve.`, `detection.`, `car.`), sobrando as táticas por nome.
    """
    tactics: list[str] = []
    for tag in tags:
        if not tag.lower().startswith("attack."):
            continue
        suffix = tag.split(".", 1)[1]
        if suffix and not suffix[0].isdigit() and not suffix.lower().startswith("t1"):
            tactics.append(suffix.replace("_", " ").title())
    return tactics
