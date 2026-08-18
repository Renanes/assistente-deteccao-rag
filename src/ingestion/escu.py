"""Parser das detecções do Splunk ESCU (https://github.com/splunk/security_content).

Formato: um arquivo YAML por detecção, com a query já pronta em SPL no campo
`search`. Diferente do Sigma, o ESCU não declara plataforma — o sinal mais
forte está em `data_source` ("Sysmon EventID 1", "ASL AWS CloudTrail"), de onde
a plataforma é inferida.
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
    infer_platforms,
)
from .schema import DetectionRule, QueryLanguage, RuleSource

GITHUB_BLOB_BASE = "https://github.com/splunk/security_content/blob/develop"


def parse_escu_rule(path: Path, repo_root: Path) -> DetectionRule | None:
    """Converte um arquivo de detecção do ESCU para o schema comum.

    Retorna `None` para YAMLs sem `name`/`id`/`search` — o diretório
    `detections/` também guarda arquivos que não são detecções.
    """
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        document: Any = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None

    if not isinstance(document, dict):
        return None

    name = document.get("name")
    native_id = document.get("id")
    search = document.get("search")
    if not name or not native_id or not search:
        return None

    relative_path = path.relative_to(repo_root).as_posix()
    data_sources = as_str_list(document.get("data_source"))
    asset_type = str(document.get("asset_type") or "")
    mitre_ids = as_str_list(document.get("mitre_attack_id"))

    # `known_false_positives` é uma frase corrida, não uma lista — vira um item
    # único para caber no mesmo campo das outras fontes.
    known_fps = collapse_whitespace(str(document.get("known_false_positives") or ""))

    return DetectionRule(
        rule_uid=f"{RuleSource.SPLUNK_ESCU.value}:{native_id}",
        source=RuleSource.SPLUNK_ESCU,
        native_id=str(native_id),
        source_path=relative_path,
        source_url=f"{GITHUB_BLOB_BASE}/{relative_path}",
        title=collapse_whitespace(str(name)),
        description=collapse_whitespace(str(document.get("description") or "")),
        false_positives=[known_fps] if known_fps else [],
        query=str(search).strip(),
        query_language=QueryLanguage.SPL,
        platforms=infer_platforms([*data_sources, asset_type, str(name)]),
        mitre_techniques=extract_mitre_techniques(mitre_ids),
        mitre_tactics=extract_mitre_tactics(mitre_ids),
        data_sources=data_sources,
        tags=_tags(document),
        author=collapse_whitespace(str(document.get("author") or "")) or None,
        status=str(document.get("status")) if document.get("status") else None,
        # ESCU não tem campo de severidade por detecção: `type` (TTP/Anomaly/
        # Hunting/Correlation) é um eixo diferente e mapeá-lo para severidade
        # seria inventar informação. Fica `None` e o eixo vira tag.
        severity=None,
        references=as_str_list(document.get("references")),
    )


def _tags(document: dict[str, Any]) -> list[str]:
    """Monta tags a partir dos eixos de classificação próprios do ESCU.

    `analytic_story` é o mais útil para retrieval: agrupa detecções por campanha
    ou família de ameaça ("Ransomware", "AWS Cross Account Activity").
    """
    tags: list[str] = []
    if detection_type := document.get("type"):
        tags.append(f"type: {detection_type}")
    if category := document.get("category"):
        tags.extend(f"category: {item}" for item in as_str_list(category))
    if security_domain := document.get("security_domain"):
        tags.append(f"security_domain: {security_domain}")
    tags.extend(as_str_list(document.get("analytic_story")))
    return tags
