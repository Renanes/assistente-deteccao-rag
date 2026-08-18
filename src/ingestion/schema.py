"""Schema comum para regras de detecção das 3 fontes públicas.

As fontes (SigmaHQ, Splunk ESCU, YARA-L da comunidade Google SecOps) têm
formatos e vocabulários bem diferentes. Este módulo define o denominador comum
para o qual todas são convertidas, e é o contrato que todas as fases seguintes
(chunking, embeddings, retrieval, RAG) consomem.

Duas escolhas centrais aqui, com impacto direto no RAG:

1. Campos narrativos (`title`, `description`, `false_positives`) ficam separados
   da `query` bruta. A Fase 2 embeda os narrativos e preserva a query como
   contexto — misturar os dois polui o vetor com sintaxe de linguagem de busca.
2. `rule_uid` e `source_url` existem para citação. A resposta do RAG precisa
   apontar para a regra real, e `source_url` é o link verificável para ela.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

# Técnica MITRE ATT&CK canônica: T1055 ou T1055.001.
MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
# Tática MITRE ATT&CK canônica: TA0004.
MITRE_TACTIC_RE = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)


class RuleSource(StrEnum):
    """Fonte pública de origem da regra."""

    SIGMA = "sigma"
    SPLUNK_ESCU = "splunk_escu"
    YARA_L = "yara_l"


class QueryLanguage(StrEnum):
    """Linguagem em que a lógica de detecção está escrita.

    Separada de `RuleSource` porque são eixos distintos: a fonte diz de onde a
    regra veio, a linguagem diz o que o analista precisa saber para usá-la.
    """

    SIGMA = "sigma"
    SPL = "spl"
    YARA_L = "yara-l"


class Severity(StrEnum):
    """Severidade normalizada nas 5 faixas do Sigma.

    Sigma já usa essa escala. ESCU não tem campo de severidade por regra (usa
    `type`, que é outro eixo) e YARA-L usa `severity = "Low"/"Medium"/"High"`,
    mapeado direto. Regras sem severidade declarada ficam com `None`.
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionRule(BaseModel):
    """Uma regra de detecção normalizada, de qualquer uma das 3 fontes."""

    # --- Identidade e proveniência ---
    rule_uid: str = Field(
        description=(
            "Identificador estável e único no corpus inteiro, no formato "
            "'<source>:<id nativo>'. Prefixar com a fonte evita colisão entre "
            "os espaços de UUID independentes de cada repositório."
        )
    )
    source: RuleSource
    native_id: str = Field(description="ID da regra no repositório de origem.")
    source_path: str = Field(
        description="Caminho do arquivo relativo à raiz do repositório clonado."
    )
    source_url: str | None = Field(
        default=None,
        description="URL pública do arquivo no GitHub — o link citado na resposta do RAG.",
    )

    # --- Campos narrativos (vão para o embedding na Fase 2) ---
    title: str
    description: str = ""
    false_positives: list[str] = Field(default_factory=list)

    # --- Lógica de detecção (preservada como contexto, não embedada) ---
    query: str = Field(description="A lógica de detecção bruta, como escrita na fonte.")
    query_language: QueryLanguage

    # --- Metadados para busca híbrida (Fase 4) ---
    platforms: list[str] = Field(
        default_factory=list,
        description="Plataformas de telemetria normalizadas (windows, linux, aws, ...).",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list, description="Técnicas ATT&CK canônicas: T1055, T1055.001."
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="Táticas ATT&CK — IDs (TA0004) ou nomes, conforme a fonte declara.",
    )
    data_sources: list[str] = Field(
        default_factory=list, description="Telemetria exigida, no vocabulário da fonte."
    )
    tags: list[str] = Field(default_factory=list)

    # --- Metadados descritivos ---
    author: str | None = None
    status: str | None = None
    severity: Severity | None = None
    references: list[str] = Field(default_factory=list)

    @field_validator("mitre_techniques", "mitre_tactics", mode="after")
    @classmethod
    def _canonical_mitre(cls, values: list[str]) -> list[str]:
        """Normaliza IDs ATT&CK para maiúsculas e remove duplicatas.

        As fontes escrevem o mesmo ID de formas diferentes (`attack.t1055.001`
        no Sigma, `T1055.001` no ESCU). Sem isso, o filtro por metadado da
        Fase 4 falharia em casar 'T1055' com 't1055'.
        """
        seen: dict[str, None] = {}
        for value in values:
            normalized = value.upper() if _looks_like_mitre_id(value) else value
            seen.setdefault(normalized, None)
        return list(seen)

    @field_validator("platforms", "tags", "data_sources", "references", mode="after")
    @classmethod
    def _dedupe_preserving_order(cls, values: list[str]) -> list[str]:
        seen: dict[str, None] = {}
        for value in values:
            cleaned = value.strip()
            if cleaned:
                seen.setdefault(cleaned, None)
        return list(seen)

    @property
    def narrative_text(self) -> str:
        """Texto narrativo concatenado — a entrada do embedding na Fase 2."""
        parts = [self.title, self.description]
        if self.false_positives:
            parts.append("Falsos positivos conhecidos: " + "; ".join(self.false_positives))
        return "\n\n".join(part for part in parts if part.strip())


def _looks_like_mitre_id(value: str) -> bool:
    return bool(MITRE_TECHNIQUE_RE.fullmatch(value) or MITRE_TACTIC_RE.fullmatch(value))
