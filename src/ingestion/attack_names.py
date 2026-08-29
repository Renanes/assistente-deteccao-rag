"""Gera o mapa de nomes do MITRE ATT&CK a partir do bundle STIX oficial.

Uso:
    python -m src.ingestion.attack_names            # gera data/attack/techniques.json
    python -m src.ingestion.attack_names --check    # confere o arquivo contra o corpus

**Por que um arquivo gerado e commitado, e não uma chamada em runtime.** O
acervo guarda só o ID da técnica (`T1055`) — nenhuma das três fontes fornece o
nome de forma utilizável: Sigma e ESCU não carregam nome nenhum, e das 916
regras YARA-L apenas 148 trazem `mitre_attack_technique`. Um catálogo de 473
IDs nus é ilegível para quem navega.

Buscar o bundle a cada arranque da aplicação seria trocar uma dependência de
dados por uma dependência de rede num caminho que precisa funcionar offline, e
o bundle tem ~35 MB. Buscar uma vez, extrair ~1% dele e commitar o resultado
mantém a aplicação sem rede e o dado auditável em `git diff`.

**O segundo produto deste script é a validação.** O mapa diz quais IDs do
acervo existem de fato no ATT&CK, quais foram descontinuados e quais foram
revogados em favor de outro. Um ID que o acervo usa e o ATT&CK não conhece é um
achado — pode ser regra velha, erro de digitação na fonte, ou um domínio que
não estamos baixando. Em qualquer caso é melhor mostrar do que esconder.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Os três domínios do ATT&CK. Enterprise cobre a esmagadora maioria do acervo,
# mas baixar os três custa uma execução a mais e elimina a dúvida "esse ID não
# existe ou está só em outro domínio?" — que é exatamente a pergunta que o
# `--check` precisa responder sem ambiguidade.
BUNDLES = {
    "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
}

OUTPUT_PATH = Path(__file__).resolve().parents[2] / "data" / "attack" / "techniques.json"

# Timeout generoso: o bundle Enterprise passa de 35 MB e a execução é manual e
# rara. Falhar por impaciência aqui só faria alguém rodar de novo.
DOWNLOAD_TIMEOUT_SECONDS = 180


@dataclass(frozen=True)
class Technique:
    """Uma técnica do ATT&CK, reduzida ao que o catálogo precisa."""

    id: str
    name: str
    domain: str
    deprecated: bool = False
    revoked: bool = False
    #: ID que substitui esta, quando revogada.
    superseded_by: str | None = None

    def as_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name, "domain": self.domain}
        # Só grava o que foge do normal: o arquivo fica menor e um `git diff`
        # nele mostra mudança de estado real, não ruído de campos default.
        if self.deprecated:
            data["deprecated"] = True
        if self.revoked:
            data["revoked"] = True
        if self.superseded_by:
            data["superseded_by"] = self.superseded_by
        return data


def _external_id(obj: dict[str, Any]) -> str | None:
    """Extrai o `Txxxx` das referências externas do objeto STIX."""
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            external_id = reference.get("external_id")
            if isinstance(external_id, str) and external_id.startswith("T"):
                return external_id
    return None


def parse_bundle(bundle: dict[str, Any], domain: str) -> dict[str, Technique]:
    """Extrai as técnicas de um bundle STIX do ATT&CK.

    Objetos revogados e descontinuados **entram** no mapa. Excluí-los deixaria
    o catálogo dizendo "não consta no ATT&CK" para um ID que consta muito bem —
    ele só não é mais recomendado, que é informação diferente e mais útil.
    """
    techniques: dict[str, Technique] = {}
    # `relationship` do tipo `revoked-by` liga o objeto velho ao que o substitui.
    revoked_by: dict[str, str] = {}
    by_stix_id: dict[str, str] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            source = obj.get("source_ref")
            target = obj.get("target_ref")
            if isinstance(source, str) and isinstance(target, str):
                revoked_by[source] = target
            continue

        if obj.get("type") != "attack-pattern":
            continue

        external_id = _external_id(obj)
        name = obj.get("name")
        if not external_id or not isinstance(name, str):
            continue

        stix_id = obj.get("id")
        if isinstance(stix_id, str):
            by_stix_id[stix_id] = external_id

        techniques[external_id] = Technique(
            id=external_id,
            name=name,
            domain=domain,
            deprecated=bool(obj.get("x_mitre_deprecated")),
            revoked=bool(obj.get("revoked")),
        )

    # Resolve o substituto agora que todo STIX id tem um `Txxxx` conhecido.
    for source_stix, target_stix in revoked_by.items():
        source_id = by_stix_id.get(source_stix)
        target_id = by_stix_id.get(target_stix)
        if source_id and target_id and source_id in techniques:
            current = techniques[source_id]
            techniques[source_id] = Technique(
                id=current.id,
                name=current.name,
                domain=current.domain,
                deprecated=current.deprecated,
                revoked=True,
                superseded_by=target_id,
            )

    return techniques


def fetch_all() -> tuple[dict[str, Technique], dict[str, str]]:
    """Baixa os três bundles. Devolve as técnicas e a versão de cada domínio."""
    import httpx

    techniques: dict[str, Technique] = {}
    versions: dict[str, str] = {}

    for domain, url in BUNDLES.items():
        print(f"baixando {domain}…", flush=True)
        response = httpx.get(url, timeout=DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True)
        response.raise_for_status()
        bundle = response.json()

        found = parse_bundle(bundle, domain)
        # Enterprise vem primeiro e não é sobrescrito: um ID que existe em dois
        # domínios é do Enterprise para efeito deste acervo, que é de detecção
        # em log corporativo.
        for technique_id, technique in found.items():
            techniques.setdefault(technique_id, technique)

        versions[domain] = _bundle_version(bundle)
        print(f"  {len(found)} técnicas · versão {versions[domain]}", flush=True)

    return techniques, versions


def _bundle_version(bundle: dict[str, Any]) -> str:
    """Lê a versão do ATT&CK declarada no objeto `x-mitre-collection`.

    `x_mitre_version` é uma string ("17.1"). A primeira versão desta função
    iterava sobre ela achando que era lista, e "17.1" iterado devolve "1" — uma
    versão plausível o bastante para passar despercebida no arquivo gerado.
    """
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            if isinstance(version, str) and version:
                return version
    return "desconhecida"


def write_map(techniques: dict[str, Technique], versions: dict[str, str]) -> Path:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_gerado_por": "python -m src.ingestion.attack_names",
        "_fonte": "https://github.com/mitre-attack/attack-stix-data",
        "versoes": versions,
        "techniques": {
            technique_id: techniques[technique_id].as_json()
            for technique_id in sorted(techniques)
        },
    }
    OUTPUT_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return OUTPUT_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="não baixa nada; confere o mapa existente contra as técnicas do acervo.",
    )
    args = parser.parse_args()

    if args.check:
        _check_against_corpus()
        return

    techniques, versions = fetch_all()
    path = write_map(techniques, versions)
    size_kb = path.stat().st_size / 1024
    print(f"\n{len(techniques)} técnicas gravadas em {path} ({size_kb:.0f} KB)")


def _check_against_corpus() -> None:
    """Compara os IDs usados pelo acervo indexado com o mapa gerado."""
    from ..embeddings import store
    from ..providers import get_settings
    from ..retrieval.techniques import load_attack_names

    names = load_attack_names()
    settings = get_settings()

    with store.connect(settings.resolved_database_url()) as conn:
        rows = conn.execute(
            f"SELECT DISTINCT t FROM {store.TABLE_NAME}, unnest(mitre_techniques) t ORDER BY t"
        ).fetchall()

    used = [row[0] for row in rows]
    unknown = [technique_id for technique_id in used if technique_id not in names]
    deprecated = [
        technique_id
        for technique_id in used
        if technique_id in names and names[technique_id].get("deprecated")
    ]
    revoked = [
        technique_id
        for technique_id in used
        if technique_id in names and names[technique_id].get("revoked")
    ]

    print(f"acervo usa {len(used)} técnicas distintas; mapa conhece {len(names)}")
    print(f"  sem correspondência no ATT&CK: {len(unknown)} {unknown[:20]}")
    print(f"  descontinuadas: {len(deprecated)} {deprecated[:20]}")
    print(f"  revogadas: {len(revoked)} {revoked[:20]}")


if __name__ == "__main__":
    main()
