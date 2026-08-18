"""Helpers de normalização compartilhados pelos três parsers de fonte.

Cada fonte declara plataforma, severidade e ATT&CK no seu próprio vocabulário.
Concentrar a tradução aqui (em vez de espalhar pelos parsers) é o que garante
que o filtro por metadado da Fase 4 funcione de forma consistente entre fontes:
uma busca por `platform=windows` precisa casar regra do Sigma, do ESCU e do
YARA-L com o mesmo termo.
"""

from __future__ import annotations

from .schema import MITRE_TACTIC_RE, MITRE_TECHNIQUE_RE, Severity

# Vocabulário controlado de plataformas. Deliberadamente curto: são os eixos
# pelos quais um analista realmente filtra ("me mostra detecções de Windows",
# "o que tem para AWS"), não uma taxonomia exaustiva de produtos.
PLATFORM_VOCABULARY: tuple[str, ...] = (
    "windows",
    "linux",
    "macos",
    "aws",
    "azure",
    "gcp",
    "m365",
    "okta",
    "kubernetes",
    "github",
    "bitbucket",
    "sap",
    "network",
    "web",
    "email",
)

# Termos que indicam cada plataforma quando ela não vem declarada num campo
# limpo. Usado sobretudo no ESCU, que descreve telemetria em texto livre
# ("Sysmon EventID 1", "ASL AWS CloudTrail") em vez de um campo de plataforma.
_PLATFORM_KEYWORDS: dict[str, tuple[str, ...]] = {
    "windows": (
        "windows",
        "sysmon",
        "powershell",
        "winevent",
        "wineventlog",
        "active directory",
        "crowdstrike processrollup",
        "ntlm",
        "kerberos",
    ),
    "linux": ("linux", "auditd", "syslog", "unix", "esxi"),
    "macos": ("macos", "osx", "mac os"),
    "aws": ("aws", "cloudtrail", "ec2", "s3", "eks", "iam"),
    "azure": ("azure", "entra", "azuread", "azure ad"),
    "gcp": ("gcp", "google cloud", "google workspace"),
    "m365": ("o365", "office 365", "m365", "microsoft 365", "sharepoint", "exchange"),
    "okta": ("okta",),
    "kubernetes": ("kubernetes", "k8s", "kube-apiserver"),
    "github": ("github",),
    "network": (
        "suricata",
        "zeek",
        "netflow",
        "firewall",
        "cisco",
        "palo alto",
        "proxy",
        "dns",
        "network",
    ),
    "web": ("web", "nginx", "apache", "iis", "webserver"),
    "email": ("email", "smtp", "proofpoint", "mail"),
}

# Sinônimos diretos usados pelas fontes que já têm um campo de plataforma
# (Sigma `logsource.product`, YARA-L `platform`).
_PLATFORM_ALIASES: dict[str, str] = {
    "win": "windows",
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
    "osx": "macos",
    "aws": "aws",
    "amazon": "aws",
    "azure": "azure",
    "entra": "azure",
    "azure_ad": "azure",
    "gcp": "gcp",
    "google": "gcp",
    "google_workspace": "gcp",
    "workspace": "gcp",
    "m365": "m365",
    "o365": "m365",
    "office365": "m365",
    "okta": "okta",
    "onelogin": "okta",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "github": "github",
    # Bitbucket é plataforma própria, não sinônimo de GitHub: colapsar as duas
    # faria um filtro por `github` devolver regras de Bitbucket.
    "bitbucket": "bitbucket",
    "network": "network",
    "zeek": "network",
    "cisco": "network",
    "fortigate": "network",
    "suricata": "network",
    "web": "web",
    "sap": "sap",
}

# Um alias que aponta para fora do vocabulário produziria um metadado que
# nenhum filtro da Fase 4 consegue casar — falha silenciosa. Barrar no import.
assert set(_PLATFORM_ALIASES.values()) <= set(PLATFORM_VOCABULARY), (
    "aliases de plataforma apontando para fora do vocabulário: "
    f"{sorted(set(_PLATFORM_ALIASES.values()) - set(PLATFORM_VOCABULARY))}"
)
assert set(_PLATFORM_KEYWORDS) <= set(PLATFORM_VOCABULARY), (
    "palavras-chave de plataforma fora do vocabulário: "
    f"{sorted(set(_PLATFORM_KEYWORDS) - set(PLATFORM_VOCABULARY))}"
)

_SEVERITY_ALIASES: dict[str, Severity] = {
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def normalize_platform(raw: str) -> str | None:
    """Traduz um valor declarado de plataforma para o vocabulário controlado.

    Retorna `None` quando o valor não corresponde a nada conhecido — melhor
    perder um metadado do que inventar um rótulo errado que o filtro da Fase 4
    usaria com confiança indevida.
    """
    key = raw.strip().lower().replace("-", "_").replace(" ", "_")
    if not key:
        return None
    if key in _PLATFORM_ALIASES:
        return _PLATFORM_ALIASES[key]
    if key in PLATFORM_VOCABULARY:
        return key
    return None


def infer_platforms(texts: list[str]) -> list[str]:
    """Infere plataformas a partir de texto livre de telemetria.

    Usado quando a fonte não tem um campo de plataforma explícito — o caso do
    ESCU, cujo sinal mais forte de plataforma está em `data_source`
    ("Sysmon EventID 1" ⇒ windows, "ASL AWS CloudTrail" ⇒ aws).
    """
    haystack = " ".join(texts).lower()
    found: dict[str, None] = {}
    for platform, keywords in _PLATFORM_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            found.setdefault(platform, None)
    return list(found)


def extract_mitre_techniques(texts: list[str]) -> list[str]:
    """Extrai técnicas ATT&CK canônicas (T1055, T1055.001) de textos quaisquer.

    Trabalhar por regex sobre o texto, em vez de ler um campo específico, é o
    que permite usar a mesma função nas 3 fontes: o Sigma escreve
    `attack.t1055.001` numa tag, o ESCU tem `mitre_attack_id`, e o YARA-L
    espalha o ID entre `mitre`, `technique` e `mitre_attack_url`.
    """
    found: dict[str, None] = {}
    for text in texts:
        for match in MITRE_TECHNIQUE_RE.findall(text or ""):
            found.setdefault(match.upper(), None)
    return list(found)


def extract_mitre_tactics(texts: list[str]) -> list[str]:
    """Extrai IDs de tática ATT&CK (TA0004) de textos quaisquer."""
    found: dict[str, None] = {}
    for text in texts:
        for match in MITRE_TACTIC_RE.findall(text or ""):
            found.setdefault(match.upper(), None)
    return list(found)


def normalize_severity(raw: str | None) -> Severity | None:
    """Mapeia uma severidade declarada para a escala de 5 faixas do schema."""
    if not raw:
        return None
    return _SEVERITY_ALIASES.get(raw.strip().lower())


def as_str_list(value: object) -> list[str]:
    """Coage um campo YAML a `list[str]`.

    As fontes alternam entre escalar e lista para o mesmo campo (`references`,
    `product`, `mitre_attack_id`), então normalizar na borda evita espalhar
    checagens de tipo pelos parsers.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        items: list[str] = []
        for item in value:
            if item is None:
                continue
            items.extend(as_str_list(item) if isinstance(item, (list, tuple, set)) else [str(item).strip()])
        return [item for item in items if item]
    return [str(value).strip()]


def collapse_whitespace(text: str) -> str:
    """Colapsa espaços e quebras de linha internos num único espaço.

    As descrições vêm quebradas em várias linhas no YAML; para embedding o que
    importa é o texto, não o layout do arquivo original.
    """
    return " ".join(text.split())
