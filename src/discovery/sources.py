"""A lista de repositórios confiáveis — o limite do que a descoberta enxerga.

Este módulo é a peça central da tool de descoberta, e não um detalhe de
configuração. A pergunta que ele responde é: *onde o agente pode procurar?* A
resposta precisa ser um dado explícito, editável por quem opera e verificável
em código — não uma instrução em prompt.

Três decisões, todas com o mesmo motivo de fundo:

1. **Allowlist, nunca denylist.** Um agente que busca "na internet" e depois
   filtra o que não presta é um agente que já leu o que não devia. Aqui o
   conjunto de origens possíveis é finito e declarado; qualquer caminho de rede
   que não saia de uma entrada desta tabela é recusado em `github.py` antes de
   virar requisição.

2. **O formato faz parte da entrada, e não é adivinhado.** Um repositório só
   pode ser cadastrado se as regras dele forem legíveis por um dos três parsers
   da Fase 1 (Sigma, ESCU, YARA-L). Isso exclui coleções excelentes que usam
   outro formato — o `elastic/detection-rules`, que é TOML, é o exemplo típico —
   e essa exclusão é deliberada: aceitar o cadastro e falhar em silêncio na
   busca seria pior do que recusar com a razão na tela.

3. **As sementes vivem em código, o cadastro vive no banco.** Quem sobe o
   projeto pela primeira vez já encontra repositórios confiáveis cadastrados
   (`SEED_SOURCES`), semeados na primeira vez que a tabela é consultada. O que
   for adicionado ou removido depois é estado do operador, e fica no Postgres.
   Semear "só se a tabela estiver vazia" é o que impede uma origem removida de
   propósito de ressuscitar no próximo arranque.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from urllib.parse import quote

import psycopg
from pydantic import BaseModel, Field, field_validator

from ..ingestion.schema import RuleSource

TABLE_NAME = "trusted_sources"

# `owner/repo`, no vocabulário que o GitHub aceita para os dois. O anexo é
# estrito de propósito: este valor entra na montagem de uma URL, e o único jeito
# seguro de montar URL é não deixar entrar o que não deveria.
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
# Nome de branch ou tag. Barra é legítima (`release/1.2`); `..` não é.
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


def normalize_slug(value: str) -> str:
    """Reduz o que a pessoa digitou a `dono/repositório`, ou recusa.

    Aceita a URL da barra de endereços porque é o que qualquer um cola ao
    cadastrar um repositório — exigir que ela seja editada à mão antes seria
    uma pegadinha. O host é **descartado**, não interpretado: `github.com` é o
    único destino possível da ferramenta, e o que vem em `https://outro/x/y`
    vira o slug `x/y`, que ainda precisa existir no GitHub para ser aceito.

    Vive aqui, e não só no validador do modelo, porque o cadastro confere o
    repositório no GitHub **antes** de construir o modelo. Com a normalização
    presa ao validador, colar a URL falhava na conferência e a conveniência
    nunca chegava a rodar. Foi assim que o defeito apareceu na primeira
    verificação da interface.
    """
    cleaned = value.strip().strip("/")
    if cleaned.lower().startswith(("http://", "https://")):
        cleaned = re.sub(r"^https?://[^/]+/", "", cleaned)
        cleaned = cleaned.removesuffix(".git").strip("/")
    if not SLUG_RE.match(cleaned):
        raise ValueError(
            f"'{value}' não é um repositório do GitHub no formato dono/repositório."
        )
    return cleaned


class RuleFormat(StrEnum):
    """Como as regras de um repositório são lidas.

    Os valores coincidem com `RuleSource` porque o formato do arquivo é o que
    determina a fonte no schema comum: uma regra em formato Sigma achada num
    repositório de terceiro continua sendo uma regra Sigma, e o analista a lê
    como tal. O repositório onde ela foi encontrada é registrado à parte, na
    proveniência da proposta.
    """

    SIGMA = "sigma"
    SPLUNK_ESCU = "splunk_escu"
    YARA_L = "yara_l"

    @property
    def rule_source(self) -> RuleSource:
        return RuleSource(self.value)


#: Extensões que cada formato pode ter. Serve para não baixar um `README.md`
#: para descobrir que não é regra.
FORMAT_EXTENSIONS: dict[RuleFormat, tuple[str, ...]] = {
    RuleFormat.SIGMA: (".yml", ".yaml"),
    RuleFormat.SPLUNK_ESCU: (".yml", ".yaml"),
    RuleFormat.YARA_L: (".yaral",),
}

#: Segmentos de caminho descartados em qualquer origem. Mesma razão da Fase 1:
#: citar uma regra descontinuada como recomendação é resposta ativamente errada.
DEFAULT_EXCLUDED_SEGMENTS: tuple[str, ...] = (
    "deprecated",
    "_deprecated",
    "unsupported",
    "removed",
    "experimental",
    "test",
    "tests",
)


class TrustedSource(BaseModel):
    """Um repositório em que a descoberta tem permissão de procurar."""

    slug: str = Field(description="`owner/repo` no GitHub — a identidade da origem.")
    ref: str = Field(default="main", description="Branch ou tag lida (o default do repositório).")
    label: str = Field(description="Nome legível, como aparece na interface.")
    rule_format: RuleFormat
    path_prefixes: list[str] = Field(
        default_factory=list,
        description=(
            "Subcaminhos onde as regras vivem ('rules', 'detections'). Vazio "
            "significa o repositório inteiro."
        ),
    )
    excluded_segments: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDED_SEGMENTS))
    note: str = Field(default="", description="Por que esta origem é confiável — texto do operador.")
    enabled: bool = True
    is_seed: bool = Field(default=False, description="Veio pré-cadastrada com a ferramenta.")
    added_at: datetime | None = None

    @field_validator("slug")
    @classmethod
    def _valid_slug(cls, value: str) -> str:
        return normalize_slug(value)

    @field_validator("ref")
    @classmethod
    def _valid_ref(cls, value: str) -> str:
        cleaned = value.strip()
        if not REF_RE.match(cleaned) or ".." in cleaned:
            raise ValueError(f"'{value}' não é um nome de branch ou tag válido.")
        return cleaned

    @field_validator("path_prefixes")
    @classmethod
    def _valid_prefixes(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            prefix = value.strip().strip("/")
            if not prefix:
                continue
            if ".." in prefix or prefix.startswith("/"):
                raise ValueError(f"'{value}' não é um subcaminho válido dentro do repositório.")
            cleaned.append(prefix)
        return cleaned

    @property
    def key(self) -> str:
        """Identidade normalizada. O GitHub não diferencia maiúsculas no slug."""
        return self.slug.lower()

    @property
    def owner(self) -> str:
        return self.slug.split("/", 1)[0]

    @property
    def repo(self) -> str:
        return self.slug.split("/", 1)[1]

    @property
    def extensions(self) -> tuple[str, ...]:
        return FORMAT_EXTENSIONS[self.rule_format]

    def accepts(self, path: str) -> bool:
        """Se um caminho do repositório é candidato a ser uma regra.

        Filtra antes de baixar: extensão do formato, dentro dos subcaminhos
        declarados, e fora dos segmentos excluídos.
        """
        lowered = path.lower()
        if not lowered.endswith(self.extensions):
            return False
        if self.path_prefixes and not any(
            path == prefix or path.startswith(f"{prefix}/") for prefix in self.path_prefixes
        ):
            return False
        segments = {segment.lower() for segment in path.split("/")[:-1]}
        return not segments & {segment.lower() for segment in self.excluded_segments}

    def blob_url(self, path: str) -> str:
        """URL legível do arquivo — é ela que vira `source_url` da regra citada."""
        return f"https://github.com/{self.slug}/blob/{self.ref}/{_encode_path(path)}"

    def raw_url(self, path: str) -> str:
        """URL do conteúdo cru. Host coberto pela allowlist de `github.py`."""
        return (
            f"https://raw.githubusercontent.com/{self.slug}/{self.ref}/{_encode_path(path)}"
        )

    def tree_url(self) -> str:
        return f"https://api.github.com/repos/{self.slug}/git/trees/{self.ref}?recursive=1"


def _encode_path(path: str) -> str:
    """Codifica o caminho preservando as barras.

    Nome de arquivo com espaço é comum em repositório de comunidade (o
    `mdecrevoisier` usa espaço em quase todos), e sem isto a requisição sai
    malformada e o arquivo "não existe".
    """
    return quote(path, safe="/")


# ---------------------------------------------------------------------------
# Sementes: o que já vem cadastrado depois do deploy da ferramenta
# ---------------------------------------------------------------------------

#: As três primeiras são as fontes do corpus original — mantê-las cadastradas é
#: o que permite descobrir regra nova publicada upstream desde a última
#: ingestão, sem reindexar 5.664 regras para achar 12. As demais são coleções
#: de comunidade em formato Sigma, escolhidas por terem autoria identificável e
#: histórico público: é isso que "confiável" significa aqui, não popularidade.
SEED_SOURCES: tuple[TrustedSource, ...] = (
    TrustedSource(
        slug="SigmaHQ/sigma",
        ref="master",
        label="SigmaHQ",
        rule_format=RuleFormat.SIGMA,
        path_prefixes=["rules"],
        is_seed=True,
        note="Repositório principal do padrão Sigma. É uma das fontes do corpus indexado.",
    ),
    TrustedSource(
        slug="splunk/security_content",
        ref="develop",
        label="Splunk ESCU",
        rule_format=RuleFormat.SPLUNK_ESCU,
        path_prefixes=["detections"],
        is_seed=True,
        note="Detecções em SPL mantidas pelo Splunk Threat Research Team.",
    ),
    TrustedSource(
        slug="chronicle/detection-rules",
        ref="main",
        label="Google SecOps (YARA-L)",
        rule_format=RuleFormat.YARA_L,
        path_prefixes=["rules"],
        is_seed=True,
        note="Regras YARA-L de exemplo da comunidade do Google SecOps.",
    ),
    TrustedSource(
        slug="mdecrevoisier/SIGMA-detection-rules",
        ref="main",
        label="mdecrevoisier",
        rule_format=RuleFormat.SIGMA,
        is_seed=True,
        note=(
            "Mais de 350 regras Sigma mapeadas para ATT&CK, com ênfase em Active "
            "Directory e telemetria nativa do Windows. Sem subdiretório de regras: "
            "a árvore inteira é de regras."
        ),
    ),
    TrustedSource(
        slug="joesecurity/sigma-rules",
        ref="master",
        label="Joe Security",
        rule_format=RuleFormat.SIGMA,
        path_prefixes=["rules"],
        is_seed=True,
        note="Regras derivadas de comportamento observado no sandbox do Joe Sandbox.",
    ),
    TrustedSource(
        slug="tsale/Sigma_rules",
        ref="main",
        label="Kostas (tsale)",
        rule_format=RuleFormat.SIGMA,
        is_seed=True,
        note="Coleção pessoal com foco em LOLBins e exploração no Windows.",
    ),
    TrustedSource(
        slug="Yamato-Security/hayabusa-rules",
        ref="main",
        label="Hayabusa",
        rule_format=RuleFormat.SIGMA,
        # Só `hayabusa/`: o diretório `sigma/` deste repositório é uma cópia
        # convertida do SigmaHQ, que já está indexado e já é uma origem
        # cadastrada. Buscar nele devolveria as mesmas regras por um caminho
        # diferente — ruído, não cobertura.
        path_prefixes=["hayabusa"],
        is_seed=True,
        note=(
            "Regras próprias do Hayabusa para log de evento do Windows. O diretório "
            "`sigma/` fica de fora: é espelho do SigmaHQ, que já está no acervo."
        ),
    ),
)


# ---------------------------------------------------------------------------
# Persistência
# ---------------------------------------------------------------------------


def ensure_schema(conn: psycopg.Connection) -> None:
    """Cria a tabela de origens confiáveis, se ainda não existir."""
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
            source_key        TEXT PRIMARY KEY,
            slug              TEXT NOT NULL,
            ref               TEXT NOT NULL,
            label             TEXT NOT NULL,
            rule_format       TEXT NOT NULL,
            path_prefixes     TEXT[] NOT NULL DEFAULT '{{}}',
            excluded_segments TEXT[] NOT NULL DEFAULT '{{}}',
            note              TEXT NOT NULL DEFAULT '',
            enabled           BOOLEAN NOT NULL DEFAULT TRUE,
            is_seed           BOOLEAN NOT NULL DEFAULT FALSE,
            added_at          TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )


def _row_to_source(row: tuple) -> TrustedSource:
    return TrustedSource(
        slug=row[0],
        ref=row[1],
        label=row[2],
        rule_format=RuleFormat(row[3]),
        path_prefixes=list(row[4] or []),
        excluded_segments=list(row[5] or []),
        note=row[6] or "",
        enabled=row[7],
        is_seed=row[8],
        added_at=row[9],
    )


def load_sources(conn: psycopg.Connection, include_disabled: bool = True) -> list[TrustedSource]:
    """Devolve as origens cadastradas, semeando na primeira vez."""
    ensure_schema(conn)
    seed_if_empty(conn)

    where = "" if include_disabled else "WHERE enabled"
    rows = conn.execute(
        f"""
        SELECT slug, ref, label, rule_format, path_prefixes, excluded_segments,
               note, enabled, is_seed, added_at
        FROM {TABLE_NAME} {where}
        ORDER BY is_seed DESC, label
        """
    ).fetchall()
    return [_row_to_source(row) for row in rows]


def seed_if_empty(conn: psycopg.Connection) -> int:
    """Cadastra as sementes quando a tabela nunca foi populada.

    "Vazia" e não "sem esta semente": semear por entrada faria uma origem
    removida de propósito voltar no arranque seguinte, o que transformaria a
    remoção num botão que não funciona.
    """
    row = conn.execute(f"SELECT count(*) FROM {TABLE_NAME}").fetchone()
    if row and row[0]:
        return 0
    for source in SEED_SOURCES:
        upsert_source(conn, source)
    return len(SEED_SOURCES)


def upsert_source(conn: psycopg.Connection, source: TrustedSource) -> None:
    conn.execute(
        f"""
        INSERT INTO {TABLE_NAME} (
            source_key, slug, ref, label, rule_format,
            path_prefixes, excluded_segments, note, enabled, is_seed
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (source_key) DO UPDATE SET
            slug              = EXCLUDED.slug,
            ref               = EXCLUDED.ref,
            label             = EXCLUDED.label,
            rule_format       = EXCLUDED.rule_format,
            path_prefixes     = EXCLUDED.path_prefixes,
            excluded_segments = EXCLUDED.excluded_segments,
            note              = EXCLUDED.note,
            enabled           = EXCLUDED.enabled
        """,
        (
            source.key,
            source.slug,
            source.ref,
            source.label,
            source.rule_format.value,
            source.path_prefixes,
            source.excluded_segments,
            source.note,
            source.enabled,
            source.is_seed,
        ),
    )


def remove_source(conn: psycopg.Connection, slug: str) -> bool:
    """Descadastra uma origem. Devolve se havia algo para remover."""
    cursor = conn.execute(
        f"DELETE FROM {TABLE_NAME} WHERE source_key = %s", (slug.strip().lower(),)
    )
    return cursor.rowcount > 0


def set_enabled(conn: psycopg.Connection, slug: str, enabled: bool) -> bool:
    """Liga/desliga uma origem sem perder o cadastro dela."""
    cursor = conn.execute(
        f"UPDATE {TABLE_NAME} SET enabled = %s WHERE source_key = %s",
        (enabled, slug.strip().lower()),
    )
    return cursor.rowcount > 0
