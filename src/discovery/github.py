"""Acesso ao GitHub, restrito ao que a lista de origens confiáveis autoriza.

Este é o único módulo do projeto que faz requisição para fora. Ele existe menos
para "falar com o GitHub" e mais para tornar a restrição verificável: um agente
que promete só ler repositórios confiáveis, mas cuja camada de rede aceita
qualquer URL, está a um prompt mal-intencionado de ler outra coisa.

Como a restrição é imposta, em três camadas que se sobrepõem de propósito:

1. **A URL é montada, nunca recebida.** Nenhuma função aqui aceita URL como
   parâmetro vinda de fora. O que entra é uma `TrustedSource` (já validada em
   `sources.py`) mais um caminho relativo; a URL sai de `source.raw_url(path)`.
   Uma URL que apontasse para outro host não teria como ser construída.

2. **A origem é conferida contra a allowlist a cada chamada**, e não uma vez no
   arranque. A lista muda em tempo de execução — é um menu na interface — e um
   cliente que tivesse copiado a lista na construção continuaria lendo uma
   origem que o operador acabou de remover.

3. **O host é conferido no último instante**, imediatamente antes do envio.
   Redundante com (1) por construção, e é essa a intenção: se algum dia alguém
   acrescentar um caminho que monte URL de outro jeito, a checagem final ainda
   está lá. Redirecionamento vem desligado pelo mesmo motivo — um 302 é
   exatamente o jeito de um host autorizado entregar conteúdo de outro.

O `GITHUB_TOKEN` é opcional e muda a *estratégia*, não a *permissão*: com token,
a busca de código do GitHub procura dentro do conteúdo dos arquivos; sem token,
resta a árvore do repositório (uma requisição, em cache) e a leitura dos
candidatos. Ver `search.py`.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .sources import TrustedSource, normalize_slug

#: Os dois únicos hosts que este módulo pode alcançar. `api.github.com` para
#: metadado e árvore; `raw.githubusercontent.com` para o conteúdo do arquivo.
ALLOWED_HOSTS = frozenset({"api.github.com", "raw.githubusercontent.com"})

REPO_ROOT = Path(__file__).resolve().parents[2]
#: A árvore de um repositório muda devagar e custa uma requisição inteira do
#: orçamento de quem não tem token (60/hora). O cache em disco é o que permite
#: refazer uma busca sem gastar cota de novo.
CACHE_DIR = REPO_ROOT / "data" / "discovery_cache"
TREE_TTL_SECONDS = 6 * 60 * 60

REQUEST_TIMEOUT_SECONDS = 20.0
USER_AGENT = "agente-detection/discovery (+https://github.com/SigmaHQ/sigma)"


class DiscoveryError(RuntimeError):
    """Falha ao consultar uma origem confiável."""


class NotAllowedError(DiscoveryError):
    """Uma leitura foi barrada porque a origem não está autorizada.

    Erro distinto de propósito: recusa de permissão não é falha de rede, e a
    interface precisa dizer coisas diferentes nos dois casos.
    """


class RateLimitError(DiscoveryError):
    """O GitHub recusou por limite de requisições.

    Separado porque a saída é diferente de qualquer outro erro: esperar, ou
    configurar `GITHUB_TOKEN`. Sem token o limite é de 60 requisições por hora
    por IP, e uma busca em 7 repositórios consome parte disso.
    """


@dataclass
class FetchStats:
    """Contagem do que a busca realmente pediu à rede.

    Vira material da resposta: quem aprova uma regra tem direito de saber
    quantos arquivos foram lidos para propô-la, e quanto veio de cache.
    """

    requests: int = 0
    cached_trees: int = 0
    files_read: int = 0
    bytes_read: int = 0
    rate_limit_remaining: int | None = None
    errors: list[str] = field(default_factory=list)


def _assert_host_allowed(url: str) -> None:
    host = (urlparse(url).hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise NotAllowedError(
            f"'{host or url}' não é um host autorizado. A descoberta só fala com "
            f"{', '.join(sorted(ALLOWED_HOSTS))}."
        )


class GitHubClient:
    """Lê repositórios confiáveis. Não sabe ler mais nada.

    A allowlist é passada como *callable* e não como lista: a interface pode
    remover uma origem entre duas chamadas, e ler a lista no momento do uso é o
    que faz a remoção valer imediatamente.
    """

    def __init__(
        self,
        allowlist: list[TrustedSource],
        token: str = "",
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        cache_dir: Path | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._allowed = {source.key for source in allowlist}
        self._token = token.strip()
        self._cache_dir = cache_dir if cache_dir is not None else CACHE_DIR
        self.stats = FetchStats()
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=timeout,
            # Sem redirecionamento automático: um 302 de um host autorizado para
            # um host qualquer é justamente o jeito de contornar a allowlist.
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )

    # -- ciclo de vida ------------------------------------------------------

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- permissão ----------------------------------------------------------

    def _assert_allowed(self, source: TrustedSource) -> None:
        if source.key not in self._allowed:
            raise NotAllowedError(
                f"'{source.slug}' não está na lista de repositórios confiáveis. "
                "Cadastre a origem antes de buscar nela."
            )

    # -- requisição ---------------------------------------------------------

    def _headers(self, accept: str) -> dict[str, str]:
        headers = {"Accept": accept}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _get(
        self,
        url: str,
        accept: str = "application/vnd.github+json",
        params: dict[str, str | int] | None = None,
    ) -> httpx.Response:
        _assert_host_allowed(url)
        self.stats.requests += 1
        try:
            response = self._client.get(url, headers=self._headers(accept), params=params)
        except httpx.HTTPError as error:
            raise DiscoveryError(f"não deu para alcançar o GitHub: {error}") from error

        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining is not None and remaining.isdigit():
            self.stats.rate_limit_remaining = int(remaining)

        if response.status_code in (403, 429) and self.stats.rate_limit_remaining == 0:
            raise RateLimitError(
                "O GitHub recusou por limite de requisições. Sem token o limite é de "
                "60 por hora e por IP; configure GITHUB_TOKEN no .env do servidor "
                "para subir esse teto, ou espere a janela virar."
            )
        if response.is_redirect:
            raise NotAllowedError(
                f"o GitHub redirecionou {url} para outro endereço; a leitura foi "
                "interrompida em vez de seguir para fora da lista de hosts autorizados."
            )
        if response.status_code == 404:
            raise DiscoveryError(f"não encontrado no GitHub: {url}")
        if response.status_code >= 400:
            raise DiscoveryError(f"o GitHub respondeu {response.status_code} para {url}")

        self.stats.bytes_read += len(response.content)
        return response

    # -- leitura ------------------------------------------------------------

    def list_tree(self, source: TrustedSource, use_cache: bool = True) -> list[str]:
        """Todos os caminhos de arquivo do repositório, filtrados pelo formato.

        Uma requisição por repositório, com cache em disco. Repositório grande
        vem `truncated: true` do GitHub — nesse caso o que voltou é usado do
        mesmo jeito, com o aviso registrado em `stats.errors`: meia árvore ainda
        acha regra, e falhar aqui deixaria a origem inteira inacessível.
        """
        self._assert_allowed(source)

        cache_file = self._cache_dir / f"{source.key.replace('/', '__')}__{source.ref}.json"
        if use_cache and (cached := self._read_cache(cache_file)) is not None:
            self.stats.cached_trees += 1
            return [path for path in cached if source.accepts(path)]

        payload = self._get(source.tree_url()).json()
        paths = [
            item["path"]
            for item in payload.get("tree", [])
            if item.get("type") == "blob" and item.get("path")
        ]
        if payload.get("truncated"):
            self.stats.errors.append(
                f"{source.slug}: a árvore veio truncada pelo GitHub; a busca viu "
                f"{len(paths)} arquivos, não o repositório inteiro."
            )

        self._write_cache(cache_file, paths)
        return [path for path in paths if source.accepts(path)]

    def fetch_file(self, source: TrustedSource, path: str) -> str:
        """Conteúdo cru de um arquivo da origem."""
        self._assert_allowed(source)
        if not source.accepts(path):
            raise NotAllowedError(
                f"'{path}' está fora dos caminhos de regra declarados para {source.slug}."
            )

        response = self._get(source.raw_url(path), accept="text/plain")
        self.stats.files_read += 1
        return response.text

    def search_code(self, source: TrustedSource, terms: list[str], limit: int = 30) -> list[str]:
        """Caminhos cujo **conteúdo** casa com os termos. Exige token.

        A busca de código do GitHub é o único caminho que enxerga dentro do
        arquivo sem baixá-lo, e ela é autenticada — sem token não existe. Por
        isso a estratégia principal continua sendo a árvore: a ferramenta
        precisa funcionar para quem clonou o repositório e não configurou nada.
        """
        self._assert_allowed(source)
        if not self._token or not terms:
            return []

        # `OR` explícito: uma pergunta em linguagem natural raramente tem todos
        # os termos no mesmo arquivo, e a busca do GitHub usa AND por padrão.
        expression = " OR ".join(terms[:6])
        try:
            payload = self._get(
                "https://api.github.com/search/code",
                params={"q": f"{expression} repo:{source.slug}", "per_page": min(limit, 100)},
            ).json()
        except DiscoveryError as error:
            # A busca de código é o caminho opcional: quando ela falha (cota
            # própria, indexação incompleta do repositório), a árvore ainda
            # responde. Registrar e seguir é melhor que derrubar a busca toda.
            self.stats.errors.append(f"{source.slug}: busca de código indisponível ({error}).")
            return []

        return [
            item["path"]
            for item in payload.get("items", [])
            if item.get("path") and source.accepts(item["path"])
        ]

    # -- cache --------------------------------------------------------------

    def _read_cache(self, path: Path) -> list[str] | None:
        try:
            if not path.is_file() or time.time() - path.stat().st_mtime > TREE_TTL_SECONDS:
                return None
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _write_cache(self, path: Path, paths: list[str]) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(paths), encoding="utf-8")
        except OSError:
            # Cache é otimização. Disco cheio ou somente-leitura não deve
            # impedir a busca de funcionar.
            pass


def probe_repository(slug: str, token: str = "", timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict:
    """Confere que um repositório existe e devolve o branch padrão dele.

    **A única leitura fora da allowlist do projeto, e por um motivo explícito:**
    é o passo de *cadastrar* uma origem, disparado por quem opera digitando o
    slug — não por um prompt, não por uma regra, não por conteúdo de terceiro.
    Sem isto, cadastrar um repositório com nome errado ou branch errado só
    falharia na primeira busca, e o sintoma seria "a descoberta não acha nada"
    em vez de "esse repositório não existe".

    Lê apenas o metadado do repositório: nunca conteúdo de arquivo.
    """
    try:
        # A mesma normalização do cadastro, e no mesmo lugar do fluxo: quem
        # cola a URL do GitHub precisa chegar até aqui, não esbarrar antes.
        cleaned = normalize_slug(slug)
    except ValueError as error:
        raise DiscoveryError(str(error)) from error

    url = f"https://api.github.com/repos/{cleaned}"
    _assert_host_allowed(url)

    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    if token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"

    try:
        response = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=False)
    except httpx.HTTPError as error:
        raise DiscoveryError(f"não deu para alcançar o GitHub: {error}") from error

    if response.status_code == 404:
        raise DiscoveryError(
            f"O GitHub não tem um repositório público em '{cleaned}'. Confira o "
            "nome do dono e do repositório."
        )
    if response.status_code in (403, 429):
        raise RateLimitError(
            "O GitHub recusou por limite de requisições. Configure GITHUB_TOKEN no "
            ".env do servidor ou tente de novo mais tarde."
        )
    if response.status_code >= 400:
        raise DiscoveryError(f"o GitHub respondeu {response.status_code} ao consultar {cleaned}.")

    payload = response.json()
    return {
        "slug": payload.get("full_name") or cleaned,
        "ref": payload.get("default_branch") or "main",
        "description": (payload.get("description") or "").strip(),
        "stars": payload.get("stargazers_count") or 0,
        "archived": bool(payload.get("archived")),
    }
