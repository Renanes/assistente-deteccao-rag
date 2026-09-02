"""Descoberta de novos casos de uso em repositórios confiáveis.

Fluxo: um pedido em linguagem natural vira um plano de busca, a busca percorre
**apenas** os repositórios cadastrados como confiáveis, e o que ela encontra
volta como proposta com a procedência anexada. Nada entra no acervo sem
aprovação explícita.

Os quatro módulos, na ordem em que o fluxo os atravessa:

- `sources`   — a lista de repositórios confiáveis (o limite do que se enxerga)
- `github`    — o acesso à rede, restrito a essa lista
- `search`    — prompt → termos → candidatos → propostas pontuadas
- `proposals` — o estado das decisões e o único caminho que escreve no índice
"""

from .github import DiscoveryError, GitHubClient, NotAllowedError, RateLimitError, probe_repository
from .proposals import ProposalStatus, approve, list_proposals, record_findings, reject
from .search import DiscoveryResult, Proposal, SearchPlan, discover, plan_search
from .sources import SEED_SOURCES, RuleFormat, TrustedSource, load_sources

__all__ = [
    "SEED_SOURCES",
    "DiscoveryError",
    "DiscoveryResult",
    "GitHubClient",
    "NotAllowedError",
    "Proposal",
    "ProposalStatus",
    "RateLimitError",
    "RuleFormat",
    "SearchPlan",
    "TrustedSource",
    "approve",
    "discover",
    "list_proposals",
    "load_sources",
    "plan_search",
    "probe_repository",
    "record_findings",
    "reject",
]
