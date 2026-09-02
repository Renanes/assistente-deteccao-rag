"""Linha de comando da descoberta — o mesmo fluxo da interface, sem navegador.

Uso:
    python -m src.discovery.run sources                      # lista as origens
    python -m src.discovery.run sources --add owner/repo --format sigma
    python -m src.discovery.run sources --remove owner/repo
    python -m src.discovery.run search "exfiltração de dados por DNS"
    python -m src.discovery.run pending
    python -m src.discovery.run approve sigma:<id>
    python -m src.discovery.run reject  sigma:<id>

Existe por dois motivos concretos, e não por simetria: dá para conferir o que a
busca faz sem depender da interface (útil quando algo dá errado), e a aprovação
por linha de comando é o caminho de quem quer indexar um lote sem clicar doze
vezes.
"""

from __future__ import annotations

import argparse
import sys

from ..embeddings import store
from ..providers import ProviderError, get_embedding_provider, get_llm_provider, get_settings
from . import proposals as proposals_module
from . import sources as sources_module
from .github import DiscoveryError, GitHubClient, probe_repository
from .search import discover
from .sources import RuleFormat, TrustedSource


def _connect():
    return store.connect(get_settings().resolved_database_url())


def _print_sources(items: list[TrustedSource]) -> None:
    if not items:
        print("nenhuma origem cadastrada.")
        return
    print(f"{len(items)} origens confiáveis:")
    for source in items:
        marca = " " if source.enabled else "×"
        prefixos = ", ".join(source.path_prefixes) or "(repositório inteiro)"
        semente = " [semente]" if source.is_seed else ""
        print(f" {marca} {source.slug}@{source.ref} — {source.rule_format.value}{semente}")
        print(f"     {source.label} · {prefixos}")
        if source.note:
            print(f"     {source.note}")


def cmd_sources(args: argparse.Namespace) -> int:
    settings = get_settings()
    with _connect() as conn:
        if args.add:
            try:
                # Confere o repositório antes de cadastrar: sem isto, um nome
                # errado só apareceria como "a busca não acha nada".
                info = probe_repository(args.add, settings.github_token)
            except DiscoveryError as error:
                print(f"erro: {error}", file=sys.stderr)
                return 1

            source = TrustedSource(
                slug=info["slug"],
                ref=args.ref or info["ref"],
                label=args.label or info["slug"].split("/")[-1],
                rule_format=RuleFormat(args.format),
                path_prefixes=args.path or [],
                note=args.note or info["description"],
            )
            sources_module.ensure_schema(conn)
            sources_module.seed_if_empty(conn)
            sources_module.upsert_source(conn, source)
            conn.commit()
            print(f"cadastrada: {source.slug}@{source.ref} ({source.rule_format.value})")
            if info["archived"]:
                print("  aviso: o repositório está arquivado — não recebe regra nova.")

        if args.remove:
            sources_module.ensure_schema(conn)
            removed = sources_module.remove_source(conn, args.remove)
            conn.commit()
            print(f"removida: {args.remove}" if removed else f"não cadastrada: {args.remove}")

        _print_sources(sources_module.load_sources(conn))
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    settings = get_settings()

    llm = None
    if not args.no_model:
        try:
            llm = get_llm_provider(settings)
        except ProviderError:
            # Sem chave de geração a busca continua, com termos determinísticos.
            llm = None

    with _connect() as conn:
        catalogo = [
            source for source in sources_module.load_sources(conn) if source.enabled
        ]
        if args.source:
            wanted = {slug.lower() for slug in args.source}
            catalogo = [source for source in catalogo if source.key in wanted]
            if not catalogo:
                print("erro: nenhuma das origens pedidas está cadastrada.", file=sys.stderr)
                return 1

        known = proposals_module.indexed_uids(conn)

        with GitHubClient(catalogo, token=settings.github_token) as client:
            try:
                result = discover(args.prompt, catalogo, client, known_uids=known, llm=llm)
            except DiscoveryError as error:
                print(f"erro: {error}", file=sys.stderr)
                return 1

        registradas = proposals_module.record_findings(conn, args.prompt, result.proposals)

    origem_termos = f"modelo {result.plan.model}" if result.plan.expanded_by_model else "extração local"
    print(f"termos ({origem_termos}): {', '.join(result.plan.terms) or '—'}")
    if result.plan.mitre_techniques:
        print(f"técnicas pedidas: {', '.join(result.plan.mitre_techniques)}")
    print(
        f"{len(result.sources_searched)} origens · {result.files_read} arquivos lidos · "
        f"{result.parsed} regras lidas · {result.already_indexed} já no acervo"
    )
    for warning in result.warnings:
        print(f"  aviso: {warning}")

    if not registradas:
        print("nenhuma regra nova encontrada para esse pedido.")
        return 0

    print(f"\n{len(registradas)} propostas:")
    for proposal in registradas:
        marca = {"pending": "•", "approved": "✓", "rejected": "×"}.get(proposal.status, "•")
        print(f" {marca} [{proposal.score:5.1f}] {proposal.rule.title}")
        print(f"     {proposal.rule_uid} · {proposal.source_slug}/{proposal.source_path}")
        if proposal.matched_techniques:
            print(f"     técnicas: {', '.join(proposal.matched_techniques)}")
    print("\naprove com: python -m src.discovery.run approve <rule_uid>")
    return 0


def cmd_pending(args: argparse.Namespace) -> int:
    with _connect() as conn:
        items = proposals_module.list_proposals(conn, status=args.status)
        counts = proposals_module.count_by_status(conn)
    print(
        f"pendentes: {counts.pending} · aprovadas: {counts.approved} · "
        f"recusadas: {counts.rejected}"
    )
    for proposal in items:
        print(f" [{proposal.score:5.1f}] {proposal.rule_uid} — {proposal.rule.title}")
        print(f"        {proposal.source_url}")
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    settings = get_settings()
    with _connect() as conn:
        try:
            if args.command == "reject":
                proposal = proposals_module.reject(conn, args.rule_uid)
                print(f"recusada: {proposal.rule_uid} — {proposal.rule.title}")
                return 0

            embedding = get_embedding_provider(settings)
            proposal, written = proposals_module.approve(conn, args.rule_uid, embedding)
        except LookupError as error:
            print(f"erro: {error}", file=sys.stderr)
            return 1
        except ProviderError as error:
            print(f"erro de provedor: {error}", file=sys.stderr)
            return 1

    print(f"indexada: {proposal.rule_uid} — {proposal.rule.title} ({written} chunk)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_sources = sub.add_parser("sources", help="lista, adiciona ou remove origens confiáveis")
    p_sources.add_argument("--add", metavar="dono/repo")
    p_sources.add_argument("--remove", metavar="dono/repo")
    p_sources.add_argument(
        "--format",
        choices=[item.value for item in RuleFormat],
        default=RuleFormat.SIGMA.value,
        help="formato das regras do repositório (padrão: sigma).",
    )
    p_sources.add_argument("--ref", help="branch ou tag (padrão: o branch default do repositório).")
    p_sources.add_argument("--label", help="nome legível na interface.")
    p_sources.add_argument("--path", action="append", help="subcaminho de regras; pode repetir.")
    p_sources.add_argument("--note", help="por que esta origem é confiável.")

    p_search = sub.add_parser("search", help="procura casos de uso novos nas origens confiáveis")
    p_search.add_argument("prompt")
    p_search.add_argument("--source", action="append", help="restringe a uma origem; pode repetir.")
    p_search.add_argument(
        "--no-model",
        action="store_true",
        help="não usa LLM para expandir os termos (extração determinística).",
    )

    p_pending = sub.add_parser("pending", help="lista as propostas registradas")
    p_pending.add_argument(
        "--status", default="pending", choices=["pending", "approved", "rejected"]
    )

    for name, help_text in (("approve", "indexa a regra proposta"), ("reject", "recusa a proposta")):
        p_decide = sub.add_parser(name, help=help_text)
        p_decide.add_argument("rule_uid")

    args = parser.parse_args()

    try:
        if args.command == "sources":
            return cmd_sources(args)
        if args.command == "search":
            return cmd_search(args)
        if args.command == "pending":
            return cmd_pending(args)
        return cmd_decide(args)
    except Exception as error:  # noqa: BLE001 - a mensagem crua é o que ajuda num CLI
        print(f"erro: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
