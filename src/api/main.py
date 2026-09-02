"""API FastAPI que expõe o pipeline RAG e serve a interface de demonstração.

Uso:
    uvicorn src.api.main:app --reload
    python -m src.api.main

Duas decisões de operação:

1. **Uma conexão por requisição**, em vez de uma conexão de aplicação
   compartilhada. Endpoints síncronos do FastAPI rodam num pool de threads e
   uma conexão psycopg não é thread-safe — compartilhá-la produziria erro
   intermitente sob concorrência, que é a pior categoria de bug para uma demo.
   O custo é alguns milissegundos por requisição.

2. **Os provedores são resolvidos uma vez, no arranque — mas chave faltando
   deixou de ser fatal.** A versão original desta decisão derrubava a aplicação
   se qualquer chave faltasse, para quem sobe ver a causa na hora. Isso passou a
   ser errado quando as chaves puderam vir de quem usa (ver `credentials.py`):
   subir sem chave nenhuma no `.env` virou um estado inicial legítimo, e não uma
   configuração quebrada. O que **continua** derrubando o arranque é
   configuração de fato inválida — `EMBEDDING_PROVIDER` com nome desconhecido,
   ou modelo de embedding sem dimensão registrada. A distinção é entre "falta um
   segredo que alguém ainda vai trazer" e "esta configuração não existe".
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ..chunking.chunk import truncate_query
from ..discovery import github as discovery_github
from ..discovery import proposals as discovery_proposals
from ..discovery import sources as discovery_sources
from ..discovery.search import Proposal, discover
from ..embeddings import store
from ..providers import (
    CATALOG,
    EmbeddingProvider,
    LLMProvider,
    ProviderError,
    get_embedding_provider,
    get_llm_provider,
    get_settings,
)
from ..providers.config import Settings
from .credentials import (
    PROVIDER_HEADERS,
    PROVIDER_ROLES,
    PROVIDER_SETTINGS_FIELD,
    InvalidKeyError,
    apply_keys,
    keys_from_headers,
    redact,
)
from ..rag.pipeline import RagPipeline
from ..retrieval.search import HybridRetriever, SearchFilters
from ..retrieval.techniques import UNTAGGED_LABEL, load_corpus_techniques
from .schemas import (
    AddSourceRequest,
    AskRequest,
    AskResponse,
    DecideRequest,
    DecideResponse,
    DiscoverRequest,
    DiscoverResponse,
    GroundingOut,
    HealthResponse,
    ModelOut,
    ModelsResponse,
    ProposalOut,
    ProposalsResponse,
    ProviderStatusOut,
    RuleOut,
    SettingsResponse,
    SourcesResponse,
    TrustedSourceOut,
    TechniqueFamilyOut,
    TechniqueOut,
    TechniquesResponse,
)

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


class Runtime:
    """O que é montado uma vez e reusado entre requisições."""

    settings = None
    embedding: EmbeddingProvider | None = None
    #: Provedor do modelo padrão, o do `.env`.
    llm: LLMProvider | None = None
    #: Provedores já construídos, indexados pelo id do modelo.
    #:
    #: Construir um cliente de SDK por requisição desperdiçaria a conexão HTTP
    #: reaproveitada; construir todos no arranque puniria quem só usa um. O
    #: cache preguiçoso paga o custo uma vez, no primeiro uso de cada modelo.
    #: A escrita concorrente é benigna: no pior caso duas threads constroem o
    #: mesmo provedor e uma sobrescreve a outra — os clientes são equivalentes.
    llm_by_model: dict[str, LLMProvider] = {}

    #: Por que o provedor do `.env` não pôde ser construído, quando foi só falta
    #: de chave. Vira material de `/api/settings`, para a interface dizer o que
    #: falta em vez de deixar a primeira pergunta falhar.
    embedding_error: str | None = None
    llm_error: str | None = None

    def llm_for(self, model: str | None) -> LLMProvider:
        """Devolve o provedor do modelo pedido, ou o padrão se não houver pedido.

        **Só para as chaves do `.env`.** Um provedor construído com chave de
        visitante nunca pode passar por aqui: o cache é compartilhado entre
        requisições e entregaria a credencial de um visitante ao próximo.
        Ver `_providers_for` e `credentials.py`.
        """
        assert self.settings is not None
        if self.llm is None:
            raise ProviderError(
                self.llm_error
                or "Nenhum provedor de geração configurado. Informe uma chave em Configuração."
            )
        if not model or model == self.llm.model:
            return self.llm

        cached = self.llm_by_model.get(model)
        if cached is not None:
            return cached

        provider = get_llm_provider(self.settings, model=model)
        self.llm_by_model[model] = provider
        return provider


runtime = Runtime()


def _missing_key_only(settings: Settings, provider: str) -> bool:
    """Se o provedor é conhecido e o único problema é a chave estar vazia.

    Separa "falta um segredo" de "esta configuração não existe". A primeira é
    tolerável no arranque desde que as chaves possam vir de quem usa; a segunda
    é erro de quem configurou e continua derrubando a aplicação.
    """
    field = PROVIDER_SETTINGS_FIELD.get(provider.strip().lower())
    return bool(field) and not getattr(settings, field, "")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    runtime.settings = settings
    runtime.embedding = runtime.llm = None
    runtime.embedding_error = runtime.llm_error = None

    # Falhar no arranque continua sendo o certo para configuração inválida —
    # quem sobe a aplicação vê a causa na hora, e não na primeira pergunta. O
    # que mudou é que falta de chave não é mais configuração inválida: é o
    # estado normal de quem acabou de clonar o repositório e vai trazer a chave
    # pela interface.
    try:
        runtime.embedding = get_embedding_provider(settings)
    except ProviderError as error:
        if not _missing_key_only(settings, settings.embedding_provider):
            raise RuntimeError(f"configuração de provedor inválida: {error}") from error
        runtime.embedding_error = str(error)

    try:
        runtime.llm = get_llm_provider(settings)
    except ProviderError as error:
        if not _missing_key_only(settings, settings.llm_provider):
            raise RuntimeError(f"configuração de provedor inválida: {error}") from error
        runtime.llm_error = str(error)

    runtime.llm_by_model = {runtime.llm.model: runtime.llm} if runtime.llm else {}
    yield


app = FastAPI(
    title="Assistente de Detecção",
    description="RAG sobre regras públicas do SigmaHQ, Splunk ESCU e YARA-L.",
    lifespan=lifespan,
)


def _connect():
    assert runtime.settings is not None
    return store.connect(runtime.settings.resolved_database_url())


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    try:
        with _connect() as conn:
            row = conn.execute("SELECT count(*) FROM rule_chunks").fetchone()
            indexed = row[0] if row else 0
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"banco indisponível: {error}") from error

    if not indexed:
        status = "sem corpus indexado"
    elif runtime.embedding is None:
        # Sem embedding não há como consultar, mesmo com o corpus indexado — a
        # pergunta precisa virar vetor antes de qualquer coisa.
        status = "aguardando chave de embedding"
    elif runtime.llm is None:
        status = "aguardando chave de geração"
    else:
        status = "ok"

    return HealthResponse(
        status=status,
        indexed_chunks=indexed,
        embedding_model=runtime.embedding.model if runtime.embedding else "",
        llm_provider=runtime.llm.name if runtime.llm else "",
        llm_model=runtime.llm.model if runtime.llm else "",
    )


@app.get("/api/models", response_model=ModelsResponse)
def models() -> ModelsResponse:
    """O catálogo de modelos de geração, como a interface monta o seletor.

    Um modelo cujo provedor não tem chave configurada vem com `available:
    false` em vez de ser omitido: quem avalia o projeto deve conseguir ver que
    a alternativa existe e o que falta para usá-la.
    """
    assert runtime.settings is not None and runtime.llm is not None

    default_model = runtime.llm.model
    return ModelsResponse(
        default_model=default_model,
        models=[
            ModelOut(
                id=card.id,
                provider=card.provider,
                label=card.label,
                note=card.note,
                price_in=card.price_in,
                price_out=card.price_out,
                available=runtime.settings.has_key_for(card.provider),
                is_default=card.id == default_model,
            )
            for card in CATALOG
        ],
    )


@app.get("/api/techniques", response_model=TechniquesResponse)
def techniques() -> TechniquesResponse:
    """O inventário de técnicas ATT&CK do acervo indexado.

    Sem cache: a agregação custa ~70 ms sobre as 5.664 linhas, e um cache
    precisaria ser invalidado a cada reindexação para não servir número velho.
    Cache aqui seria complexidade comprando um ganho que não existe.
    """
    try:
        with _connect() as conn:
            inventory = load_corpus_techniques(conn)
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"banco indisponível: {error}") from error

    return TechniquesResponse(
        families=[
            TechniqueFamilyOut(
                parent=TechniqueOut(**family.parent.model_dump()),
                subtechniques=[TechniqueOut(**item.model_dump()) for item in family.subtechniques],
                rule_count=family.rule_count,
                parent_declared=family.parent_declared,
            )
            for family in inventory.families
        ],
        total_rules=inventory.total_rules,
        untagged_count=inventory.untagged_count,
        untagged_label=UNTAGGED_LABEL,
        tagged_count=inventory.tagged_count,
        distinct_techniques=inventory.distinct_techniques,
        attack_version=inventory.attack_version,
        unknown_ids=inventory.unknown_ids,
        deprecated_ids=inventory.deprecated_ids,
        revoked_ids=inventory.revoked_ids,
    )


@app.get("/api/settings", response_model=SettingsResponse)
def settings_status() -> SettingsResponse:
    """O que está configurado — **nunca** o valor de nenhuma chave.

    Este endpoint existe para a interface dizer o que falta, e por isso é o
    lugar onde uma credencial mais facilmente vazaria. A resposta é construída
    a partir de booleanos e nomes de provedor; o valor da chave não é lido aqui
    em momento nenhum, nem redigido — simplesmente não entra.
    """
    assert runtime.settings is not None
    settings = runtime.settings

    # Com que modelo o corpus foi realmente indexado. É a informação que evita
    # o modo de falha mais confuso do "traga sua chave": vetores de modelos
    # diferentes não são comparáveis, então uma chave que só cobre outro modelo
    # de embedding devolve vizinhos errados em vez de erro.
    corpus_model = ""
    try:
        with _connect() as conn:
            info = store.describe_corpus(conn)
            corpus_model = info.models[0] if info.models else ""
    except Exception:  # noqa: BLE001 - banco fora não impede reportar as chaves
        corpus_model = ""

    return SettingsResponse(
        providers=[
            ProviderStatusOut(
                provider=provider,
                configured_in_env=bool(getattr(settings, field, "")),
                roles=PROVIDER_ROLES[provider],
                header=PROVIDER_HEADERS[provider],
            )
            for provider, field in PROVIDER_SETTINGS_FIELD.items()
        ],
        embedding_provider=settings.embedding_provider,
        embedding_model=settings.openai_embedding_model
        if settings.embedding_provider == "openai"
        else settings.voyage_embedding_model,
        corpus_embedding_model=corpus_model,
        embedding_ready=runtime.embedding is not None,
        llm_ready=runtime.llm is not None,
    )


def _providers_for(
    keys: dict[str, str], model: str | None
) -> tuple[EmbeddingProvider, LLMProvider]:
    """Resolve os provedores desta requisição, honrando a chave do visitante.

    **Nada construído com chave de visitante entra em cache.** O cache existe
    para reaproveitar conexão HTTP entre requisições, e é exatamente por ser
    compartilhado que guardar ali um cliente com credencial de visitante a
    entregaria ao próximo. Sem chave no cabeçalho, o caminho é o de sempre.
    """
    assert runtime.settings is not None

    if not keys:
        if runtime.embedding is None:
            # A mensagem da camada de provedores manda editar o `.env`, o que
            # era a única saída antes de existir o painel. Agora há duas, e a
            # mais rápida para quem só quer experimentar é a primeira.
            raise ProviderError(
                "Falta a chave que embedda a pergunta — sem ela nenhuma consulta "
                "roda, nem com chave de geração configurada. Informe uma chave de "
                "OpenAI ou Voyage em Configuração, ou preencha o .env do servidor. "
                f"(Detalhe: {runtime.embedding_error})"
            )
        return runtime.embedding, runtime.llm_for(model)

    effective = apply_keys(runtime.settings, keys)
    return get_embedding_provider(effective), get_llm_provider(effective, model=model)


@app.post("/api/ask", response_model=AskResponse)
def ask(payload: AskRequest, http_request: Request) -> AskResponse:
    # Chave trazida por quem usa, válida só nesta requisição. Cabeçalho ausente
    # é o caso normal: significa "use o `.env`".
    try:
        keys = keys_from_headers(http_request.headers)
    except InvalidKeyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    # Chave ausente, modelo fora do catálogo ou provedor sem credencial são erro
    # de pedido (400), não falha de serviço (503): quem pediu é que precisa
    # corrigir, e a mensagem diz o quê.
    try:
        embedding, llm = _providers_for(keys, payload.model)
    except ProviderError as error:
        raise HTTPException(status_code=400, detail=redact(str(error))) from error

    # Filtro explícito do catálogo. `None` preserva o caminho antigo, em que os
    # filtros são deduzidos do texto da pergunta; qualquer escolha na interface
    # substitui a dedução por inteiro, porque quem clicou já disse o que queria.
    filters = None
    if payload.mitre_techniques or payload.include_untagged:
        filters = SearchFilters(
            mitre_techniques=tuple(dict.fromkeys(payload.mitre_techniques)),
            include_untagged=payload.include_untagged,
        )

    started = time.perf_counter()
    try:
        with _connect() as conn:
            pipeline = RagPipeline(
                HybridRetriever(conn, embedding), llm, top_k=payload.top_k
            )
            result = pipeline.answer(payload.question, filters=filters)
    except Exception as error:  # noqa: BLE001
        # `redact` porque a mensagem de erro de um SDK viaja para a resposta
        # HTTP, e uma credencial não pode ir junto por descuido.
        raise HTTPException(status_code=503, detail=redact(str(error))) from error

    cited_uids = {rule.rule_uid for rule in result.citations}
    rules = [
        RuleOut(
            index=index,
            cited=rule.rule_uid in cited_uids,
            rule_uid=rule.rule_uid,
            title=rule.title,
            source=rule.source,
            source_url=rule.source_url,
            query=rule.query,
            query_language=rule.query_language,
            query_truncated=rule.query_truncated,
            platforms=rule.platforms,
            mitre_techniques=rule.mitre_techniques,
            severity=rule.severity,
            similarity=rule.similarity,
            matched_by=rule.matched_by,
            ranks=rule.ranks,
        )
        for index, rule in enumerate(result.retrieved, start=1)
    ]

    check = result.citation_check
    return AskResponse(
        question=result.question,
        answer=result.answer,
        rules=rules,
        grounding=GroundingOut(
            is_grounded=check.is_grounded,
            cited=list(check.cited),
            invalid=list(check.invalid),
            uncited=check.uncited,
        ),
        relaxed_filters=bool(result.search and result.search.relaxed_filters),
        filtered_techniques=list(result.search.filters.mitre_techniques) if result.search else [],
        filtered_untagged=bool(result.search and result.search.filters.include_untagged),
        answered_without_model=result.answered_without_model,
        answer_truncated=result.answer_truncated,
        llm_provider=result.llm_provider,
        llm_model=result.llm_model,
        embedding_model=embedding.model,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ---------------------------------------------------------------------------
# Descoberta de novos casos de uso
#
# A propriedade que estes endpoints preservam é uma só: **a busca não decide**.
# `/api/discovery/search` lê repositórios confiáveis e devolve propostas;
# `/api/discovery/decide` é o único caminho que escreve no acervo, e ele exige
# um `rule_uid` que já esteja registrado como proposta. Não há endpoint que
# encontre e indexe no mesmo passo — a separação é o desenho, não uma etapa
# que faltou juntar.
# ---------------------------------------------------------------------------


def _embedding_for(keys: dict[str, str]) -> EmbeddingProvider:
    """O provedor de embedding desta requisição, honrando a chave do visitante.

    Separado de `_providers_for` porque aprovar uma regra não precisa de modelo
    de geração: exigir chave de LLM para indexar seria barrar quem tem tudo o
    que a operação realmente usa.
    """
    assert runtime.settings is not None
    if not keys:
        if runtime.embedding is None:
            raise ProviderError(
                "Falta a chave que gera os vetores. Sem ela a regra aprovada não pode "
                "ser indexada. Informe uma chave de OpenAI ou Voyage em Configuração."
            )
        return runtime.embedding
    return get_embedding_provider(apply_keys(runtime.settings, keys))


def _llm_or_none(keys: dict[str, str], model: str | None = None) -> LLMProvider | None:
    """O modelo que traduz o pedido em termos de busca, se houver um disponível.

    `None` não é falha: a descoberta cai na extração determinística de termos e
    continua funcionando. Ver `discovery/search.plan_search`.
    """
    assert runtime.settings is not None
    try:
        if not keys:
            return runtime.llm_for(model)
        return get_llm_provider(apply_keys(runtime.settings, keys), model=model)
    except ProviderError:
        return None


def _source_out(source: discovery_sources.TrustedSource) -> TrustedSourceOut:
    return TrustedSourceOut(
        slug=source.slug,
        ref=source.ref,
        label=source.label,
        rule_format=source.rule_format.value,
        path_prefixes=list(source.path_prefixes),
        note=source.note,
        enabled=source.enabled,
        is_seed=source.is_seed,
    )


def _sources_payload(conn) -> SourcesResponse:  # type: ignore[no-untyped-def]
    assert runtime.settings is not None
    return SourcesResponse(
        sources=[_source_out(source) for source in discovery_sources.load_sources(conn)],
        formats=[item.value for item in discovery_sources.RuleFormat],
        has_github_token=bool(runtime.settings.github_token),
    )


def _proposal_out(proposal: Proposal) -> ProposalOut:
    rule = proposal.rule
    # A lógica mostrada na ficha passa pelo mesmo teto que a indexação aplica
    # (`chunking.truncate_query`). Não é só economia de banda: a cauda do corpus
    # é extrema — há regra Sigma com 250 KB de lista de hash — e uma proposta
    # dessas travaria a página. Mostrar o que de fato entraria no acervo é
    # também a informação mais honesta para quem decide.
    query, query_truncated = truncate_query(rule.query)
    return ProposalOut(
        rule_uid=proposal.rule_uid,
        status=proposal.status,
        title=rule.title,
        description=rule.description,
        query=query,
        query_truncated=query_truncated,
        query_language=rule.query_language.value,
        platforms=list(rule.platforms),
        mitre_techniques=list(rule.mitre_techniques),
        severity=rule.severity.value if rule.severity else None,
        author=rule.author,
        references=list(rule.references),
        source_slug=proposal.source_slug,
        source_label=proposal.source_label,
        source_path=proposal.source_path,
        source_url=proposal.source_url,
        rule_source=rule.source.value,
        score=proposal.score,
        matched_terms=list(proposal.matched_terms),
        matched_techniques=list(proposal.matched_techniques),
        found_by=list(proposal.found_by),
    )


@app.get("/api/sources", response_model=SourcesResponse)
def list_trusted_sources() -> SourcesResponse:
    """Os repositórios em que a descoberta pode procurar. Nada além deles."""
    try:
        with _connect() as conn:
            payload = _sources_payload(conn)
            conn.commit()  # a primeira chamada semeia a tabela
            return payload
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"banco indisponível: {error}") from error


@app.post("/api/sources", response_model=SourcesResponse)
def add_trusted_source(payload: AddSourceRequest) -> SourcesResponse:
    """Cadastra um repositório confiável, conferindo antes que ele exista.

    A conferência no GitHub é o que evita o pior resultado possível deste
    formulário: um cadastro aceito com nome ou branch errado, que não falha
    aqui e sim depois, como "a busca não acha nada nessa origem".
    """
    assert runtime.settings is not None

    try:
        rule_format = discovery_sources.RuleFormat(payload.rule_format)
    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{payload.rule_format}' não é um formato que os parsers leem. "
                f"Use um destes: {', '.join(item.value for item in discovery_sources.RuleFormat)}."
            ),
        ) from error

    try:
        info = discovery_github.probe_repository(payload.slug, runtime.settings.github_token)
    except discovery_github.RateLimitError as error:
        raise HTTPException(status_code=429, detail=redact(str(error))) from error
    except discovery_github.DiscoveryError as error:
        raise HTTPException(status_code=400, detail=redact(str(error))) from error

    try:
        source = discovery_sources.TrustedSource(
            slug=info["slug"],
            ref=payload.ref or info["ref"],
            label=payload.label or info["slug"].split("/")[-1],
            rule_format=rule_format,
            path_prefixes=payload.path_prefixes,
            note=payload.note or info["description"],
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    try:
        with _connect() as conn:
            discovery_sources.ensure_schema(conn)
            discovery_sources.seed_if_empty(conn)
            discovery_sources.upsert_source(conn, source)
            conn.commit()
            return _sources_payload(conn)
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"banco indisponível: {error}") from error


@app.delete("/api/sources/{owner}/{repo}", response_model=SourcesResponse)
def remove_trusted_source(owner: str, repo: str) -> SourcesResponse:
    """Descadastra uma origem — inclusive uma das que vieram pré-cadastradas.

    Sementes são um ponto de partida, não uma decisão imutável de quem escreveu
    a ferramenta. Removida uma, ela não volta: a semeadura só roda com a tabela
    inteiramente vazia.
    """
    try:
        with _connect() as conn:
            discovery_sources.ensure_schema(conn)
            if not discovery_sources.remove_source(conn, f"{owner}/{repo}"):
                raise HTTPException(
                    status_code=404, detail=f"'{owner}/{repo}' não está cadastrado."
                )
            conn.commit()
            return _sources_payload(conn)
    except HTTPException:
        raise
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"banco indisponível: {error}") from error


@app.post("/api/discovery/search", response_model=DiscoverResponse)
def discovery_search(payload: DiscoverRequest, http_request: Request) -> DiscoverResponse:
    """Procura casos de uso novos nas origens confiáveis. **Não indexa nada.**"""
    assert runtime.settings is not None

    try:
        keys = keys_from_headers(http_request.headers)
    except InvalidKeyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    started = time.perf_counter()
    try:
        with _connect() as conn:
            catalog = [
                source for source in discovery_sources.load_sources(conn) if source.enabled
            ]
            conn.commit()

            if payload.sources:
                wanted = {slug.strip().lower() for slug in payload.sources}
                catalog = [source for source in catalog if source.key in wanted]

            if not catalog:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Nenhuma origem confiável habilitada para buscar. Cadastre um "
                        "repositório em Origens confiáveis antes de pesquisar."
                    ),
                )

            known = discovery_proposals.indexed_uids(conn)
            llm = _llm_or_none(keys)

            with discovery_github.GitHubClient(
                catalog, token=runtime.settings.github_token
            ) as client:
                result = discover(
                    payload.prompt,
                    catalog,
                    client,
                    known_uids=known,
                    llm=llm,
                    limit=payload.limit,
                )

            recorded = discovery_proposals.record_findings(conn, payload.prompt, result.proposals)
    except HTTPException:
        raise
    except discovery_github.RateLimitError as error:
        raise HTTPException(status_code=429, detail=redact(str(error))) from error
    except discovery_github.NotAllowedError as error:
        raise HTTPException(status_code=403, detail=redact(str(error))) from error
    except discovery_github.DiscoveryError as error:
        raise HTTPException(status_code=502, detail=redact(str(error))) from error
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=redact(str(error))) from error

    return DiscoverResponse(
        prompt=payload.prompt,
        proposals=[_proposal_out(proposal) for proposal in recorded],
        terms=list(result.plan.terms),
        techniques=list(result.plan.mitre_techniques),
        expanded_by_model=result.plan.expanded_by_model,
        model=result.plan.model,
        sources_searched=result.sources_searched,
        files_read=result.files_read,
        rules_parsed=result.parsed,
        already_indexed=result.already_indexed,
        requests=result.requests,
        rate_limit_remaining=result.rate_limit_remaining,
        warnings=result.warnings,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


@app.get("/api/discovery/proposals", response_model=ProposalsResponse)
def discovery_proposals_list(status: str = "pending") -> ProposalsResponse:
    """As propostas registradas, por estado. Sobrevive ao recarregar a página."""
    if status not in ("pending", "approved", "rejected", "all"):
        raise HTTPException(status_code=400, detail=f"estado desconhecido: '{status}'.")

    try:
        with _connect() as conn:
            items = discovery_proposals.list_proposals(
                conn, status=None if status == "all" else status
            )
            counts = discovery_proposals.count_by_status(conn)
            conn.commit()
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"banco indisponível: {error}") from error

    return ProposalsResponse(
        proposals=[_proposal_out(proposal) for proposal in items],
        pending=counts.pending,
        approved=counts.approved,
        rejected=counts.rejected,
    )


@app.post("/api/discovery/decide", response_model=DecideResponse)
def discovery_decide(payload: DecideRequest, http_request: Request) -> DecideResponse:
    """Aprova (indexa) ou recusa uma proposta. O único caminho de escrita."""
    if payload.decision not in ("approve", "reject"):
        raise HTTPException(
            status_code=400, detail="decisão precisa ser 'approve' ou 'reject'."
        )

    try:
        keys = keys_from_headers(http_request.headers)
    except InvalidKeyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    try:
        with _connect() as conn:
            if payload.decision == "reject":
                proposal = discovery_proposals.reject(conn, payload.rule_uid)
                return DecideResponse(
                    rule_uid=proposal.rule_uid,
                    status=proposal.status,
                    title=proposal.rule.title,
                    message="Recusada. Ela continua aparecendo em buscas, marcada como recusada.",
                )

            embedding = _embedding_for(keys)
            proposal, written = discovery_proposals.approve(conn, payload.rule_uid, embedding)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ProviderError as error:
        raise HTTPException(status_code=400, detail=redact(str(error))) from error
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=redact(str(error))) from error

    return DecideResponse(
        rule_uid=proposal.rule_uid,
        status=proposal.status,
        title=proposal.rule.title,
        indexed_chunks=written,
        message=(
            "Indexada no acervo. Já responde à busca."
            if written
            else "Já estava indexada — nada foi reescrito."
        ),
    )


# A interface é servida pela mesma aplicação de propósito: quem clona o
# repositório sobe um processo só e abre uma URL. Sem passo de build, sem
# servidor separado — critério de aceite da fase é alguém de fora conseguir
# rodar sem contexto adicional.
if FRONTEND_DIR.is_dir():

    @app.middleware("http")
    async def revalidar_estaticos(request, call_next):
        """Obriga o navegador a revalidar o CSS e o JS da interface.

        Sem `Cache-Control`, o navegador aplica frescor heurístico próprio e
        pode servir uma folha de estilo antiga junto com um HTML novo. Como o
        HTML é `no-cache` e os estáticos não eram, essa combinação acontecia de
        verdade: markup novo com nomes de classe velhos, ou seja, a página sem
        estilo nenhum. Foi relatado por quem usa, depois da reconstrução da
        interface.

        `no-cache` não proíbe o cache — obriga a perguntar se mudou. O `etag`
        que o StaticFiles já emite faz a resposta ser um 304 barato quando nada
        mudou, então o custo é um ida-e-volta por arquivo, não um download.
        """
        response = await call_next(request)
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.get("/")
    def index() -> FileResponse:
        # `no-cache` manda revalidar a cada carga — não proíbe o cache, obriga a
        # perguntar se mudou. Sem isto o navegador serve o HTML anterior por
        # heurística própria, e quem editou a interface fica olhando a versão
        # velha achando que a mudança não subiu. Aconteceu de fato aqui.
        return FileResponse(
            FRONTEND_DIR / "index.html", headers={"Cache-Control": "no-cache"}
        )

    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)


if __name__ == "__main__":
    main()
