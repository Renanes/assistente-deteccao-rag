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
    AskRequest,
    AskResponse,
    GroundingOut,
    HealthResponse,
    ModelOut,
    ModelsResponse,
    ProviderStatusOut,
    RuleOut,
    SettingsResponse,
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
