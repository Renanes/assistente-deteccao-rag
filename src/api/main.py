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

2. **Os provedores são resolvidos uma vez, no arranque.** Se a chave estiver
   faltando ou o `EMBEDDING_PROVIDER` for inválido, a aplicação falha ao subir
   com a mensagem da camada de provedores, e não na primeira pergunta.
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ..embeddings import store
from ..providers import (
    EmbeddingProvider,
    LLMProvider,
    ProviderError,
    get_embedding_provider,
    get_llm_provider,
    get_settings,
)
from ..rag.pipeline import RagPipeline
from ..retrieval.search import HybridRetriever
from .schemas import AskRequest, AskResponse, GroundingOut, HealthResponse, RuleOut

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


class Runtime:
    """O que é montado uma vez e reusado entre requisições."""

    settings = None
    embedding: EmbeddingProvider | None = None
    llm: LLMProvider | None = None


runtime = Runtime()


@asynccontextmanager
async def lifespan(app: FastAPI):
    runtime.settings = get_settings()
    try:
        runtime.embedding = get_embedding_provider(runtime.settings)
        runtime.llm = get_llm_provider(runtime.settings)
    except ProviderError as error:
        # Falhar aqui é melhor que falhar na primeira pergunta: quem sobe a
        # aplicação vê a causa imediatamente.
        raise RuntimeError(f"configuração de provedor inválida: {error}") from error
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
    assert runtime.embedding is not None and runtime.llm is not None
    try:
        with _connect() as conn:
            row = conn.execute("SELECT count(*) FROM rule_chunks").fetchone()
            indexed = row[0] if row else 0
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"banco indisponível: {error}") from error

    return HealthResponse(
        status="ok" if indexed else "sem corpus indexado",
        indexed_chunks=indexed,
        embedding_model=runtime.embedding.model,
        llm_provider=runtime.llm.name,
        llm_model=runtime.llm.model,
    )


@app.post("/api/ask", response_model=AskResponse)
def ask(request: AskRequest) -> AskResponse:
    assert runtime.embedding is not None and runtime.llm is not None

    started = time.perf_counter()
    try:
        with _connect() as conn:
            pipeline = RagPipeline(
                HybridRetriever(conn, runtime.embedding), runtime.llm, top_k=request.top_k
            )
            result = pipeline.answer(request.question)
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=str(error)) from error

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
        answered_without_model=result.answered_without_model,
        answer_truncated=result.answer_truncated,
        llm_provider=result.llm_provider,
        llm_model=result.llm_model,
        embedding_model=runtime.embedding.model,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# A interface é servida pela mesma aplicação de propósito: quem clona o
# repositório sobe um processo só e abre uma URL. Sem passo de build, sem
# servidor separado — critério de aceite da fase é alguém de fora conseguir
# rodar sem contexto adicional.
if FRONTEND_DIR.is_dir():

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)


if __name__ == "__main__":
    main()
