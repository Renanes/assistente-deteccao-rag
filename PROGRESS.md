# Progresso do projeto

## Status atual
- Fase atual: Fase 0 concluída — Fase 1 (Coleta e normalização) é o próximo passo
- Última atualização: 2026-08-09

## Decisões de arquitetura
- **Git dedicado para este projeto** — `agente_detection` estava aninhado
  dentro do repositório git da pasta `Área de Trabalho`, cujo remote aponta
  para um projeto não relacionado (`siem-copilot`). Inicializado um repo git
  novo dentro de `agente_detection/`, isolado, para não poluir o histórico de
  outro projeto. Decisão confirmada com o usuário no início da Fase 0.
- **Postgres via `pgvector/pgvector:pg16`** — imagem oficial do pgvector já
  com a extensão compilada, em vez de instalar a extensão manualmente sobre a
  imagem `postgres` padrão. Evita passo extra de build/init frágil.
  Extensão habilitada automaticamente via script em
  `docker/init/01_extensions.sql` (mecanismo padrão do entrypoint oficial do
  Postgres: `docker-entrypoint-initdb.d`), executado só na primeira
  inicialização do volume.
- **Estrutura de diretórios** — seguida exatamente a sugerida no `CLAUDE.md`
  (seção 5), com pastas vazias marcadas por `.gitkeep` até a Fase 1 popular
  com código real.
- **Pendente para a Fase 3**: a Anthropic não tem API de embeddings própria
  (o caminho recomendado por eles é Voyage AI). O `.env.example` já deixa um
  placeholder (`ANTHROPIC_EMBEDDING_MODEL=voyage-3`) mas a decisão real de
  qual modelo/API usar quando `EMBEDDING_PROVIDER=anthropic` ainda precisa ser
  tomada e documentada aqui quando a camada `src/providers/` for implementada.

## Pendências / bloqueios
- Nenhuma no momento. `.env` local só tem placeholders — falta preencher
  `ANTHROPIC_API_KEY` e/ou `OPENAI_API_KEY` reais antes da Fase 3 (embeddings)
  funcionar de ponta a ponta.

## Próximos passos
- Iniciar Fase 1: clonar as 3 fontes públicas (SigmaHQ, Splunk ESCU, YARA-L
  da comunidade Google SecOps) em `data/raw/` (gitignored) e definir o schema
  Pydantic comum (título, descrição, query, plataforma, técnica MITRE,
  referências) em `src/ingestion/`.

## Histórico de sessões

### 2026-08-09 — Sessão 1 (Claude Code)
- Lido `CLAUDE.md`; `PROGRESS.md` não existia, criado agora seguindo a
  estrutura da seção 8.
- Confirmado com o usuário: repo git dedicado para este projeto (ver decisões
  de arquitetura acima), em vez de reaproveitar o repo git da `Área de
  Trabalho` (remote `siem-copilot`, projeto não relacionado).
- Fase 0 completa:
  - Esqueleto de diretórios criado (`data/raw`, `src/{ingestion,chunking,
    providers,embeddings,retrieval,rag,api,frontend}`, `eval/`, `tests/`).
  - `.gitignore` (segredos, `data/raw/`, artefatos Python/Node, volume do
    Postgres).
  - `.env.example` com `LLM_PROVIDER`/`EMBEDDING_PROVIDER`,
    `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`, config de banco e de API.
  - `docker-compose.yml` com Postgres (`pgvector/pgvector:pg16`) +
    `docker/init/01_extensions.sql` para habilitar a extensão `vector`
    automaticamente.
  - `README.md` inicial (será expandido na Fase 8).
  - Validado o critério de aceite: `docker compose up -d` sobe o container
    saudável e `SELECT extname, extversion FROM pg_extension WHERE extname =
    'vector'` confirma a extensão habilitada (v0.8.2).
- Estado em que a sessão foi deixada: repositório git ainda não inicializado
  localmente (próxima ação); container Postgres rodando em background
  (`detection_rag_postgres`, saudável). Nenhum código de ingestão escrito
  ainda — Fase 1 é o próximo passo.
