# Assistente de Detecção com RAG

Ferramenta de portfólio que indexa regras de detecção públicas (SigmaHQ,
Splunk ESCU, YARA-L da comunidade Google SecOps) e responde perguntas de
analistas de segurança citando a regra exata usada como fonte.

> Projeto em desenvolvimento. Este README será expandido na Fase 8 com as
> decisões de arquitetura e os resultados de avaliação de retrieval. Para o
> plano completo, ver [`CLAUDE.md`](./CLAUDE.md); para o estado atual do
> desenvolvimento, ver [`PROGRESS.md`](./PROGRESS.md).

## Status

🚧 Fase 0 concluída (setup do ambiente). Ingestão de dados ainda não iniciada.

## Rodando localmente

Pré-requisitos: Docker Desktop, Python 3.12.

```bash
cp .env.example .env
# preencha ANTHROPIC_API_KEY ou OPENAI_API_KEY em .env

docker compose up -d
```

Isso sobe um Postgres com a extensão `pgvector` habilitada em
`localhost:5432` (banco `detection_rag`).

## Stack

- Python 3.12, FastAPI + Pydantic v2
- Postgres + `pgvector`
- Provedor de LLM/embedding configurável via `.env` (Anthropic ou OpenAI —
  ver `src/providers/`)
