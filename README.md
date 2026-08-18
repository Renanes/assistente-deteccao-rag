# Assistente de Detecção com RAG

Ferramenta de portfólio que indexa regras de detecção públicas (SigmaHQ,
Splunk ESCU, YARA-L da comunidade Google SecOps) e responde perguntas de
analistas de segurança citando a regra exata usada como fonte.

> Projeto em desenvolvimento. Este README será expandido na Fase 8 com as
> decisões de arquitetura e os resultados de avaliação de retrieval. Para o
> plano completo, ver [`CLAUDE.md`](./CLAUDE.md); para o estado atual do
> desenvolvimento, ver [`PROGRESS.md`](./PROGRESS.md).

## Status

🚧 Fase 1 concluída: as 3 fontes públicas são ingeridas e normalizadas para um
schema comum (**5.664 regras**). Chunking e embeddings são o próximo passo.

## Rodando localmente

Pré-requisitos: Docker Desktop, Python 3.12, Git.

```bash
cp .env.example .env
# preencha ANTHROPIC_API_KEY ou OPENAI_API_KEY em .env

docker compose up -d
```

Isso sobe um Postgres com a extensão `pgvector` habilitada em
`localhost:5432` (banco `detection_rag`).

### Ambiente Python

```bash
py -3.12 -m venv .venv          # Windows; use python3.12 no Linux/macOS
.venv/Scripts/activate          # ou: source .venv/bin/activate
pip install -r requirements.txt
```

### Ingestão das regras (Fase 1)

As regras são clonadas de repositórios públicos de terceiros e **não são
versionadas** neste repo (`data/raw/` é gitignored):

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git              data/raw/sigma
git clone --depth 1 https://github.com/splunk/security_content.git    data/raw/splunk_escu
git clone --depth 1 https://github.com/chronicle/detection-rules.git  data/raw/chronicle_yara_l

python -m src.ingestion.run
```

Isso grava o corpus normalizado em `data/normalized/rules.jsonl` (um
`DetectionRule` por linha) e imprime a contagem por fonte e a cobertura de
metadados. Números da última execução:

| Fonte | Regras | Com técnica ATT&CK | Com plataforma |
|---|---:|---:|---:|
| SigmaHQ | 3.141 | 2.795 | 3.078 |
| Splunk ESCU | 2.144 | 2.118 | 2.095 |
| YARA-L (Google SecOps) | 379 | 293 | 310 |
| **Total** | **5.664** | **5.206** (92%) | **5.483** (97%) |

Regras marcadas como descontinuadas são excluídas na ingestão — citar uma regra
deprecada como recomendação seria uma resposta ativamente errada. Isso remove
537 das 916 regras YARA-L do repositório do Chronicle.

### Testes

```bash
pytest
```

## Stack

- Python 3.12, FastAPI + Pydantic v2
- Postgres + `pgvector`
- Provedor de LLM/embedding configurável via `.env` (Anthropic ou OpenAI —
  ver `src/providers/`)
