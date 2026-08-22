# Assistente de Detecção com RAG

Ferramenta de portfólio que indexa regras de detecção públicas (SigmaHQ,
Splunk ESCU, YARA-L da comunidade Google SecOps) e responde perguntas de
analistas de segurança citando a regra exata usada como fonte.

> Projeto em desenvolvimento. A documentação das decisões de arquitetura será
> expandida na Fase 8. Para o plano completo, ver [`CLAUDE.md`](./CLAUDE.md);
> para o histórico de decisões, ver [`PROGRESS.md`](./PROGRESS.md).

## Status

Pipeline completo funcionando: ingestão → chunking → embeddings → busca
híbrida → resposta citada → interface de demonstração.

| | |
|---|---|
| Regras indexadas | **5.664** (Sigma 3.141, ESCU 2.144, YARA-L 379) |
| Recall@5 do retrieval | **97%** em 30 perguntas de resposta conhecida |
| Respostas ancoradas | **30/30**, com 0 citações inexistentes |
| Método e números | [`eval/results.md`](./eval/results.md) |

Os números de retrieval foram obtidos com `text-embedding-3-small` da OpenAI
(1536 dimensões) e a geração com `claude-opus-5`. Resultados variam entre
modelos de embedding — trocar o provedor exige reindexar.

## Rodando localmente

Pré-requisitos: Docker Desktop, Python 3.12, Git.

```bash
cp .env.example .env
# preencha ANTHROPIC_API_KEY ou OPENAI_API_KEY em .env

docker compose up -d
```

Isso sobe um Postgres com a extensão `pgvector` habilitada em
`127.0.0.1:5432` (banco `detection_rag`).

> **Use `127.0.0.1`, não `localhost`.** No Windows, `localhost` resolve para
> `::1` primeiro e o Docker publica a porta só em IPv4: cada conexão espera
> ~30 s no IPv6 antes de cair para IPv4. Medido neste projeto: 30,056 s contra
> 0,017 s. O `.env.example` já vem com o endereço correto.

### Ambiente Python

```bash
py -3.12 -m venv .venv          # Windows; use python3.12 no Linux/macOS
.venv/Scripts/activate          # ou: source .venv/bin/activate
pip install -r requirements.txt
```

### 1. Ingestão das regras

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

### 2. Chunking

```bash
python -m src.chunking.run
```

Separa os campos narrativos (que viram vetor) da query bruta (preservada como
contexto). Grava `data/normalized/chunks.jsonl`.

### 3. Embeddings e indexação

Preencha `OPENAI_API_KEY` no `.env` e rode:

```bash
python -m src.embeddings.run --dry-run   # estima o custo antes de gastar
python -m src.embeddings.run
```

São ~831 mil tokens (cerca de US$ 0,02 com `text-embedding-3-small`) e leva
aproximadamente 90 segundos.

### 4. Subir a demonstração

```bash
uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Abra <http://127.0.0.1:8000>. A interface é servida pela mesma aplicação — não
há passo de build nem servidor separado.

A geração usa o provedor de `LLM_PROVIDER` (`anthropic` ou `openai`); o
embedding usa `EMBEDDING_PROVIDER` (`openai` ou `voyage`). As duas escolhas são
independentes porque a Anthropic não tem API de embeddings própria.

### Sem interface

```bash
python -m src.retrieval.run "tem regra pra T1055 no Windows?" --explain
python -m src.rag.run "como detectar dump de memória do LSASS?" --show-sources
python -m src.rag.run "mesma pergunta" --provider openai   # troca o provedor
```

### Avaliação

```bash
python eval/run_eval.py --sweep            # métricas de retrieval e ablação
python eval/run_eval.py --with-rag         # inclui ancoragem (gasta LLM)
```

### Testes

```bash
pytest                      # tudo
pytest -m "not integration" # só o que não precisa de banco nem de chave
```

Os testes marcados como `integration` exigem o Postgres no ar, o corpus
indexado e uma chave válida; sem isso são pulados automaticamente.

## Stack

- Python 3.12, FastAPI + Pydantic v2
- Postgres + `pgvector` (índice HNSW, cosseno)
- Provedor de LLM/embedding configurável via `.env` — nenhum SDK de provedor é
  importado fora de `src/providers/`, e há um teste que garante isso
- Interface sem framework e sem CDN de biblioteca: HTML, CSS e JS servidos pela
  própria aplicação
