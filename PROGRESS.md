# Progresso do projeto

## Status atual
- Fase atual: Fase 1 concluída — Fase 2 (Estratégia de chunking) é o próximo passo
- Última atualização: 2026-08-17

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

- **Separação narrativa/query já no schema (Fase 1)** — `DetectionRule` guarda
  `title`/`description`/`false_positives` separados de `query`, e expõe
  `narrative_text` como a entrada prevista do embedding. A alternativa era
  guardar o documento bruto e separar só na Fase 2, mas isso empurraria o
  parsing de 3 formatos diferentes para dentro da camada de chunking. Com a
  separação no schema, a Fase 2 lida com texto, não com formatos.
- **`rule_uid` no formato `<fonte>:<id nativo>`** — as 3 fontes têm espaços de
  UUID independentes e nada garante ausência de colisão entre elas. O prefixo
  resolve isso e ainda torna o ID legível em log e em citação. O runner conta
  duplicatas em vez de silenciá-las: duplicata é sinal de bug no parser.
- **`source_url` gravado na ingestão** — a citação da Fase 5 precisa de um link
  verificável, não só do caminho do arquivo. Montado como URL de blob do GitHub
  a partir do caminho relativo.
- **Vocabulário controlado de plataformas** (`src/ingestion/normalize.py`) — o
  filtro por metadado da Fase 4 só funciona se as 3 fontes convergirem para os
  mesmos termos. Sigma declara `logsource.product`, YARA-L declara `platform`/
  `product`, e o ESCU não declara nada (a plataforma é inferida de
  `data_source`: "Sysmon EventID 1" ⇒ windows). Há um `assert` no import
  barrando alias que aponte para fora do vocabulário — sem ele, um erro de
  digitação viraria um metadado que nenhum filtro conseguiria casar.
- **ATT&CK extraído por regex, não por campo** — cada fonte escreve o ID de um
  jeito (`attack.t1055.001` em tag do Sigma, `mitre_attack_id` no ESCU, espalhado
  entre `mitre`/`technique`/`mitre_attack_url` no YARA-L). Uma regex sobre os
  textos candidatos cobre as 3 com uma implementação só, e o validator do
  Pydantic canonicaliza para maiúsculas.
- **Regras descontinuadas excluídas do corpus** — citar uma regra deprecada como
  recomendação é uma resposta ativamente errada, não só ruído. Remove 537 das
  916 regras YARA-L (o repo do Chronicle tem mais regra deprecada que ativa).
- **ESCU fica sem severidade** — o ESCU não tem campo de severidade por detecção.
  `type` (TTP/Anomaly/Hunting/Correlation) é outro eixo e mapeá-lo para
  severidade seria inventar informação; virou tag, e `severity` fica `None`.
- **YARA-L com parser textual próprio** — não é YAML. O parser lê o bloco `meta:`
  e recorta a lógica de `events:` em diante, sem validar a gramática YARA-L
  (validar sintaxe não é objetivo do projeto). O cabeçalho de licença Apache
  fica fora da query de propósito: repeti-lo em cada regra gastaria contexto do
  prompt da Fase 5 sem acrescentar nada.
- **Fixtures de teste em vez dos clones** — `data/raw/` é gitignored e muda a
  cada pull upstream; um teste apoiado nele quebraria por motivo alheio ao
  código. As fixtures em `tests/fixtures/` são recortes reais de cada fonte,
  mais uma fixture de borda montada a partir de padrões reais do repo do
  Chronicle (chave `{` na linha seguinte, sem `rule_id`, `mitre` em texto livre).

## Pendências / bloqueios
- `.env` local só tem placeholders — falta preencher `ANTHROPIC_API_KEY` e/ou
  `OPENAI_API_KEY` reais antes da Fase 3 (embeddings) funcionar ponta a ponta.
- Docker Desktop não estava rodando nesta sessão (não bloqueou a Fase 1, que é
  só arquivo; volta a importar na Fase 3).
- 181 das 5.664 regras ficaram sem nenhuma plataforma normalizada e 458 sem
  técnica ATT&CK. É esperado (nem toda regra declara), mas vale revisitar na
  Fase 6 se a avaliação mostrar que o filtro por metadado está perdendo regra.

## Próximos passos
- Iniciar Fase 2 (chunking): a separação narrativa/query já existe no schema
  (`DetectionRule.narrative_text`). Falta decidir a granularidade do chunk —
  uma regra inteira por chunk ou dividir descrições longas — e testar com casos
  das 3 fontes. Entrada: `data/normalized/rules.jsonl` (gerado por
  `python -m src.ingestion.run`).

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

### 2026-08-17 — Sessão 2 (Claude Code)

**Achado no início da sessão:** `data/raw/` tinha diretórios de uma sessão
intermediária **não registrada** neste arquivo (11/ago): um clone do repo
YARA-L do Chronicle sob o nome temporário `chronicle_tmp`, e um diretório
`chronicle_yara_l` vazio (tentativa anterior que falhou). Nenhum código tinha
sido escrito, e o commit da Fase 0 seguia sendo o único no histórico git.
Consolidado assim: `chronicle_tmp` renomeado para `chronicle_yara_l` (é o clone
íntegro, 916 `.yaral`), o diretório vazio e clones redundantes removidos.
Registrado aqui para não se perder de novo.

**Fase 1 concluída.** O que foi feito:
- Ambiente Python: venv com 3.12 (a `python` do PATH era 3.11; o `CLAUDE.md`
  pede 3.12), `requirements.txt` e `pyproject.toml` (config de pytest e ruff).
- Schema comum em `src/ingestion/schema.py` (`DetectionRule`, Pydantic v2), com
  enums `RuleSource`, `QueryLanguage` e `Severity`.
- Helpers de normalização em `src/ingestion/normalize.py` (plataforma, ATT&CK,
  severidade), compartilhados pelos 3 parsers.
- Três parsers: `sigma.py`, `escu.py` (YAML) e `yaral.py` (parser textual
  próprio — YARA-L não é YAML).
- Runner `src/ingestion/run.py`: percorre as 3 fontes, descarta descontinuadas
  e duplicatas, grava `data/normalized/rules.jsonl` e reporta cobertura.
- 31 testes em `tests/test_ingestion.py` com fixtures reais das 3 fontes.

**Critério de aceite atendido:** as 3 fontes convertidas para o mesmo schema e
validadas com Pydantic — 5.664 regras (Sigma 3.141, ESCU 2.144, YARA-L 379),
zero duplicata de `rule_uid`, nenhuma regra sem descrição ou sem query,
cobertura de 92% em técnica ATT&CK e 97% em plataforma.

**Decisões desta sessão:** todas as entradas de Fase 1 na seção "Decisões de
arquitetura" acima. Duas correções feitas ainda durante a sessão, depois de
inspecionar a saída real: `bitbucket` estava colapsando em `github` (um filtro
por `github` devolveria regras de Bitbucket) e `sap` apontava para um valor
fora do vocabulário. As duas viraram plataformas próprias, com `assert` no
import para impedir a classe inteira de erro.

**Estado em que a sessão foi deixada:** `pytest` verde (31 testes), corpus
normalizado gerado em `data/normalized/` (gitignored, reproduzível com
`python -m src.ingestion.run`). Nada da Fase 2 escrito ainda.
