# Progresso do projeto

## Status atual
- Fase atual: Fase 2 concluída — Fase 3 (Embeddings e ingestão) é o próximo passo
- Última atualização: 2026-08-21

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

- **Um chunk por regra (Fase 2)** — decidido medindo o corpus, não por
  convenção: o texto narrativo mais longo das 5.664 regras tem 1.897
  caracteres e o p99 fica em 1.455. Nenhuma regra chega perto do tamanho em
  que dividir passaria a valer a pena, e dividir criaria chunks irmãos
  competindo pelo mesmo top-k e uma citação ambígua ("qual pedaço da regra?").
  `chunk_index`/`chunk_total` ficam no contrato do `RuleChunk` mesmo valendo
  sempre 0/1: se a Fase 6 mostrar perda de recall, dividir vira mudança de
  código e não migração de banco.
- **A query não é embeddada; é preservada literal** — sintaxe de linguagem de
  busca (`EventID=1`, `| tstats`, `$e.metadata.event_type`) domina o vetor com
  tokens que nenhum analista digita numa pergunta em linguagem natural. A query
  vai junto no chunk como contexto para a resposta da Fase 5, verbatim: o
  analista quer ver a regra, não uma paráfrase.
- **Linha de contexto no texto embeddado** — título e descrição sozinhos não
  dizem plataforma nem técnica. O texto embeddado passa a começar por uma frase
  em prosa ("Regra Sigma para windows. Técnicas MITRE ATT&CK: T1055.001.
  Fontes de dados: ..."), não por pares chave-valor: o modelo de embedding é
  treinado em prosa, e `source=sigma | platform=windows` vira token solto que
  ancora mal. Isso não substitui o filtro por metadado da Fase 4 (que continua
  sendo o caminho do termo exato) — evita depender só dele quando o analista
  descreve a técnica sem citar o ID.
- **Teto de 4.000 caracteres na query preservada** — a distribuição é
  concentrada (p90 = 1.268) mas a cauda é extrema: a regra "Vulnerable Driver
  Load" do Sigma tem 250 KB de query, quase tudo lista de hash do LOLDrivers.
  Sem teto, uma única regra recuperada estoura o contexto do prompt da Fase 5 e
  empurra as outras para fora. O corte atinge 41 das 5.664 regras (0,7%), cai
  numa fronteira de linha (meia condição parece completa e engana quem lê),
  deixa marcador explícito e liga a flag `query_truncated`, para a resposta
  remeter à fonte em vez de fingir que mostrou a regra inteira.
- **`logsource.definition` do Sigma fora do texto embeddado** — 390 regras
  carregam esse campo dentro de `data_sources`, e ele não é fonte de dado: é
  campo livre de nota de operação, com conteúdo indo de um parágrafo de
  requisito de logging a um GUID solto. Filtrado por prefixo e não por tamanho,
  justamente porque o tamanho não separa os dois casos — um teto de caracteres
  deixaria o GUID passar. Um segundo filtro por tamanho (60 chars, contra p90
  de 31) pega a prosa que não vem prefixada. O `data_sources` completo continua
  íntegro no chunk para o filtro da Fase 4 — o descarte é só do que vira vetor.
  Achado inspecionando a saída real, não previsto no plano da fase.

## Pendências / bloqueios
- ~~`.env` local só tem placeholders~~ — resolvido em 21/08: `OPENAI_API_KEY`
  preenchida pelo usuário. `ANTHROPIC_API_KEY` segue vazia.
- **`.env` está inconsistente com as chaves disponíveis**: `LLM_PROVIDER` e
  `EMBEDDING_PROVIDER` seguem em `anthropic`, mas só a chave da OpenAI existe.
  Precisa virar `openai` (ao menos em `EMBEDDING_PROVIDER`) antes da Fase 3
  rodar ponta a ponta. Não alterado nesta sessão por ser decisão do usuário.
- ~~Docker Desktop não estava rodando~~ — resolvido em 21/08: subido, com
  apenas `detection_rag_postgres` ativo (44 MB). Os 4 containers do projeto
  `siemcopilot` no mesmo daemon estão com `restart=no` e não sobem sozinhos;
  o deste projeto tem `restart=unless-stopped`. pgvector 0.8.2 confirmado.
- 181 das 5.664 regras ficaram sem nenhuma plataforma normalizada e 458 sem
  técnica ATT&CK. É esperado (nem toda regra declara), mas vale revisitar na
  Fase 6 se a avaliação mostrar que o filtro por metadado está perdendo regra.

## Próximos passos
- **Decidir o provedor de embedding e registrar aqui** (bloqueia a Fase 3). A
  pendência aberta na Fase 0 continua: a Anthropic não tem API de embedding
  própria — o caminho dela é a Voyage AI, que é outra API e outra chave, não a
  `ANTHROPIC_API_KEY`. Com só a chave da OpenAI preenchida, o caminho de menor
  atrito é `EMBEDDING_PROVIDER=openai` (`text-embedding-3-small`, 1536
  dimensões) e deixar a Anthropic para a geração da Fase 5, que é exatamente a
  separação que o `CLAUDE.md` prevê ao ter duas variáveis distintas. Se a
  Voyage entrar depois, registrar `VOYAGE_API_KEY` como terceira variável.
- Implementar `src/providers/` com a interface comum (geração + embedding) e as
  duas implementações, sem SDK de provedor vazando para fora dessa camada.
- Criar o schema do pgvector (dimensão do vetor decidida pelo modelo acima) com
  colunas de metadado para o filtro da Fase 4: `platforms`, `mitre_techniques`,
  `source`, `query_language`, `severity`.
- Indexar `data/normalized/chunks.jsonl` (gerado por
  `python -m src.chunking.run`; depende de `python -m src.ingestion.run`).

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

### 2026-08-21 — Sessão 3 (Claude Code)

**Fase 2 concluída.** O que foi feito:
- `src/chunking/chunk.py`: modelo `RuleChunk` (Pydantic v2) e as funções
  `chunk_rule`, `build_embedding_text`, `build_context_line`, `truncate_query`
  e `select_context_data_sources`.
- `src/chunking/run.py`: runner que lê `rules.jsonl` em streaming e grava
  `data/normalized/chunks.jsonl`, reportando contagem por fonte, truncamentos e
  a distribuição de tamanho do texto embeddado.
- 23 testes novos em `tests/test_chunking.py`, sobre as fixtures reais das 3
  fontes (54 no total no projeto, todos verdes).

**Critério de aceite atendido:** a função de chunking está testada com casos
das 3 fontes. A invariante central — a query nunca entra no texto embeddado —
é verificada nas 3 de uma vez, com um marcador de sintaxe por linguagem
(`condition:` no Sigma, `tstats` no SPL, `events:` no YARA-L).

**Números do corpus após o chunking:** 5.664 chunks (Sigma 3.141, ESCU 2.144,
YARA-L 379), 41 queries truncadas (0,7%), texto embeddado com p50 = 464
caracteres, p99 = 1.383 e máximo de 2.056 — folga confortável para o limite de
qualquer modelo de embedding.

**Decisões desta sessão:** as 5 entradas de Fase 2 na seção "Decisões de
arquitetura" acima. Todas as escolhas de granularidade e de teto saíram de
medição do corpus real antes de escrever o código, não de convenção.

**Correção feita durante a sessão**, depois de inspecionar a saída real (mesmo
padrão da Sessão 2): o campo `logsource.definition` do Sigma estava entrando na
linha de contexto embeddada — em um caso, um GUID puro; em outro, um parágrafo
de requisito de logging, gerando ainda um `..` no fim da frase. A primeira
tentativa filtrou por tamanho e deixou passar 49 casos; o critério correto era
o prefixo. Vale como lembrete: nesta base, olhar a saída gerada tem achado
defeito que teste sobre fixture não pega.

**Ambiente:** Docker Desktop subido a pedido do usuário, com só o container
deste projeto ativo (ver Pendências). `OPENAI_API_KEY` preenchida por ele.
`ruff` está configurado no `pyproject.toml` mas não instalado no venv — não
bloqueia nada, mas `pip install ruff` deixaria o lint disponível.

**Estado em que a sessão foi deixada:** `pytest` verde (54 testes),
`chunks.jsonl` gerado e sem defeito na linha de contexto, commit da Fase 2
feito. Nada da Fase 3 escrito — o primeiro passo dela é a decisão de provedor
de embedding registrada em "Próximos passos".
