# Progresso do projeto

## Status atual
- Fase atual: Fase 3 concluída — Fase 4 (Busca híbrida) é o próximo passo
- Última atualização: 2026-08-22

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

- **`EMBEDDING_PROVIDER=openai` com `text-embedding-3-small` (1536 dimensões)**
  — resolve a pendência aberta desde a Fase 0. O motivo de não usar o
  `3-large` (3072) é concreto e não preferência: os índices HNSW e IVFFlat do
  pgvector só aceitam até 2.000 dimensões. Com 3.072, a busca vetorial cairia
  em varredura sequencial sobre o corpus inteiro, ou exigiria migrar a coluna
  para `halfvec` e aceitar a perda de precisão. Há uma guarda em
  `check_index_support` que recusa qualquer modelo acima do limite *antes* de
  gastar chamada de API, e um teste que trava o padrão como indexável.
- **Não existe `EMBEDDING_PROVIDER=anthropic`** — a Anthropic não tem API de
  embeddings própria. A alternativa considerada era um
  `AnthropicEmbeddingProvider` que por baixo chamasse a Voyage; foi descartada
  porque o nome mentiria sobre qual serviço recebe o texto e qual chave é
  cobrada. A Voyage entrou como provedor de primeira classe
  (`EMBEDDING_PROVIDER=voyage`, `VOYAGE_API_KEY`), e `anthropic` levanta um
  erro dedicado que explica o porquê e aponta as duas saídas — é a resposta
  intuitiva e errada, e vale ensinar uma vez em vez de deixar quem configura
  procurar. `LLM_PROVIDER=anthropic` segue válido: a restrição é só de
  embedding.
- **`embed_documents` e `embed_query` são métodos separados na interface**,
  mesmo sendo idênticos na OpenAI. A Voyage distingue `input_type="document"`
  de `"query"` e a qualidade de retrieval piora sem isso; com um método só, o
  provedor da Voyage teria que adivinhar o contexto da chamada.
- **SDKs importados dentro das funções, não no topo dos módulos** — importar
  `openai`, `anthropic` e `voyageai` de uma vez custa quase um segundo de
  arranque e nenhuma execução usa os três. Assim, rodar com um provedor não
  exige que os SDKs dos outros estejam sequer instalados.
- **Metadados como colunas `TEXT[]` com índice GIN, não como `jsonb`** — o
  filtro "só regras de Windows para T1055" é o critério de aceite da Fase 4, e
  o schema é conhecido e estável. Um `jsonb` genérico seria mais lento e mais
  verboso sem ganhar nada.
- **Coluna `search_text` gerada pelo banco** (`tsvector` de `embedding_text`,
  com índice GIN) — é a metade lexical da busca híbrida da Fase 4, e ser
  gerada impede que fique dessincronizada do texto de origem. Indexa
  `embedding_text` puro em vez de concatená-lo com `platforms`/
  `mitre_techniques` por dois motivos: a linha de contexto da Fase 2 já embute
  os dois nesse texto, e `array_to_string` é STABLE (não IMMUTABLE), o que o
  Postgres recusa numa coluna gerada.
- **`embedding_model` gravado em cada linha, com guarda de consistência** —
  vetores de modelos diferentes não são comparáveis, e misturá-los não quebra
  nada de forma visível: só devolve vizinhos errados. `check_model_consistency`
  recusa a ingestão que misturaria modelos, inclusive o caso traiçoeiro de dois
  modelos de mesma dimensão (`text-embedding-3-small` e `ada-002` têm 1536 os
  dois). A saída é `--reset`.
- **Teste que proíbe importar SDK de provedor fora de `src/providers/`** — o
  requisito central do `CLAUDE.md` (seção 3) passa a ser verificado, e não
  confiado à memória de quem escreve a próxima fase. Sem ele, um
  `from openai import OpenAI` no pipeline RAG da Fase 5 passaria despercebido e
  o lock-in voltaria pela porta dos fundos.

## Pendências / bloqueios
- ~~`.env` inconsistente com as chaves disponíveis~~ — resolvido em 22/08:
  `LLM_PROVIDER=openai`, `EMBEDDING_PROVIDER=openai`,
  `OPENAI_EMBEDDING_MODEL=text-embedding-3-small`. `ANTHROPIC_LLM_MODEL`
  atualizado de `claude-sonnet-5` para `claude-opus-5`.
- **`ANTHROPIC_API_KEY` existe no ambiente do SO desta máquina** (108 chars) e
  em `pydantic-settings` a variável de ambiente tem **precedência sobre o
  arquivo `.env`**. Ou seja: `LLM_PROVIDER=anthropic` pode funcionar neste
  shell e falhar em qualquer outro lugar, sem nada no `.env` explicar o
  porquê. Descoberto porque um teste de "chave ausente" não levantou erro. Os
  testes agora zeram as três chaves explicitamente, mas vale saber ao depurar.
- **`anthropic==0.40.0` é uma versão antiga do SDK.** Basta para a geração
  simples que a Fase 5 precisa (`messages.create` com `system` + `messages`),
  mas não expõe `thinking` adaptativo nem `output_config.effort`, que são o
  caminho recomendado nos modelos atuais. Se a Fase 5 for usar esses recursos,
  atualizar o pin antes.
- **Full-text não casa técnica-pai com subtécnica.** Verificado no banco:
  `to_tsvector('english', ...)` tokeniza `T1213.003` como um termo único, então
  uma busca por `T1213` **não** o recupera (16 regras pela coluna de metadado
  contra 10 pelo full-text; em `T1055`, 79 contra 58). Não é defeito da Fase 3:
  é a razão de `mitre_techniques` ser uma coluna `TEXT[]` indexada. A Fase 4
  precisa expandir o termo (`t = 'T1213' OR t LIKE 'T1213.%'`) pela coluna de
  metadado, e não depender do full-text para ID ATT&CK.
- 181 das 5.664 regras ficaram sem nenhuma plataforma normalizada e 458 sem
  técnica ATT&CK. É esperado (nem toda regra declara), mas vale revisitar na
  Fase 6 se a avaliação mostrar que o filtro por metadado está perdendo regra.

## Próximos passos
- Implementar `src/retrieval/` com a busca híbrida da Fase 4, combinando:
  (a) similaridade de cosseno sobre `embedding` (índice HNSW já criado),
  (b) filtro por metadado nas colunas `platforms` / `mitre_techniques`
      (índices GIN já criados) — **com expansão de técnica-pai para
      subtécnica**, ver Pendências,
  (c) full-text sobre `search_text` (índice GIN já criado).
- Decidir e documentar como as duas pontuações são combinadas (RRF, soma
  ponderada ou filtro-e-reordena). Registrar aqui a escolha e o porquê.
- Critério de aceite da fase: uma pergunta com termo exato (ex.: "T1055")
  recupera corretamente mesmo quando a similaridade semântica pura falharia.
  Vale escrever esse caso como teste antes da implementação.

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

### 2026-08-22 — Sessão 4 (Claude Code)

**Fase 3 concluída.** O que foi feito:
- `.env` e `.env.example` ajustados para a decisão de provedor (ver Decisões).
- `src/providers/`: `base.py` (interfaces `EmbeddingProvider` e `LLMProvider` +
  `ProviderError`), `config.py` (`Settings` com pydantic-settings, tabela
  `EMBEDDING_DIMENSIONS`, constante `PGVECTOR_INDEX_MAX_DIMENSIONS`),
  `openai_provider.py`, `anthropic_provider.py` (só geração),
  `voyage_provider.py` (só embedding) e `registry.py`.
- `src/embeddings/`: `store.py` (schema pgvector, índices, upsert idempotente,
  inspeção do corpus indexado) e `run.py` (runner com `--limit`, `--reset` e
  `--dry-run`).
- 24 testes novos em `tests/test_providers.py` (78 no total, todos verdes).

**Critério de aceite atendido:** base populada e consultável ponta a ponta com
o provedor OpenAI. 5.664 chunks indexados em 90 segundos (~831 mil tokens,
~US$ 0,02). Verificado com busca semântica real — e as perguntas foram feitas
em português contra um corpus em inglês, o que o modelo resolveu bem:
- "como detectar injecao de processo em Windows" → *Mavinject Inject DLL Into
  Running Process* (T1055.001), *Windows Process Injection into Commonly Abused
  Processes* (T1055.002), similaridade 0,656/0,655.
- "alguem exfiltrando dados compactados com 7zip" → *7Zip Compressing Dump
  Files* e duas variantes de *Compress Data and Lock With Password for
  Exfiltration* (T1560.001).
- "login suspeito de multiplos paises ao mesmo tempo" → *OneLogin User Logins
  From Multiple Countries* (YARA-L), *Okta User Logins from Multiple Cities*.

**Índices criados:** HNSW (`vector_cosine_ops`) sobre `embedding`; GIN sobre
`platforms`, `mitre_techniques` e `search_text`; B-tree sobre `rule_uid`.

**Decisões desta sessão:** as 8 entradas de Fase 3 na seção "Decisões de
arquitetura" acima.

**Duas correções feitas durante a sessão**, ambas descobertas rodando e não
lendo:
1. A coluna gerada `search_text` foi recusada pelo Postgres com "generation
   expression is not immutable" — `array_to_string` é STABLE. A correção
   melhorou o design: as arrays eram redundantes ali, porque a linha de
   contexto da Fase 2 já embute plataforma e técnica no `embedding_text`.
2. Um teste de "chave ausente" não levantou erro, revelando que a
   `ANTHROPIC_API_KEY` do ambiente do SO tem precedência sobre o `.env` (ver
   Pendências). Os testes passaram a zerar as três chaves explicitamente, com
   uma guarda que verifica o próprio isolamento — sem ela, esses testes viram
   falso-positivo silencioso em máquina alheia.

**Estado em que a sessão foi deixada:** `pytest` verde (78 testes), base
`detection_rag` populada com 5.664 chunks de `text-embedding-3-small` no
container `detection_rag_postgres`, commit da Fase 3 feito. Nada da Fase 4
escrito.
