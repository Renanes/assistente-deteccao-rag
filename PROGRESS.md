# Progresso do projeto

## Status atual
- Fase atual: Fase 6 concluída — Fase 7 (Frontend e demo) é o próximo passo
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

- **Filtro por metadado é rígido; só as outras duas pernas ranqueiam (Fase 4)**
  — se o analista digitou `T1055`, uma regra de `T1027` está *errada*, não
  "menos relevante". Tratar a técnica como mais um sinal de ranqueamento
  (somando peso ao score) foi considerado e descartado: deixaria regra errada
  no topo sempre que a similaridade semântica fosse alta o bastante, que é
  exatamente o modo de falha que a fase existe para corrigir.
- **Expansão de técnica ATT&CK nos dois sentidos** — pai casa as subtécnicas
  (`T1055` → `T1055.%`) e subtécnica casa também o pai (`T1218.011` → `T1218`).
  O primeiro sentido é o que resolve a limitação medida na Fase 3 (o full-text
  tokeniza `T1055.001` como termo único, então `T1055` não o alcança); o
  segundo existe porque quem pergunta por uma subtécnica aceita bem uma regra
  marcada só com o pai. Há um teste garantindo que a lista de prefixos vazia
  nunca vira `%` — um filtro que deixa passar o corpus inteiro é o erro
  silencioso clássico aqui.
- **Fusão por Reciprocal Rank Fusion (RRF), k = 60** — similaridade de cosseno
  vive em [0, 1] e o `ts_rank` do Postgres é ilimitado e minúsculo; somar exige
  normalizar, e toda normalização seria arbitrária (dividir pelo máximo do lote
  faz a pontuação de um documento depender de quem mais veio no lote). O RRF
  descarta as pontuações e usa só a posição. O k = 60 é o da publicação
  original (Cormack et al., 2009) e ficou configurável para a Fase 6 poder
  variar e medir.
- **A perna de full-text recebe só termos de alto sinal, unidos por OR** — ela
  existe para casar identificador exato (`4688`, `mimikatz`, `rundll32.exe`),
  não para fazer trabalho semântico, que é do vetor. Unir por AND não devolveria
  nada numa pergunta em linguagem natural. As stopwords **portuguesas** são
  removidas em código porque a coluna `search_text` usa a configuração
  `english` do Postgres, que só descarta as inglesas — sem isso, "como" e
  "detectar" entrariam na consulta OR como termos legítimos.
- **A interpretação da pergunta reusa `infer_platforms` da ingestão** — se
  "sysmon" mapeia para `windows` ao classificar uma regra, precisa mapear igual
  ao interpretar a pergunta. Duas tabelas de sinônimos divergiriam com o tempo
  e o filtro passaria a errar em silêncio.
- **Filtro que não casa nada é relaxado, com flag visível** — devolver lista
  vazia deixa o analista sem resposta e sem saber por quê; relaxar em silêncio
  é pior ainda, porque a Fase 5 afirmaria que existe regra para uma técnica que
  o corpus não cobre. A busca refaz sem filtro e marca `relaxed_filters=True`.
- **Pool de candidatos de 8× o `top_k` (mínimo 50) antes da fusão** — um
  documento em 40º no vetor e 3º no full-text só pode ser resgatado pela fusão
  se estiver nas duas listas. Pool curto transformaria o RRF em decoração.

- **Citações são verificadas em código, não só pedidas no prompt (Fase 5)** — o
  critério de aceite é "a resposta sempre referencia a fonte real recuperada", e
  prompt é pedido, não garantia: nada impede um modelo citar `[7]` com cinco
  regras no contexto. `check_citations` devolve os índices citados, os
  inválidos e se a resposta não citou nada, e é isso que transforma "pedimos
  para citar certo" em "sabemos se citou". A Fase 6 mede a taxa disso.
- **As regras entram no contexto numeradas (`[1]`, `[2]`), não pelo `rule_uid`**
  — pedir que o modelo repita `sigma:ec570e53-4c76-45a9-804d-dc3f355ff7a7` no
  meio do texto seria convidar erro de transcrição, e um UID errado é uma
  citação falsa. Um índice curto é fácil de reproduzir sem errar e trivial de
  casar por regex depois. O mapeamento índice → regra real é feito em código.
- **Sem regra recuperada, o modelo não é chamado** — o pipeline devolve uma
  resposta fixa dizendo que nada no acervo corresponde. Chamar o modelo com
  contexto vazio só criaria a oportunidade de ele responder de memória, que é
  exatamente o que a fase precisa impedir. De quebra, é mais barato.
- **O aviso de filtro relaxado vem antes do contexto, não depois** — se o
  modelo só descobre que nenhuma regra cobre a técnica pedida depois de ler
  cinco regras plausíveis, a chance de apresentá-las como resposta à pergunta
  original é muito maior.
- **REVISÃO da interface de `LLMProvider` (decidida na Fase 3)**: `generate`
  passou a devolver um `Generation` (texto + `truncated` + `stop_reason`) em
  vez de `str`. O motivo: a primeira versão inferia truncamento pela pontuação
  final do texto, e acusou de cortada uma resposta legítima terminada em bloco
  de código. Só o provedor sabe se bateu no teto de tokens, e cada SDK chama
  isso de um jeito (`stop_reason="max_tokens"` na Anthropic,
  `finish_reason="length"` na OpenAI) — normalizar os dois é precisamente o
  trabalho desta camada. A decisão original não foi apagada, foi corrigida.

- **REVISÃO de duas decisões da Fase 4, com base na medição da Fase 6.** As
  decisões originais continuam registradas acima; o que mudou foi a evidência.
  A avaliação de 30 perguntas mostrou que a busca híbrida como desenhada na
  Fase 4 era **pior que a busca vetorial pura** (MRR 0,724 contra 0,846). Duas
  causas independentes, ambas desligadas por padrão:
  1. **Inferência de plataforma a partir da pergunta.** `infer_platforms` foi
     escrito para texto de telemetria (`data_source` de uma regra), não para
     frase em linguagem natural, e aplicado a perguntas dispara demais. Três
     falhas do mesmo tipo, todas excluindo a resposta certa: "endereço de
     e-mail" inferiu `email` numa regra `web`; "logs web" inferiu `web` numa
     regra `network`; "Google Workspace" inferiu `gcp` numa regra **sem
     plataforma declarada** — e 181 chunks estão nesse caso, então qualquer
     filtro de plataforma os elimina. Nas três, sem o filtro a regra volta ao
     1º lugar. Filtro de plataforma **explícito** (faceta de interface) segue
     valendo: quem escolhe "windows" num menu quis dizer isso; quem escreveu
     "logs web" numa frase, não. `INFER_PLATFORM_BY_DEFAULT = False`.
  2. **A perna de full-text.** Medida em quatro variantes (peso 1,0 e 0,5; só
     identificadores; indexando também a query bruta) e nenhuma superou
     simplesmente não usá-la. A causa é estrutural e não de ajuste: a coluna
     `search_text` indexa `embedding_text`, exatamente o texto que o vetor já
     cobre — as duas pernas olhavam para a mesma coisa, e a lexical só
     acrescentava ruído de OR. `USE_FULLTEXT_BY_DEFAULT = False`.
  **O que a revisão não invalida:** o filtro por metadado ATT&CK, que continua
  ligado, é o que dá o ganho sobre a vetorial pura (MRR 0,879 contra 0,846) e é
  o que sustenta o critério de aceite da Fase 4. A revisão foi na inferência de
  plataforma e na perna lexical, não no princípio de filtrar por metadado.
- **`search_text` passou a indexar a query bruta além da narrativa** — mudança
  de `ALTER TABLE` numa coluna gerada, sem reindexar vetor nenhum. Indexar só a
  narrativa deixava a coluna redundante com o embedding; a lógica de detecção é
  o único material que o vetor não vê (medido: "tttracer" aparece em 3 chunks
  na narrativa e em outros 6 apenas na query). A perna segue desligada por
  padrão, mas se for reativada agora tem material próprio para buscar.
- **O `k` do RRF não foi sintonizado, e não é omissão** — na configuração
  padrão existe uma única lista ranqueada, e o RRF preserva a ordem dela para
  qualquer `k`. A varredura só faz sentido com a perna de full-text ligada, e é
  assim que `run_eval.py --sweep` a executa.

## Pendências / bloqueios
- ~~`.env` inconsistente com as chaves disponíveis~~ — resolvido em 22/08:
  `LLM_PROVIDER=openai`, `EMBEDDING_PROVIDER=openai`,
  `OPENAI_EMBEDDING_MODEL=text-embedding-3-small`. `ANTHROPIC_LLM_MODEL`
  atualizado de `claude-sonnet-5` para `claude-opus-5`.
- **`ANTHROPIC_API_KEY` existe no ambiente do SO desta máquina** e em
  `pydantic-settings` a variável de ambiente tem **precedência sobre o arquivo
  `.env`**. Em 22/08 foi verificado que o valor no ambiente e o no `.env` são
  idênticos, então hoje não há divergência — mas a precedência continua valendo
  e uma edição no `.env` que não seja replicada no ambiente seria ignorada em
  silêncio. Os testes zeram as três chaves explicitamente por causa disso.
- **O `.env` foi restaurado de uma cópia anterior à Fase 3 em 22/08**, junto com
  a inclusão da chave Anthropic, desfazendo `EMBEDDING_PROVIDER=openai`,
  `OPENAI_EMBEDDING_MODEL=text-embedding-3-small` e `ANTHROPIC_LLM_MODEL=
  claude-opus-5`. Ficou com `EMBEDDING_PROVIDER=anthropic`, que não existe — as
  Fases 3 e 4 pararam de rodar até a correção. A guarda da Fase 3 pegou o caso
  com mensagem explicativa em vez de falhar obscuramente, que era o objetivo
  dela. Corrigido; `LLM_PROVIDER=anthropic` foi preservado por ser mudança
  intencional. Vale ter em mente que `.env` é gitignored e não tem histórico:
  uma regressão dele não aparece em `git diff`.
- **`anthropic==0.40.0` é uma versão antiga do SDK.** Confirmado na Fase 5
  que basta para o que o pipeline faz: `messages.create` com `system` +
  `messages` funciona, e `claude-opus-5` e `claude-sonnet-5` respondem
  normalmente. O que ela não expõe é `thinking` adaptativo e
  `output_config.effort`. Nenhum dos dois é necessário para a resposta citada
  da Fase 5, mas valeria atualizar o pin se a Fase 6 mostrar que respostas mais
  elaboradas melhoram a avaliação.
- ~~Full-text não casa técnica-pai com subtécnica~~ — resolvido na Fase 4
  pela expansão bidirecional no filtro de metadado (ver Decisões). O
  comportamento do full-text segue o mesmo; o que mudou é não depender dele
  para ID ATT&CK.
- ~~A perna de full-text fica inerte em perguntas em português~~ /
  ~~`k` do RRF não sintonizado~~ — as duas pendências foram resolvidas na Fase
  6 pela via inesperada de a perna de full-text ser desligada (ver Decisões).
- **Uma pergunta do conjunto de avaliação segue falhando: q09** ("uso do
  tttracer.exe para despejar a memória de um processo como o lsass"), na
  posição 20. A regra certa existe e tem o termo na descrição, mas o corpus tem
  muitas regras de dump de LSASS e a descrição dela é curta. É o tipo de caso
  que a perna lexical deveria resolver e não resolveu.
- **O conjunto de avaliação tem um ponto cego conhecido**: as perguntas foram
  escritas a partir das *descrições*, então nenhuma testa busca por termo que
  só existe na lógica de detecção. Foi por isso que a escolha entre desligar a
  perna lexical e apenas estreitá-la ficou empatada — e o micro-benchmark que
  tentei montar para desempatar estava mal desenhado (perguntava "regra que usa
  X" quando dezenas de regras contêm X, sem resposta única) e não informou
  nada. Fica registrado como o que medir se a perna for reativada.
- **`top_k` (5) e o multiplicador do pool (8×) seguem sem sintonia medida.** Com
  recall@5 de 97% na configuração padrão, mexer neles tem pouco a ganhar; ficam
  como parâmetros.
- 181 das 5.664 regras ficaram sem nenhuma plataforma normalizada e 458 sem
  técnica ATT&CK. É esperado (nem toda regra declara), mas vale revisitar na
  Fase 6 se a avaliação mostrar que o filtro por metadado está perdendo regra.

## Próximos passos
- Fase 7: API FastAPI expondo o pipeline (`src/api/`) e a interface de demo
  (`src/frontend/`).
- **Ler a skill de frontend-design da Anthropic antes de desenhar qualquer
  tela** — é exigência explícita do `CLAUDE.md` (seção 4), com processo de duas
  passadas: plano de design compacto (paleta de 4–6 cores nomeadas, tipografia
  com papéis, conceito de layout, um elemento de assinatura), crítica desse
  plano, e só então implementação.
- A interface tem material próprio para mostrar, e vale usá-lo em vez de virar
  mais um chat genérico: `RetrievedRule.matched_by` e `.ranks` explicam por que
  cada regra apareceu, `citation_check` distingue resposta ancorada de resposta
  solta, e `relaxed_filters` avisa que não existe regra para o termo pedido.
- Critério de aceite: alguém de fora consegue rodar e testar sem contexto
  adicional, e a interface não parece um template genérico de dashboard.
- Fase 8: README com as decisões de arquitetura e os resultados da avaliação,
  registrando que os números de `eval/results.md` foram obtidos com
  `text-embedding-3-small` (exigência do `CLAUDE.md`, seção 3).

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

### 2026-08-22 — Sessão 5 (Claude Code)

**Fase 4 concluída.** O que foi feito:
- `src/retrieval/query.py`: `parse_query` extrai da pergunta os três sinais
  (técnica ATT&CK, plataforma, termos lexicais) e `build_tsquery` monta a
  consulta de full-text.
- `src/retrieval/fusion.py`: Reciprocal Rank Fusion, com as posições de origem
  preservadas em cada resultado para a interface poder explicar *por que* a
  regra apareceu.
- `src/retrieval/search.py`: `HybridRetriever`, `SearchFilters` (com a expansão
  de técnica) e `SearchResponse`.
- `src/retrieval/run.py`: CLI de inspeção (`--explain`, `--no-filters`).
- 35 testes novos em `tests/test_retrieval.py` — 28 unitários e 7 de
  integração, estes marcados com `@pytest.mark.integration` e pulados
  automaticamente onde falte Postgres ou chave. 113 no total, todos verdes.

**Critério de aceite atendido, com número.** A pergunta "regras para <técnica>"
foi medida contra a busca vetorial pura, contando quantas das 5 regras
devolvidas realmente cobrem a técnica pedida:

| Técnica    | Vetorial pura | Híbrida |
|------------|---------------|---------|
| T1055      | 0/5           | 5/5     |
| T1218.011  | 1/5           | 5/5     |
| T1552.001  | 0/5           | 5/5     |
| T1003.001  | 1/5           | 5/5     |
| T1547.001  | 1/5           | 5/5     |

Para "T1055" a vetorial pura devolve regras de `T1047`, `T1059` e `T1053` — a
similaridade semântica sozinha não tem como saber o que o código significa.
Esse é exatamente o cenário que o `CLAUDE.md` descreve no aceite da fase.

**Decisões desta sessão:** as 7 entradas de Fase 4 na seção "Decisões de
arquitetura" acima.

**Correção feita durante a sessão:** o primeiro teste de RRF afirmava que estar
em 2º nas duas listas venceria estar em 1º e 3º. Falhou — e a implementação
estava certa, o teste é que estava errado: a curva 1/(k+rank) é convexa, então
1/61 + 1/63 > 2/62. A propriedade virou um teste próprio, documentado como
intencional, porque é contraintuitiva e alguém sintonizando o `k` na Fase 6
poderia lê-la como bug.

**Estado em que a sessão foi deixada:** `pytest` verde (113 testes, 7 deles de
integração rodando contra a base real), commit da Fase 4 feito. Nada da Fase 5
escrito.

### 2026-08-22 — Sessão 6 (Claude Code)

**Chave Anthropic validada** a pedido do usuário, com chamada real: autentica,
e tanto `claude-opus-5` quanto `claude-sonnet-5` respondem. Na mesma checagem
apareceu a regressão do `.env` registrada em Pendências.

**Fase 5 concluída.** O que foi feito:
- `src/rag/prompt.py`: instrução de sistema com as cinco regras de ancoragem,
  formatação numerada das regras recuperadas e montagem do prompt.
- `src/rag/pipeline.py`: `RagPipeline`, `RagAnswer` e `check_citations`.
- `src/rag/run.py`: CLI com `--provider` (sobrescreve `LLM_PROVIDER` só na
  execução) e `--show-sources`.
- `src/providers/base.py`: `Generation` (ver a revisão em Decisões).
- 22 testes novos em `tests/test_rag.py` — 20 unitários com LLM e retriever
  falsos, mais 2 de integração. 135 no total, todos verdes.

**Critério de aceite atendido nas três partes:**
1. *Cita a fonte real*: as citações são resolvidas para `RetrievedRule` e o
   teste de integração confere que todo `rule_uid` citado está entre os
   recuperados e tem `source_url`.
2. *Nunca responde fora do contexto*: perguntado "qual a capital da França?",
   o modelo respondeu "As regras fornecidas não respondem a essa pergunta — ela
   não é sobre detecção" e descreveu o que o contexto cobria. Ele sabe a
   resposta e recusou usá-la.
3. *Funciona com os dois provedores*: teste parametrizado sobre `anthropic` e
   `openai`, ambos passando, com a resposta ancorada nos dois casos.

**Configuração em uso:** gerar com `anthropic/claude-opus-5`, embeddar com
`openai/text-embedding-3-small`. É exatamente o cenário que motivou separar
`LLM_PROVIDER` de `EMBEDDING_PROVIDER` na Fase 3.

**Correção feita durante a sessão:** o aviso "a resposta pode ter sido cortada"
disparou numa resposta completa da OpenAI que terminava em bloco de código. A
heurística olhava a pontuação final do texto, o que é impossível de acertar. A
correção virou mudança de interface (ver a revisão de `LLMProvider` em
Decisões) e um teste de regressão que fixa o comportamento nos dois sentidos.

**Estado em que a sessão foi deixada:** `pytest` verde (135 testes, 9 de
integração), pipeline RAG funcionando ponta a ponta pelos dois provedores,
commit da Fase 5 feito. Nada da Fase 6 escrito — `eval/` segue só com
`.gitkeep`.

### 2026-08-22 — Sessão 7 (Claude Code)

**Fase 6 concluída, com um resultado que contradiz a Fase 4.**

**Método, e por que ele importa aqui.** As 30 regras-alvo foram sorteadas do
corpus com semente fixa (`20260822`), estratificadas por fonte, **antes** de
qualquer pergunta ser escrita. Sem isso seria trivial escolher depois só as
regras que funcionam e publicar um número bonito. As perguntas foram escritas a
partir da descrição de cada regra, em português, sem copiar o título — há um
teste verificando isso. Duas limitações que o número carrega e que nenhum
processo elimina, registradas em `eval/run_eval.py`: só um `rule_uid` conta
como correto (o corpus tem regras equivalentes, então é um piso), e quem
escreveu as perguntas conhecia o sistema.

**Resultado da configuração padrão (filtro ATT&CK + vetorial):**

| Métrica | Valor |
|---|---|
| recall@1 | 80% |
| recall@3 | 97% |
| recall@5 | 97% |
| recall@10 | 97% |
| MRR | 0,879 |

Por tipo de pergunta: `attack_id` 100%, `semantic` 100%, `lexical` 92%. Por
fonte: ESCU 100%, YARA-L 100%, Sigma 92%. Única falha: q09, na posição 20.

**Ablação — e aqui está a contradição com a Fase 4:**

| Configuração | recall@5 | MRR |
|---|---|---|
| **Padrão**: filtro ATT&CK + vetorial | 97% | 0,879 |
| Vetorial pura, sem filtro (linha de base) | 97% | 0,846 |
| + perna de full-text | 93% | 0,786 |
| + inferência de plataforma | 87% | 0,796 |
| + ambas (a híbrida original da Fase 4) | 83% | 0,724 |

A busca híbrida como desenhada na Fase 4 era **pior que não fazer nada**. As
duas causas e a revisão estão em "Decisões de arquitetura" acima. O que a Fase
4 mediu ("T1055" indo de 0/5 para 5/5) continua verdadeiro — mas o mérito era
do filtro por metadado, não da perna lexical, e a Fase 4 atribuiu o ganho ao
conjunto sem separar as partes. A ablação é o que separa.

**Ancoragem das respostas geradas** (`--with-rag`, com
`anthropic/claude-opus-5`): 30/30 respostas ancoradas, 0 com citação
inexistente.

**O que foi entregue:**
- `eval/questions.jsonl` (30 perguntas), `eval/run_eval.py` (ablação, recortes,
  varredura de `k`, ancoragem opcional) e `eval/results.md` (reproduzível).
- Parâmetros novos em `search()` para a ablação poder medir cada perna:
  `use_fulltext`, `fulltext_weight`, `infer_platform`, `identifiers_only`.
- `search_text` passou a incluir a query bruta (ver Decisões).
- 21 testes novos em `tests/test_eval.py`, metade sobre a integridade do
  conjunto de perguntas e metade travando os defaults que a medição escolheu —
  sem eles, religar as duas pernas por parecer "mais completo" derrubaria o
  recall sem nada acusar. 156 no total, todos verdes.

**Um experimento que não deu certo, registrado para não ser refeito:** tentei
desempatar "desligar a perna lexical" contra "estreitá-la" com um
micro-benchmark sobre termos que só existem na lógica de detecção. O desenho
estava errado — perguntava "regra que usa X" quando dezenas de regras contêm X,
sem resposta única, e devolveu `>20` para tudo. Não informou nada, e a escolha
acabou sendo pela configuração de melhor MRR, que também é a mais simples.

**Estado em que a sessão foi deixada:** `pytest` verde (156 testes),
`eval/results.md` gerado, commit da Fase 6 feito. Nada da Fase 7 escrito.
