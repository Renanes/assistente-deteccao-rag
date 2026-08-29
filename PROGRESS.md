# Progresso do projeto

## Status atual
- Fase atual: **Fase 8 concluída — roadmap do `CLAUDE.md` completo.**
  Em manutenção pós-roadmap (ver sessão de 2026-08-29).
- Última atualização: 2026-08-29

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

- **`POSTGRES_HOST=127.0.0.1`, nunca `localhost` (Fase 7)** — no Windows,
  `localhost` resolve para `::1` antes de `127.0.0.1` e o Docker publica a
  porta só em IPv4. O libpq espera o timeout de TCP no IPv6 antes de cair para
  IPv4, **a cada conexão**. Medido: 30,056 s contra 0,017 s. Todo script deste
  projeto vinha pagando esses 30 segundos desde a Fase 3 sem que ninguém
  notasse, porque em script isso parece "está processando"; na API, em que cada
  requisição abre uma conexão, virou travamento.
- **`store.connect` ganhou `connect_timeout` de 8 s** — o default do libpq é
  ~30 s, e 30 s de espera silenciosa é indistinguível de travamento para quem
  está usando. Com teto curto, configuração errada falha com mensagem.
- **`CREATE EXTENSION` saiu de `connect` e virou `ensure_extension`**, chamado
  só pelo caminho de indexação. Rodar DDL em toda conexão era desperdício num
  script e pegava lock em `pg_extension` a cada requisição da API. Criar
  extensão é preparo de ambiente, não operação de leitura.
- **Uma conexão por requisição na API, não uma compartilhada** — endpoints
  síncronos do FastAPI rodam num pool de threads e uma conexão psycopg não é
  thread-safe. Compartilhá-la produziria erro intermitente sob concorrência,
  que é a pior categoria de defeito para uma demonstração.
- **Provedores resolvidos no arranque da aplicação, não na primeira pergunta**
  — se a chave falta ou o `EMBEDDING_PROVIDER` é inválido, a aplicação falha ao
  subir com a mensagem da camada de provedores.
- **A interface é servida pela própria aplicação FastAPI, sem passo de build** —
  o critério de aceite da fase é alguém de fora rodar sem contexto adicional.
  HTML, CSS e JS estáticos, sem framework e sem CDN de biblioteca (só as fontes
  do Google Fonts). O renderizador de markdown é ~60 linhas escritas aqui e
  escapa HTML antes de qualquer coisa, porque o texto vem de um LLM.

- **NÃO categorizar as 458 regras sem técnica ATT&CK; expô-las como faceta** —
  a pergunta era se valeria preencher a técnica das regras que não declaram
  nenhuma, para o filtro alcançar 100% do acervo. Recusado, e o motivo é o
  mesmo que já governa o filtro: ele é **rígido**, tratado como verdade
  (`T1027` numa busca por `T1055` está *errada*, não "menos relevante").
  Preencher por inferência — regex mais solto, heurística de texto ou um LLM
  lendo a descrição — misturaria na mesma coluna dois metadados de
  confiabilidade incomparável: técnica **declarada pela fonte** (verificável, é
  o que sustenta o MRR de 0,879 medido na Fase 6) e técnica **adivinhada aqui**.
  É a mesma decisão já tomada para a severidade do ESCU: `None` em vez de
  derivar de `type`, porque derivar seria inventar informação.
  A saída é a faceta "Sem técnica declarada": as 458 regras deixam de ser um
  buraco silencioso e viram um valor com contagem, pedível. Se um dia a
  inferência for feita, que seja em **coluna própria**, marcada como inferida e
  fora do filtro rígido.
- **O catálogo de técnicas e a faceta são a mesma agregação** — construir a
  faceta separada do índice duplicaria a matemática de rollup, e duas
  implementações divergem na primeira mudança. `src/retrieval/techniques.py` é
  a fonte única; a API e a interface leem dela.
- **`expand_technique` virou função compartilhada, e é o que impede o número de
  mentir** — o filtro expande `T1055` para `T1055.%` e `T1218.011` para
  `T1218`. Se o catálogo contasse por conta própria, exibiria "T1059.001 — 252
  regras" e o clique devolveria 375, sem erro nenhum: só um número errado. Agora
  `_filter_sql` e o rollup chamam a mesma função, e **o número exibido é sempre
  o que o filtro devolve** (`match_count`), com a contagem própria como
  secundária. Conferido contra o Postgres real nas 473 técnicas do acervo: zero
  divergência. A propriedade ficou travada em teste que roda sem banco.
- **Agrupamento por família de técnica, não por tática — decidido medindo** — a
  intenção inicial era agrupar por tática, que é o eixo legível para um
  analista. A coluna `mitre_tactics` não sustenta: 67 valores distintos para as
  14 táticas reais, incluindo ID de tática cru (`TA0006`), **ID de software**
  (`S0029`, 11 regras), variantes de grafia da mesma tática (`Defense Evasion` e
  `Defense-Impairment` como valores separados) e um valor único contendo quatro
  táticas separadas por vírgula. 2.228 chunks (39%) não têm tática nenhuma. A
  família sai do próprio ID, não depende de dado externo e é o eixo que o filtro
  já expande. **A limpeza de `mitre_tactics` fica registrada como pendência.**
- **Nomes ATT&CK vêm de arquivo gerado e commitado, não de chamada em runtime**
  — o acervo guarda só o ID, e nenhuma das três fontes dá o nome de forma
  utilizável (Sigma e ESCU não trazem nenhum; só 148 das 916 regras YARA-L
  trazem `mitre_attack_technique`). Um índice de 473 IDs nus é ilegível.
  `python -m src.ingestion.attack_names` baixa os três bundles STIX do MITRE,
  extrai ~1% deles e grava `data/attack/techniques.json` (105 KB, 1.140
  técnicas, ATT&CK v19.2). Buscar em runtime trocaria uma dependência de dados
  por uma de rede num caminho que precisa funcionar offline, com 35 MB de
  download. O arquivo fica fora de `data/raw/` e `data/normalized/`, que são
  gitignored, e é auditável em `git diff`.
- **O segundo produto do mapa de nomes é validação, e ela já rendeu** — antes
  dele, `T1685` parecia ID inválido: 276 regras, um volume alto demais para um
  ID que eu não reconhecia. O mapa resolveu: é "Disable or Modify Tools", a
  renumeração de `T1562` no ATT&CK v19. O acervo usa **as duas grafias** — 4
  técnicas revogadas (`T1562`, `T1562.001`, `T1562.008`, `T1070.001`) convivem
  com as sucessoras. Nenhum ID do acervo está fora do ATT&CK (0 desconhecidos,
  0 descontinuados), o que também valida os parsers da Fase 1.
- **Clicar no catálogo arma um filtro, não dispara uma busca** — a página é
  dirigida por pergunta; a técnica é a restrição, não a consulta. "Sem técnica
  declarada" sem pergunta nenhuma não teria o que responder. O filtro explícito
  **vence** a técnica inferida do texto: quem clicou já disse o que queria.
- **`include_untagged` é campo próprio no `SearchFilters`, não valor sentinela**
  — um `"__sem__"` dentro de `mitre_techniques` passaria pela expansão de
  técnica (que não faz sentido para ele) e vazaria para `filtered_techniques` na
  resposta da API e para o aviso de filtro relaxado, onde apareceria como se
  fosse um ID ATT&CK. Combinado com técnicas, o efeito é **união**, não
  interseção — que seria sempre vazia, já que nenhuma regra pode declarar
  `T1055` e não declarar nada ao mesmo tempo.

- **A chave de API de quem usa nunca toca o disco do servidor** — o pedido era
  um painel para quem clona o repositório trazer as próprias chaves. Três
  modelos foram postos lado a lado e o escolhido foi o de **chave só no
  navegador**: ela vive no `localStorage` do visitante, viaja num cabeçalho por
  requisição, é usada e descartada. Não vai para o `.env`, não fica em memória
  entre requisições, e nenhum endpoint a devolve.
  A alternativa recusada era gravar no `.env` pela interface. O motivo da recusa
  é que esta aplicação **não tem autenticação** (o `CLAUDE.md`, seção 2, põe auth
  e multi-tenant fora do escopo v1): um endpoint que grave segredo em disco sem
  auth deixa qualquer um que alcance a porta trocar a chave do operador e gastar
  o dinheiro dele. Com a chave no navegador, hospedar a demo publicamente
  continua seguro — cada visitante traz e paga a própria.
- **Provedor construído com chave de visitante nunca entra em cache** — é a
  regra que o desenho inteiro depende. `Runtime.llm_by_model` existe para
  reaproveitar conexão HTTP entre requisições, e guardar ali um cliente com a
  credencial de um visitante a entregaria ao próximo. `apply_keys` devolve
  **cópia** de `Settings` pelo mesmo motivo: mutar o objeto compartilhado faria
  a chave de um valer para os outros. Os dois casos são falha silenciosa — não
  quebram nada visível — então são teste, não convenção.
- **`/api/settings` responde com booleano, nunca com valor** — é o endpoint por
  onde uma credencial mais facilmente vazaria. A tentação seria devolver os
  últimos caracteres "para conferir", e isso é vazamento parcial numa aplicação
  sem auth. Há teste travando o formato do contrato e proibindo campos com nome
  de segredo. As mensagens de erro passam por `redact` antes de virar resposta
  HTTP: erro de SDK viaja para o cliente e é barato demais garantir que uma
  chave não vá junto.
- **REVISÃO da decisão de arranque da Fase 7.** A original — "provedores
  resolvidos no arranque; se a chave falta, a aplicação falha ao subir" —
  continua registrada acima e estava certa no contexto dela: chave faltando era
  configuração quebrada, e falhar cedo mostrava a causa. Com as chaves podendo
  vir de quem usa, **subir sem chave nenhuma virou um estado inicial legítimo**:
  é exatamente a situação de quem acabou de clonar o repositório, e derrubar a
  aplicação nele tornaria o painel inalcançável. O arranque passou a distinguir
  "falta um segredo que alguém vai trazer" (tolerado, vira estado reportado em
  `/api/health` e `/api/settings`) de "esta configuração não existe" —
  `EMBEDDING_PROVIDER` com nome desconhecido, modelo de embedding sem dimensão
  registrada —, que **continua** derrubando o arranque.
- **A faceta de chave cobre embedding e geração, não só geração** — pedir só a
  chave "da IA generativa" entregaria um app quebrado. O pipeline embedda a
  pergunta **antes** de gerar, e quem traz só chave Anthropic não consegue nem
  consultar, porque a Anthropic não tem API de embeddings (decisão da Fase 3).
  A interface declara o papel de cada provedor (`PROVIDER_ROLES`) e avisa
  separadamente qual das duas pontas está descoberta. Avisa também quando o
  provedor de embedding escolhido não bate com o modelo que indexou o corpus —
  esse é o pior modo de falha do "traga sua chave", porque não dá erro: vetores
  de modelos diferentes não são comparáveis e a busca só devolve regra errada.

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
- **A responsividade em largura de celular não foi confirmada visualmente.** Os
  pontos de quebra existem (900 px e 620 px) e há teste garantindo que estão na
  folha de estilo, mas a ferramenta de navegador reportou sucesso no
  redimensionamento sem que a captura refletisse a mudança. Vale abrir a página
  num celular de verdade antes de considerar isso verificado.
- **`--reload` do uvicorn não foi testado.** A demo foi validada com o servidor
  em modo normal.
- **`mitre_tactics` está poluída e hoje não é usada por nada.** 67 valores
  distintos para 14 táticas reais: ID de tática cru (`TA0006`), ID de software
  (`S0029`), variantes de grafia da mesma tática e um valor único com quatro
  táticas separadas por vírgula; 39% dos chunks sem tática nenhuma. Foi o que
  impediu o catálogo de agrupar por tática (ver Decisões). Limpar exigiria um
  vocabulário controlado como o de plataformas da Fase 1 — o mapa ATT&CK
  commitado agora dá a tabela de referência para isso. Agrupar por tática é o
  eixo mais legível para um analista, então isso tem valor real.
- **O acervo usa técnica revogada e sucessora ao mesmo tempo**, e o filtro não
  atravessa a revogação: pedir `T1562` não devolve as 276 regras de `T1685`, e
  vice-versa. São 4 pares (`T1562`, `T1562.001`, `T1562.008`, `T1070.001`). O
  catálogo **mostra** a revogação e para onde ela aponta, que é honesto, mas não
  age sobre ela. Expandir o filtro pelas revogações é mudança de comportamento
  do retrieval e, pela cultura do projeto, deveria ser medida na avaliação antes
  de virar padrão — não implementada em silêncio.
- **O catálogo não lista as regras de uma técnica.** Clicar arma um filtro para
  a próxima pergunta; não há como navegar as 143 regras de `T1003.001` sem
  perguntar algo. Um endpoint de listagem paginada resolveria, mas é
  funcionalidade nova e não estava no pedido.

- **A chave no `localStorage` é legível por qualquer script desta página.** É o
  limite conhecido do modelo escolhido, dito por extenso na própria interface.
  A página não carrega script de terceiros e escapa o texto do LLM antes de
  renderizar, então não há vetor conhecido hoje — mas quem for além desta demo
  deveria olhar para fluxo com backend guardando token de sessão, não a chave.
- **Não há limite de uso por visitante.** Com a chave vindo de quem usa isso não
  gasta o dinheiro do operador, mas uma instância pública ainda serve de proxy
  aberto para a API do provedor de quem colar a chave ali. Nada a fazer enquanto
  a demo for local; vale registrar antes de qualquer hospedagem.
- **O `.env` continua sem caminho de escrita pela interface**, por decisão. Quem
  quiser fixar a chave numa máquina própria edita o arquivo e reinicia — e é o
  que a interface recomenda para uso permanente.

## Próximos passos

O roadmap das Fases 0 a 8 está completo. O que segue é melhoria, não entrega
pendente — em ordem de retorno pelo esforço:

- **Fechar as duas pendências de verificação** (baratas): abrir a interface num
  celular de verdade e rodar a demo com `uvicorn --reload`.
- **Ampliar o conjunto de avaliação para cobrir o ponto cego conhecido** —
  perguntas por termo que só existe na lógica de detecção. É o que decidiria em
  definitivo se a perna de full-text merece voltar a ser ligada, já que a
  coluna passou a indexar a query bruta na Fase 6.
- **Investigar q09**, a única falha remanescente do conjunto.
- **Sintonizar `top_k` e o multiplicador do pool**, hoje em padrões não
  medidos. Com recall@5 de 97% há pouco a ganhar, mas o harness já suporta.
- **Atualizar o pin de `anthropic` (0.40.0)** se em algum momento `thinking`
  adaptativo ou `output_config.effort` passarem a fazer diferença na resposta.

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

### 2026-08-22 — Sessão 8 (Claude Code)

**Fase 7 concluída.**

**Processo de design seguido como o `CLAUDE.md` (seção 4) exige.** A skill de
frontend-design não estava disponível localmente, então foi buscada na URL. O
processo de duas passadas foi cumprido:

*Passada 1 — plano.* Conceito: **mesa de referência, não conversa**. O acervo
são 5.664 regras catalogadas com identificador estável e link verificável, e o
produto é a citação — o analista quer a regra, não a paráfrase. Paleta de 6
cores nomeadas (`papel`, `carta`, `tinta`, `grafite`, `verificado`,
`ressalva`), com o verde-pinho reservado à aparelhagem de citação. Três papéis
tipográficos: Space Grotesk (display), IBM Plex Sans (corpo), IBM Plex Mono (as
queries — face desenhada para isso). Elemento de assinatura: **o selo de
ancoragem**, que estampa o resultado da verificação de citação feita em código.

*Passada 2 — crítica.* Contra os três anti-padrões nomeados pela skill: não é
creme + serifada + terracota, não é quase-preto + neon, e o risco real
identificado foi a "ficha de catálogo" virar card genérico de dashboard —
mitigado tratando-a como documento regrado, sem sombra e sem canto arredondado,
com a query real em mono. O verde como accent é escolha incomum (o reflexo
seria azul ou terracota) e vem do domínio: verificação.

**O que foi entregue:**
- `src/api/`: `main.py` (endpoints `/api/ask`, `/api/health`, e a interface
  servida na raiz) e `schemas.py`.
- `src/frontend/`: `index.html`, `styles.css`, `app.js` — sem framework, sem
  CDN de biblioteca, sem passo de build.
- README com o caminho completo de execução, do clone à demo.
- 17 testes novos em `tests/test_api.py`. Metade cobre um risco específico da
  entrega: a página é estática, sem compilador, então um `id` renomeado no HTML
  e não no JS quebraria só no navegador de quem for avaliar. Há teste cruzando
  os dois arquivos, e testes travando o piso de qualidade (foco visível,
  `prefers-reduced-motion`, quebra mobile, tema escuro) e a paleta planejada.
  173 no total, todos verdes.

**Dois defeitos encontrados rodando, não lendo:**

1. **O achado maior da sessão, e ele é antigo:** a API travava. A investigação
  passou por hipóteses erradas (lock de `CREATE EXTENSION`, thread-safety do
  psycopg) até um teste isolado mostrar que `psycopg.connect` levava **30
  segundos até na thread principal**. Causa: `localhost` resolve para `::1`
  primeiro no Windows e o Docker publica só em IPv4. Medido: 30,056 s contra
  0,017 s com `127.0.0.1`. Isso vinha desde a Fase 3 — a indexação de 90 s e
  todas as execuções da avaliação pagaram esse pedágio sem que aparecesse,
  porque em script 30 s parecem trabalho. Só a API, que abre conexão por
  requisição, expôs o problema.
2. **A seção de resultado aparecia com o atributo `hidden` presente**, porque
  `.result { display: grid }` vence o `display: none` que o navegador aplica
  via `[hidden]`. A página abria mostrando um selo de ancoragem vazio.
  Corrigido com `[hidden] { display: none !important }` e um teste de
  regressão.

**Verificado no navegador:** estado inicial, consulta real ("tem regra pra
T1055 no Windows?"), selo lendo "Resposta ancorada · 5 de 5 regras citadas · 0
citações inválidas", marcadores `[n]` ligados às fichas, régua de proveniência
("cosseno 0.465 · vetorial") e a lógica de detecção em bloco recolhível. O que
**não** foi verificado está em Pendências.

**Estado em que a sessão foi deixada:** `pytest` verde (173 testes),
`uvicorn src.api.main:app` sobe e serve a demo, commit da Fase 7 feito. Nada da
Fase 8 escrito além do caminho de execução no README.

### 2026-08-22 — Sessão 9 (Claude Code)

**Fase 8 concluída. O roadmap do `CLAUDE.md` está completo (Fases 0 a 8).**

O README foi reescrito como porta de entrada do portfólio, com a divisão de
propósito que o `CLAUDE.md` (seção 8) exige: README para humanos avaliando o
projeto, `PROGRESS.md` para continuidade entre sessões. O README não repete o
histórico — aponta para ele.

**Estrutura do README:** pitch com os números de cabeça, diagrama do pipeline,
caminho de execução completo, sete decisões de arquitetura com o *porquê*,
avaliação com método e limitações, limitações conhecidas, stack e estrutura do
repositório.

**A seção que mais importa** é a 5, sobre a busca híbrida: ela conta que a
avaliação contradisse o desenho original, mostra a tabela de ablação e explica
o que sobreviveu (o filtro ATT&CK) e o que caiu (inferência de plataforma e
perna lexical). Documentar a revisão em vez de apresentar só o resultado final
é o que torna o número confiável — e é o oposto de um README que só mostra o
que deu certo.

**Verificação das afirmações:** um script conferiu que as métricas do README
batem com `eval/results.md`, que a contagem de regras bate com
`data/normalized/rules.jsonl`, que o conjunto tem as 30 perguntas anunciadas e
que todos os links internos apontam para arquivos existentes. As limitações
conhecidas foram transcritas de Pendências, incluindo as que não são
lisonjeiras (q09 falhando, ponto cego do conjunto de avaliação,
responsividade não confirmada em tela pequena).

**Estado em que a sessão foi deixada:** `pytest` verde (173 testes), pipeline
completo funcionando de ponta a ponta, README final, commit da Fase 8 feito.
Projeto entregue conforme o brief.

### 2026-08-26 — Sessão 9 (Claude Code)

**O que foi feito:** escolha do modelo de geração pela interface, a pedido do
usuário — "só opus 5 deixa a aplicação muito cara".

**Decisões tomadas nesta sessão:**

- **Catálogo de modelos como fonte única** (`src/providers/catalog.py`) — a API
  valida contra ele, o CLI valida contra ele e a interface monta o seletor a
  partir de `GET /api/models`. A alternativa era listar os modelos no JS e
  aceitar qualquer string no backend; foi descartada porque as duas listas
  divergem na primeira mudança e o sintoma é o seletor oferecer um modelo que a
  API recusa. Há teste travando a direção da dependência: nenhum id do catálogo
  pode aparecer escrito no `app.js`.
- **O provedor é derivado do modelo, não pedido junto** — `get_llm_provider`
  ganhou o parâmetro `model`, e quando ele vem, o provedor sai do catálogo em
  vez de `LLM_PROVIDER`. Pedir o par (provedor, modelo) na requisição criaria a
  chance de chegarem contraditórios; assim isso é irrepresentável. `LLM_PROVIDER`
  segue decidindo só o padrão.
- **Preço no catálogo, como metadado de exibição** — valores conferidos em
  26/08/2026 nas duas tabelas oficiais. Nada no código ramifica por preço. Ficam
  ali porque o motivo do seletor existir é custo: sem o número ao lado, a escolha
  vira palpite. Preço de tabela envelhece — o docstring datou a conferência.
- **Modelos sem chave aparecem como indisponíveis, não somem** — quem avalia o
  projeto precisa ver que a alternativa existe e o que falta para usá-la. Escolher
  um deles é 400 (erro de pedido), não 503 (falha de serviço).
- **Cache preguiçoso de provedores por modelo na API** — construir um cliente de
  SDK por requisição jogaria fora a conexão HTTP reaproveitada; construir todos
  no arranque puniria quem usa um só. A escrita concorrente é benigna e está
  comentada como tal.

**Dois defeitos encontrados e corrigidos no caminho:**

1. **`OPENAI_LLM_MODEL=gpt-5` não existe mais.** A conta não lista esse id: a
   aplicação subia normal e só quebraria na primeira pergunta com
   `LLM_PROVIDER=openai`. Trocado por `gpt-5.4-mini` no `.env`, no `.env.example`
   e no default de `config.py`. Há teste de regressão exigindo que os dois
   modelos padrão estejam no catálogo.
2. **O cabeçalho mentia depois da troca de modelo.** `GERAÇÃO` vinha de
   `/api/health` (o padrão do `.env`) e continuava dizendo `claude-opus-5`
   enquanto a resposta logo abaixo vinha assinada por `claude-haiku-4-5`.
   Encontrado olhando o screenshot da interface, não pelos testes. Agora o
   seletor é dono desse campo, com bandeira para a resposta tardia do
   `/api/health` não sobrescrever a escolha.

**Medição na mesma pergunta** (`T1055 no Windows`, top-3), todas ancoradas e
citando as 3 regras: `claude-opus-5` 11,4 s · `claude-haiku-4-5` 4,3 s ·
`gpt-5.4-nano` 3,2 s. A qualidade da citação não caiu nos modelos baratos —
esperado, já que o pipeline entrega o contexto pronto e a tarefa de redação é
modesta.

**Pendência levantada e não executada:** o `AnthropicLLMProvider` não passa
`thinking` nem `output_config`. No Opus 5 isso significa pensamento adaptativo
ligado por padrão, ou seja, tokens de raciocínio cobrados em toda pergunta de
uma tarefa que é essencialmente redigir a partir de contexto já recuperado.
Passar `output_config={"effort": "low"}` provavelmente corta custo sem perda
relevante aqui. Não foi feito porque muda a qualidade da resposta e estava fora
do que foi pedido — decisão do usuário, registrada para a próxima sessão.

**Estado em que a sessão foi deixada:** `pytest` verde — 183 testes, incluindo
os de integração contra o banco indexado e as duas APIs reais (168 sem
integração). Interface verificada no navegador: seletor populado pela API, foco
de teclado visível, troca de modelo, persistência da escolha entre recargas e
cabeçalho coerente com ela. Aplicação no ar em `127.0.0.1:8000`.

Nota de ambiente: o `ruff` está configurado no `pyproject.toml` mas não está
instalado no `.venv`, então o lint não foi executado nesta sessão.

**Correção na mesma sessão, após retorno do usuário:** *"eu não vi nada
relacionado a me dar a opção de escolher essas opções no front-end"*.

O relato estava certo e o defeito era de design, não de implementação: o
seletor era um `<select>`, e um menu suspenso **esconde as opções até alguém
clicar nele**. A página não comunicava que havia escolha a fazer — as sete
opções e os sete preços eram invisíveis, que é justamente o oposto do objetivo
(comparar custo antes de escolher). Trocado por fichas de rádio visíveis,
agrupadas por provedor, no mesmo idioma visual dos chips de exemplo que a
página já usava (tracejado em repouso, sólido e verde quando ativo). São
`input[type=radio]` reais dentro de um `fieldset`, então navegação por setas,
papel de grupo e foco de teclado vêm do navegador, sem reimplementação.

Há teste travando isso: `<select` não pode voltar ao HTML da interface.

**Segundo defeito, encontrado ao investigar o relato:** a rota `/` não mandava
nenhum cabeçalho de cache, então o navegador servia o `index.html` anterior por
heurística própria — quem editava a interface via a versão velha e concluía que
a mudança não tinha subido. Agora responde `Cache-Control: no-cache`, que não
proíbe cache: obriga a revalidar. Os estáticos já revalidavam por `etag`.

**Lição registrada:** os testes de interface do projeto conferem que os `id` do
HTML e do JS casam e que os arquivos são servidos — nenhum deles consegue ver
que um controle é *indescobrível*. Isso só apareceu porque um humano olhou a
tela. Screenshot de verificação não substitui a pergunta "dá para perceber que
isso é clicável, sem clicar?".

### 2026-08-27 — Sessão 10 (Claude Code)

**O que foi feito:** reconstrução do front-end, a pedido do usuário ("está muito
amador"), seguindo a skill `frontend-design` que ele colocou na raiz do repo
como `SKILL.md`.

**Diagnóstico antes de desenhar.** A skill lista três aparências em que design
gerado por IA se acomoda por padrão. A interface da Fase 7 estava em cima de
duas: layout de jornal com réguas finas e raio quase zero, e — no tema escuro —
fundo quase preto com um único accent verde. Somado a Space Grotesk + IBM Plex,
que é o par tipográfico reflexo, o resultado lia como template. A crítica do
usuário estava correta e tinha causa identificável.

**Decisões de design desta reconstrução:**

- **Conceito: instrumento de bancada, não documento.** Quem usa isto passa o dia
  em console de SIEM. A identidade vem de painel de instrumento — petróleo com
  matiz visível (nunca preto), superfícies fresadas, detalhamento em latão.
- **Paleta de 6 nomeadas** (`--petroleo #0B1F28`, `--bancada #102C38`,
  `--fresa #1D4454`, `--luz #E6F0F2`, `--vapor #86A6B0`, `--latao #D9A441`),
  mais verde de aferição e âmbar de ressalva em superfície mínima. Dois accents
  semânticos em vez de um único vibrante: é o que separa a paleta do formato
  "quase preto com um accent" que a skill manda evitar.
- **Tipografia com três papéis**: Chakra Petch (display, angular, de painel,
  usada com parcimônia), Archivo (corpo), JetBrains Mono (dados, identificadores
  e lógica de detecção). Nenhuma é a escolha reflexa, e há teste exigindo as
  três famílias.
- **Assinatura: o mapa do acervo.** Uma célula por regra indexada — 5.664 — e a
  consulta *acende* as que responderam. É o produto inteiro numa imagem:
  recuperação é estreitamento. Desenhado em canvas, e não em 5.664 nós no DOM.
  A posição de cada regra vem de um hash FNV-1a do `rule_uid`, então a mesma
  regra cai sempre na mesma célula — sem estabilidade o mapa não significaria
  nada. A cascata de acendimento respeita `prefers-reduced-motion`.
- **Sem numeral nos três passos do percurso.** O nome de cada etapa já carrega a
  ordem; numerar seria decorar, e a skill é explícita sobre marcadores numerados
  que não codificam sequência real. Os índices `[1]`..`[k]` das fichas continuam
  numerados porque ali o número *é* o identificador de citação.
- **Tema escuro assumido, não alternado** — decidido com o usuário. "Latão sobre
  petróleo" não tem equivalente honesto em tema claro, e um claro meia-boca é
  exatamente o acabamento que a reconstrução buscava eliminar. O piso de
  qualidade foi mantido (foco visível, movimento reduzido, quebra mobile) e o
  teste que exigia `prefers-color-scheme: dark` foi trocado por um que exige a
  declaração explícita de `color-scheme` e o fundo pintado — a decisão passou a
  ser verificada, não apagada.
- **Nome no cabeçalho passou a ser "Assistente de detecção"** (o nome real do
  projeto), em vez da metáfora "Mesa de referência", que vinha do conceito
  anterior. A skill pede nomear pelo que a pessoa reconhece.

**Achado que muda a leitura do problema: o Dark Reader estava repintando a
página.** Ao medir as cores computadas no navegador, o fundo vinha
`rgb(24,26,27)` — cinza neutro — e não o `#0B1F28` do token. A extensão tinha
injetado onze folhas de estilo e re-derivado a paleta inteira. Cadeia de
evidências: o token resolvia certo, a regra estava no CSSOM, um `background`
*inline* no botão era ignorado (só `!important` de origem "user" faz isso),
nenhuma regra `!important` existia em folha acessível da página, um `<button>`
recém-criado aceitava a cor, e os valores observados (`#181A1B` de fundo,
`#E8E6E3` de texto) são a assinatura do Dark Reader.

Acrescentado `<meta name="darkreader-lock">`, o mecanismo oficial da extensão
para se abster em página que já tem tema escuro próprio. Isso devolveu o fundo
correto, mas os controles de formulário continuaram sendo transformados — a
extensão segue com regras por seletor de origem "user" nesta máquina.

**Consequência honesta:** boa parte do que o usuário via como "amador"
provavelmente era a extensão achatando qualquer paleta para o mesmo cinza. A
estrutura, a tipografia e o layout foram verificados no navegador; **o
julgamento de cor não pôde ser feito nesta máquina** enquanto o Dark Reader
estiver ativo para `127.0.0.1`.

**Pendências desta sessão:**
- **Quebra mobile não verificada visualmente.** `resize_window` reportou sucesso
  mas o `window.innerWidth` permaneceu em 2560; as media queries de 980px e
  620px estão escritas e não foram confirmadas em viewport real.
- O `ruff` continua configurado no `pyproject.toml` e ausente do `.venv`.

**Estado em que a sessão foi deixada:** `pytest` verde — 186 testes, incluindo
integração. Consulta completa exercitada na interface nova (mapa acendendo 5 de
5.664, resposta ancorada, 5/5 citadas, fichas com procedência e lógica). Sem
erros no console.

**Correção após relato de layout quebrado (mesma data).**

O usuário abriu a página e encontrou o layout desmontado. Investigação: servidor
no ar, os três arquivos em 200, CSS com 133 chaves balanceadas e sem caractere
inválido, e — medindo em iframes de 390, 700 e 1280 px — nenhum transbordo
horizontal e as 117 regras carregadas nas três larguras. Ou seja, o estado em
disco estava íntegro; a quebra foi de *entrega*, não de código.

**Causa: cache incoerente entre o HTML e os estáticos.** A rota `/` tinha
recebido `Cache-Control: no-cache` na sessão anterior, mas o mount `/static`
não. Sem `Cache-Control`, o navegador aplica frescor heurístico próprio, então
era possível receber o `index.html` novo — que revalidava — junto com o
`styles.css` **antigo**, servido do cache. Markup novo com nomes de classe
velhos é exatamente uma página sem estilo. A reconstrução da interface trocou
todos os nomes de classe (`.desk` → `.bancada`, `.card` → `.ficha`, …), o que
tornou essa incoerência máxima em vez de sutil.

Corrigido com um middleware que carimba `no-cache` em `/static/*`. `no-cache`
não proíbe o cache: obriga a revalidar, e o `etag` que o StaticFiles já emite
faz a resposta ser um 304 barato. Há teste de integração exigindo que o HTML e
os dois estáticos revalidem juntos — a assimetria é que causou o defeito, então
é ela que o teste trava.

Corrigido também, preventivamente: `min-width: 0` no `fieldset` do seletor de
modelos. Um `fieldset` não encolhe abaixo da largura mínima do conteúdo por
padrão e é assim que empurra a página para fora da viewport em tela estreita.
Não estava causando transbordo nas larguras medidas, mas é armadilha conhecida
e o custo de desarmar é uma linha.

**Pendência anterior resolvida:** a quebra mobile, que ficara sem verificação
porque `resize_window` não alterava o `innerWidth`, foi confirmada renderizando
a página dentro de iframes de largura fixa — as media queries respondem ao
viewport do iframe. Em 390 px o formulário empilha, o botão ocupa a largura
inteira, as fichas de modelo quebram por provedor e nada transborda.

**Nota de verificação:** dentro do iframe o Dark Reader não se aplica, então
foi ali que as cores reais puderam ser conferidas pela primeira vez — o botão
sai em `rgb(217,164,65)`, o latão do plano, nas três larguras.

`pytest` verde: 187 testes.

### 2026-08-29 — Sessão 11 (Claude Code)

**Índice de técnicas ATT&CK e a faceta "Sem técnica declarada".** Partiu de uma
pergunta do usuário — se valeria categorizar 100% do acervo com alguma técnica,
já que ele queria construir busca por técnica.

**A resposta foi não, e virou desenho.** Forçar 100% preencheria por inferência
a coluna que o filtro rígido trata como verdade, misturando técnica declarada
pela fonte com técnica adivinhada aqui. O raciocínio completo está em Decisões.
O que substituiu a ideia: expor as 458 regras como faceta pedível, e construir o
índice do acervo — que é onde a faceta ganha sentido, porque é lá que ela deixa
de ser um buraco e vira um número.

**Medições feitas antes de decidir, e duas mudaram o desenho:**

| Medição | Valor | Efeito |
|---|---|---|
| Regras sem técnica | 458 de 5.664 (8,1%) | vira a faceta |
| Técnicas distintas | 473, em 187 famílias | todas bem formadas |
| `mitre_tactics` | 67 valores para 14 táticas reais | **matou** o agrupamento por tática |
| Rollup do inventário | 604 ms → ~70 ms | otimizado; sem cache |

O caso da `mitre_tactics` é o mais instrutivo: eu ia agrupar o catálogo por
tática, que é o eixo legível para um analista, e a medição mostrou a coluna
carregando ID de software (`S0029`), ID de tática cru e blobs com vírgula. Virou
pendência em vez de fundação.

**O achado que só o dado externo resolveu.** `T1685` aparecia em 276 regras e eu
não conseguia afirmar se era ID válido ou artefato de parsing — a suspeita era
plausível pelo volume. O mapa ATT&CK resolveu: é "Disable or Modify Tools", a
renumeração de `T1562` no v19.2, e o acervo usa as duas grafias. Zero IDs fora
do ATT&CK entre os 473, o que também é um atestado dos parsers da Fase 1.
Registrar isto importa porque a conclusão intuitiva (`T1685` é lixo) estava
errada e teria levado a "limpar" dado bom.

**A invariante que dá sentido ao catálogo.** O número exibido tem que ser o que
o clique devolve. Como o filtro expande `T1055` → `T1055.%` e `T1218.011` →
`T1218`, uma contagem calculada em separado exibiria "T1059.001 — 252" e o
clique devolveria 375. `expand_technique` virou função única, usada pelo
`_filter_sql` e pelo rollup. Conferido contra o Postgres nas **482 entradas**
(473 técnicas + 9 pais sintéticos): **zero divergência**. Travado em teste de
propriedade que roda sem banco, mais um de integração contra o WHERE real.

**O que foi entregue:**
- `src/ingestion/attack_names.py` — gerador offline do mapa ATT&CK, com
  `--check` para conferir o acervo contra ele.
- `data/attack/techniques.json` — 1.140 técnicas, 105 KB, ATT&CK v19.2,
  commitado (fora dos caminhos gitignored).
- `src/retrieval/techniques.py` — inventário, rollup e a expansão compartilhada.
- `SearchFilters.include_untagged` e o `OR cardinality(...) = 0` no filtro.
- `GET /api/techniques`; `mitre_techniques` e `include_untagged` no `/api/ask`.
- Interface: índice recolhível dentro da seção do mapa, busca por ID ou nome,
  chips de filtro armado junto do campo de pergunta.
- 40 testes novos (`tests/test_techniques.py` + adições em `test_api.py`).
  **213 no total, todos verdes**, 9 deles de integração contra a base real.

**Um bug meu, corrigido durante a sessão:** o leitor de versão do bundle STIX
iterava sobre `x_mitre_version` achando que era lista. "19.2" iterado devolve
"1" — uma versão plausível o bastante para eu ter commitado o arquivo errado
sem notar. Só apareceu porque olhei a saída do script em vez de confiar no
"gravado com sucesso".

**Verificado no navegador**, não só em teste: catálogo com 188 linhas, faceta no
topo com 458, busca por "lsass" trazendo `T1003` e `T1547` (esta por "LSASS
Driver") com as subtécnicas abrindo sozinhas, e as duas consultas ponta a ponta
— filtro `T1003.001` devolvendo 5 regras todas marcadas com ele, e a faceta "Sem
técnica" devolvendo 5 regras todas com `mitre_techniques` vazio, que é
exatamente o conjunto que nenhum filtro alcançava antes. Responsividade
reconferida em 414 px pela técnica do iframe (o `resize_window` segue reportando
sucesso sem alterar o `innerWidth`).

**Estado em que a sessão foi deixada:** `pytest` verde (213 testes), servidor do
usuário na porta 8000 preservado, alterações **não commitadas** — o diff da
sessão anterior (reconstrução da interface) também segue sem commit no mesmo
working tree.

### 2026-08-29 — Sessão 12 (Claude Code)

**Painel de configuração de chaves, para quem clona o repositório trazer as
próprias.** O pedido mencionava "barra lateral"; não existe uma — o layout é de
coluna única — então o painel ficou no cabeçalho, ao lado dos medidores que já
dizem qual provedor está em uso.

**A pergunta que precisou ser feita antes de codar:** onde a chave vive. Três
modelos foram postos lado a lado com o custo de cada um, e a escolha foi a de
chave só no navegador. O raciocínio está em Decisões; o resumo é que sem
autenticação — fora do escopo v1 pelo `CLAUDE.md` — um endpoint que grave
segredo em disco é um jeito de estranho trocar a chave do operador.

**Duas coisas que o pedido não previa e que teriam entregue um app quebrado:**

1. **Não é uma chave, são duas pontas.** A pergunta vira vetor antes de virar
   resposta. Quem trouxesse só a chave "da IA generativa" (Anthropic) não
   conseguiria nem consultar. A interface declara o papel de cada provedor e
   avisa qual das pontas está descoberta — verificado no navegador: colando só
   a chave Anthropic, 3 dos 7 modelos destravam e o aviso de embedding
   permanece, que é o comportamento correto.
2. **A aplicação não subia sem chave** — exatamente o estado de quem acabou de
   clonar, e isso deixaria o painel inalcançável. O arranque passou a separar
   "falta um segredo" de "configuração inválida" (ver a REVISÃO em Decisões).
   Verificado: com as três chaves em branco a aplicação sobe, `/api/health`
   reporta `aguardando chave de embedding` e `/api/ask` devolve 400 com a
   instrução, em vez de 500.

**O que foi entregue:**
- `src/api/credentials.py` — cabeçalhos por provedor, validação que nunca ecoa
  o valor recebido, `apply_keys` por cópia e `redact` para as mensagens de erro.
- `GET /api/settings` — diagnóstico com booleanos, mais o modelo com que o
  corpus foi realmente indexado.
- `/api/ask` resolve provedores por requisição quando há chave de visitante, e
  **sem cache** nesse caminho.
- Painel no cabeçalho: campo mascarado, salvar/trocar/remover, avisos por ponta
  descoberta, e o seletor de modelos recalculando disponibilidade ao vivo.
- `tests/test_credentials.py` (31 testes) mais 7 em `test_api.py`.
  **251 no total, todos verdes**, 22 de integração.

**Um teste que corrigiu meu modelo mental, não o código:** eu havia escrito que
qualquer caractere de controle na chave deveria ser recusado, e o teste falhou
para `\n` no fim. O código estava certo: `strip()` apara quebra de linha de
copiar-e-colar, que é o caso comum e benigno; o que precisa ser recusado é
controle no **meio** do valor, que é corrupção. Os testes foram reescritos para
distinguir os dois, com o caso do meio coberto explicitamente.

**Verificado no navegador** com chave falsa: salvar guarda no `localStorage`,
limpa o campo, troca o rótulo para "neste navegador" e passa a emitir o
cabeçalho; remover desfaz as quatro coisas. Nenhuma chave real foi digitada, e
a chave falsa foi apagada do navegador ao fim.

**Estado em que a sessão foi deixada:** `pytest` verde (251 testes, 22 de integração), servidor
reiniciado na porta 8000 com o código novo, `SKILL.md` segue fora do
versionamento por ser conteúdo de terceiros.
