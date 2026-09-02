# Assistente de Detecção com RAG

Indexa **5.664 regras de detecção públicas** (SigmaHQ, Splunk ESCU, YARA-L da
comunidade Google SecOps) e responde perguntas de analistas de segurança
citando a regra exata usada como fonte.

A promessa central — *nunca uma resposta inventada* — não é feita por prompt.
Cada citação da resposta é conferida **em código** contra as regras que o
retrieval realmente devolveu, e o resultado dessa conferência aparece na
interface.

| | |
|---|---|
| Regras indexadas | **5.664** (Sigma 3.141, ESCU 2.144, YARA-L 379) |
| Recall@5 do retrieval | **97%** em 30 perguntas de resposta conhecida |
| MRR | **0,879** |
| Respostas ancoradas | **30/30**, com 0 citações inexistentes |
| Método e números completos | [`eval/results.md`](./eval/results.md) |

Os números saíram de `text-embedding-3-small` (OpenAI, 1536 dimensões) para o
embedding e `claude-opus-5` para a geração. Resultados de retrieval variam
entre modelos de embedding; trocar o provedor exige reindexar.

---

## Como funciona

```
pergunta em linguagem natural
      │
      ├─ técnica ATT&CK citada? ──► filtro rígido na coluna de metadado
      │                              (T1055 casa T1055 e T1055.*)
      │
      └─ pergunta inteira ──────► embedding ──► similaridade de cosseno
                                                 (HNSW no pgvector)
                                                        │
                                        top-k regras recuperadas
                                                        │
                    prompt com as regras numeradas [1]…[n], nada mais
                                                        │
                                              resposta gerada
                                                        │
                    ✔ verificação: todo [n] citado existe no contexto?
```

O detalhe que distingue este projeto de uma demo genérica de RAG está na
última linha. As demais decisões estão abaixo.

---

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

### Escolha do modelo de geração

O `.env` define apenas o **padrão**. A interface mostra os modelos como fichas
selecionáveis, com o preço em cada uma, e a escolha vale por pergunta — o
acervo, a busca e a verificação de citação não mudam com ela. Só muda quem
redige a resposta.

As opções ficam à vista sem precisar abrir nada, de propósito: o motivo do
controle existir é comparar custo, e um menu suspenso esconderia justamente a
informação que sustenta a escolha.

O catálogo vive em `src/providers/catalog.py` e é servido por `GET /api/models`,
com preço por 1M de tokens:

| Modelo | Provedor | Entrada | Saída |
| --- | --- | ---: | ---: |
| `gpt-5.4-nano` | OpenAI | US$ 0,20 | US$ 1,25 |
| `gpt-5.4-mini` | OpenAI | US$ 0,75 | US$ 4,50 |
| `claude-haiku-4-5` | Anthropic | US$ 1,00 | US$ 5,00 |
| `gpt-5.4` | OpenAI | US$ 2,50 | US$ 15,00 |
| `claude-sonnet-5` | Anthropic | US$ 3,00 | US$ 15,00 |
| `claude-opus-5` | Anthropic | US$ 5,00 | US$ 25,00 |
| `gpt-5.5` | OpenAI | US$ 5,00 | US$ 30,00 |

Preços conferidos em 26/08/2026; são metadado de exibição e não entram em
nenhuma decisão do código. Um modelo cujo provedor não tem chave configurada
aparece no seletor como indisponível, em vez de sumir — quem avalia o projeto
deve ver que a alternativa existe e o que falta para usá-la.

O ganho é concreto: na mesma pergunta (`T1055 no Windows`, top-3), a resposta
sai ancorada e citando as 3 regras nos três modelos testados, com
`claude-opus-5` em 11,4 s, `claude-haiku-4-5` em 4,3 s e `gpt-5.4-nano` em
3,2 s — a 20x menos por token de saída.

### Sem interface

```bash
python -m src.retrieval.run "tem regra pra T1055 no Windows?" --explain
python -m src.rag.run "como detectar dump de memória do LSASS?" --show-sources
python -m src.rag.run "mesma pergunta" --provider openai        # troca o provedor
python -m src.rag.run "mesma pergunta" --model claude-haiku-4-5  # troca o modelo
```

`--model` implica o provedor: escolher `claude-haiku-4-5` já manda a chamada
para a Anthropic, mesmo com `LLM_PROVIDER=openai` no ambiente.

### Avaliação

```bash
python eval/run_eval.py --sweep            # métricas de retrieval e ablação
python eval/run_eval.py --with-rag         # inclui ancoragem (gasta LLM)
```

### Descoberta de regras novas

Amplia o acervo procurando regras em repositórios confiáveis. Pela interface,
na área **Ampliar** (menu do cabeçalho); pela linha de comando:

```bash
python -m src.discovery.run sources                  # os repositórios cadastrados
python -m src.discovery.run sources --add owner/repo --format sigma
python -m src.discovery.run search "abuso de LAPS no Active Directory"
python -m src.discovery.run approve sigma:<id>       # indexa a regra proposta
python -m src.discovery.run reject  sigma:<id>
```

A busca **não** indexa nada: ela devolve propostas com o repositório e o
arquivo de origem, e só `approve` escreve no acervo. `GITHUB_TOKEN` no `.env`
é opcional — sem ele a busca lê a árvore de arquivos de cada repositório
(60 requisições por hora, por IP); com ele, também procura dentro do conteúdo.


### Testes

```bash
pytest                      # tudo
pytest -m "not integration" # só o que não precisa de banco nem de chave
```

Os testes marcados como `integration` exigem o Postgres no ar, o corpus
indexado e uma chave válida; sem isso são pulados automaticamente.

---

## Decisões de arquitetura

### 1. A query de detecção não vira vetor

Uma regra tem duas metades com naturezas opostas: campos narrativos (título,
descrição, falsos positivos) e a lógica de detecção (`EventID=1`, `| tstats`,
`$e.metadata.event_type`). Só a primeira é embeddada.

Sintaxe de linguagem de busca domina o vetor com tokens que ninguém digita numa
pergunta em linguagem natural. A query vai junto no chunk, **literal**, como
contexto para a resposta — o analista quer ver a regra, não uma paráfrase dela.

A separação acontece já no schema de ingestão, não na camada de chunking. Isso
mantém o parsing dos três formatos em um lugar só: a Fase de chunking lida com
texto, não com YAML e YARA-L.

### 2. Um chunk por regra, decidido medindo

O texto narrativo mais longo das 5.664 regras tem 1.897 caracteres, com p99 em
1.455. Nenhuma chega perto do tamanho em que dividir compensaria, e dividir
criaria chunks irmãos competindo pelo mesmo top-k e uma citação ambígua ("qual
pedaço da regra?").

`chunk_index` e `chunk_total` existem no contrato mesmo valendo sempre 0 e 1:
se a avaliação mostrar perda de recall em descrições longas, dividir passa a
ser mudança de código e não migração de banco.

A query preservada tem teto de 4.000 caracteres. A distribuição é concentrada
(p90 = 1.268), mas a cauda é extrema: a regra *Vulnerable Driver Load* do Sigma
tem **250 KB** de query, quase tudo lista de hash do LOLDrivers. Sem teto, uma
única regra recuperada estoura o contexto do prompt. O corte atinge 41 das
5.664 regras, cai numa fronteira de linha (meia condição parece completa e
engana quem lê) e liga uma flag que a resposta usa para remeter à fonte.

### 3. `text-embedding-3-small`, e o motivo não é custo

Os índices HNSW e IVFFlat do pgvector aceitam no máximo **2.000 dimensões**. O
`text-embedding-3-large` produz 3.072: a busca vetorial cairia em varredura
sequencial sobre o corpus inteiro, ou exigiria migrar a coluna para `halfvec` e
aceitar a perda de precisão. O `3-small` tem 1.536 e cabe.

Há uma guarda que recusa qualquer modelo acima do limite **antes** de gastar
chamada de API, e um teste que trava o padrão como indexável.

### 4. A camada de provedores, e o teste que a defende

`LLM_PROVIDER` e `EMBEDDING_PROVIDER` são variáveis independentes de propósito:
a Anthropic não expõe API de embeddings própria, então "gerar com um provedor e
embeddar com outro" é o caso normal, não a exceção. A configuração padrão deste
projeto é exatamente essa.

Não existe `EMBEDDING_PROVIDER=anthropic`. Cogitei implementá-lo chamando a
Voyage AI por baixo e descartei: o nome mentiria sobre qual serviço recebe o
texto e qual chave é cobrada. A Voyage entrou como provedor de primeira classe,
e `anthropic` levanta um erro que explica o porquê e aponta as duas saídas.

O requisito de não depender de um SDK específico fora dessa camada é
**verificado, não confiado**: um teste varre `src/` e falha se encontrar
`import openai`, `import anthropic` ou `import voyageai` fora de
`src/providers/`. Sem ele, a regra sobrevive só enquanto alguém lembrar dela.

### 5. A busca híbrida, e o que a avaliação desmentiu

Esta é a decisão mais interessante do projeto, porque a medição contradisse o
desenho original.

A intuição era combinar três sinais: filtro por metadado, similaridade vetorial
e busca full-text, fundidos por Reciprocal Rank Fusion. Uma medição pontual
parecia confirmar: para a pergunta "T1055", a busca vetorial pura devolvia 0 de
5 regras corretas e a híbrida, 5 de 5.

A avaliação sistemática mostrou que o ganho vinha de **uma** das três peças, e
que as outras duas atrapalhavam:

| Configuração | recall@5 | MRR |
|---|---:|---:|
| **Padrão hoje**: filtro ATT&CK + vetorial | **97%** | **0,879** |
| Vetorial pura, sem filtro (linha de base) | 97% | 0,846 |
| + perna de full-text | 93% | 0,786 |
| + inferência de plataforma | 87% | 0,796 |
| + ambas (a híbrida original) | 83% | 0,724 |

**A inferência de plataforma excluía a resposta certa.** A função que mapeia
texto para plataforma foi escrita para telemetria (`Sysmon EventID 1` ⇒
windows), não para frase corrente, e aplicada a perguntas dispara demais:
"endereço de e-mail" virava filtro `email` numa regra marcada como `web`;
"logs web" virava `web` numa regra `network`; "Google Workspace" virava `gcp`
numa regra **sem plataforma declarada** — e 181 regras estão nesse caso, então
qualquer filtro de plataforma as elimina. Filtro explícito, vindo de uma faceta
de interface, continua valendo: quem escolhe "windows" num menu quis dizer
isso; quem escreveu "logs web" numa frase, não.

**A perna de full-text era redundante por construção.** A coluna indexada era o
mesmo texto que o vetor já cobria — as duas pernas olhavam para a mesma coisa,
e a lexical só somava ruído de OR. Foram medidas quatro variantes (peso
reduzido, só identificadores, indexando também a query bruta) e nenhuma superou
simplesmente não usá-la.

**O que sobreviveu** é o filtro ATT&CK, que dá o ganho real sobre a vetorial
pura (MRR 0,879 contra 0,846) e expande nos dois sentidos: `T1055` casa suas
subtécnicas, `T1218.011` casa também o pai. Isso importa porque o full-text do
Postgres tokeniza `T1055.001` como termo único, então uma busca por `T1055`
nunca o alcançaria por via lexical.

A perna de full-text segue implementada e ativável por parâmetro, e a coluna
passou a indexar a query bruta — o único material que o embedding não vê. O
conjunto de avaliação atual não cobre esse caso, então a decisão de mantê-la
desligada vale enquanto for essa a evidência.

### 6. "Nunca inventa" é verificado, não prometido

O prompt do sistema proíbe responder fora do contexto e exige citação. Isso é
um pedido, não uma garantia: nada impede um modelo escrever `[7]` com cinco
regras no contexto.

Depois da geração, `check_citations` extrai os índices citados e confere cada
um contra as regras recuperadas. O resultado — quantas citadas, quais
inválidas, se a resposta não citou nada — vai no payload da API e aparece na
interface como o selo de ancoragem. É o que transforma *"pedimos para citar
certo"* em *"sabemos se citou"*.

Três decisões de apoio:

- **As regras entram numeradas (`[1]`, `[2]`), não pelo `rule_uid`.** Pedir que
  o modelo repita `sigma:ec570e53-4c76-45a9-804d-dc3f355ff7a7` no meio do texto
  convidaria erro de transcrição, e um UID errado é uma citação falsa. O
  mapeamento índice → regra real é feito em código.
- **Sem regra recuperada, o modelo não é chamado.** Contexto vazio só criaria a
  oportunidade de ele responder de memória.
- **Filtro que não casa nada é relaxado, com aviso visível.** Devolver lista
  vazia deixa o analista sem saber por quê; relaxar em silêncio faria a resposta
  afirmar que existe regra para uma técnica que o corpus não cobre.

Verificação direta: perguntado *"qual a capital da França?"*, o assistente
responde que as regras fornecidas não respondem à pergunta e descreve o que o
contexto cobre. Ele sabe a resposta e recusa usá-la.

### 7. A interface

Conceito: **mesa de referência, não conversa**. O acervo são regras catalogadas
com identificador estável e link verificável, e o produto é a citação — por
isso cada regra é uma ficha de catálogo com a lógica de detecção mostrada como
ela é escrita na fonte, e não um card de dashboard.

O elemento de assinatura é o selo de ancoragem descrito acima. A ousadia visual
fica concentrada nele; o resto é disciplinado de propósito.

Sem framework, sem CDN de biblioteca e sem passo de build: a página é servida
pela própria aplicação FastAPI, para que rodar a demo seja um comando. O
renderizador de markdown tem ~60 linhas e escapa HTML antes de tudo, porque o
texto vem de um LLM e não é confiável por construção.

**Quatro áreas, não uma pilha.** A primeira versão empilhava tudo numa página
só, e foi ficando errada à medida que a ferramenta cresceu: perguntar, navegar
o que o acervo cobre, trazer regra nova e cuidar de onde ela pode vir são
tarefas diferentes, feitas em momentos diferentes e — nas duas últimas — por
quem mantém o acervo, não por quem consulta. Um menu no cabeçalho separa
**Consultar**, **Técnicas**, **Ampliar** e **Repositórios**; a Configuração
fica na mesma faixa, à direita.

**Repositórios é área e não painel** porque a lista é o limite do que a
descoberta enxerga. Enquanto ela era um `<details>` recolhido dentro da busca,
ver esse limite exigia primeiro fazer uma busca — e é a primeira coisa que
alguém avaliando a ferramenta precisa conseguir olhar.

O que a separação obriga a pagar, e onde está pago:

- **O mapa fica em Consultar**, não na área do acervo, porque ele é parte da
  resposta: é o mapa que mostra a consulta estreitando o acervo inteiro até as
  poucas regras que a sustentam. Como um canvas oculto tem largura zero, a troca de
  vista redesenha o mapa — sem isso, abrir a página em `#ampliar` e voltar
  deixava o elemento de assinatura em branco.
- **O filtro é armado numa vista e age noutra.** Clicar numa técnica restringe
  a próxima pergunta, que está em outra área — então a aba Consultar ganha um
  selo com a contagem e a área de Técnicas mostra um aviso com o caminho de
  volta. Sem isso o clique não teria consequência visível, que é o custo
  clássico de separar telas. Pelo mesmo motivo, a área de Ampliar tem um
  caminho direto para a de Repositórios: a busca depende da lista, e quem está
  buscando não deveria ter que procurá-la no menu.
- **O endereço acompanha a vista** (`#tecnicas`), com `replaceState` e não
  atribuição de hash: a segunda forma empilharia uma entrada de histórico por
  clique e transformaria o "voltar" do navegador num desfazer de abas.
- **O menu é um `tablist` de verdade**: setas percorrem as abas, `tabindex`
  rotativo, `aria-controls`/`aria-labelledby` fechando nos dois sentidos. Há
  testes para o fechamento das referências — é o tipo de coisa que quebra em
  silêncio quando alguém renomeia um `id`.

### 8. A descoberta é restrita por uma lista, não por instrução

A tool que amplia o acervo (`src/discovery/`) busca regras "na internet" — e a
palavra que faz o trabalho aqui é *restrita*. Um agente que consulta a web e
depois filtra o que não presta já leu o que não devia; a única forma de a
restrição significar algo é ela ser um dado explícito, conferido em código,
antes de a requisição sair.

**A allowlist é imposta em três camadas que se sobrepõem de propósito:**

1. **A URL é montada, nunca recebida.** Nenhuma função de rede aceita URL vinda
   de fora. O que entra é uma origem já validada mais um caminho relativo, e a
   URL sai de `source.raw_url(path)`. Uma URL para outro host não teria como
   ser construída.
2. **A origem é conferida a cada chamada**, não uma vez no arranque — a lista é
   um menu na interface e muda em tempo de execução. Um cliente que tivesse
   copiado a lista continuaria lendo uma origem recém-removida.
3. **O host é conferido no último instante**, imediatamente antes do envio, e o
   cliente HTTP não segue redirecionamento. Um 302 é exatamente o jeito de um
   host autorizado entregar conteúdo de outro.

Há testes para as três, e eles são a razão de o módulo de rede existir
separado do resto: `httpx.MockTransport` intercepta no transporte, então o
cliente real — com os cabeçalhos e o tratamento de erro reais — é o que está
sendo exercitado.

**A busca não decide.** `POST /api/discovery/search` produz propostas
persistidas como pendentes; `POST /api/discovery/decide` é o único caminho que
chunka, embeda e grava. Não existe endpoint que encontre e indexe no mesmo
passo, e isso é o desenho — não uma etapa que faltou juntar. Cada proposta
carrega o repositório, o caminho e o link do arquivo: aprovar sem ver a
procedência seria confiar num texto que apareceu na tela, que é o oposto do que
o resto do projeto faz.

**O formato é declarado, não adivinhado.** Uma origem só pode ser cadastrada se
as regras dela forem legíveis por um dos três parsers da Fase 1. Isso deixa de
fora coleções excelentes em outro formato — `elastic/detection-rules` é TOML —
e a exclusão é deliberada: aceitar o cadastro e não devolver nada seria pior
que recusar com o motivo na tela.

**Duas medições mudaram o código na primeira execução real**, e valem registro
porque as duas eram invisíveis em teste sintético:

| Sintoma | Causa | Correção |
|---|---|---|
| 12 propostas irrelevantes, todas nota 1.0 | plataforma pontuava sozinha, então todo arquivo com "windows" no nome virava candidato — a busca gastava suas leituras em ordem alfabética | plataforma virou desempate; só termo ou técnica qualifica |
| termos do modelo não casavam com título nenhum | o modelo devolve frases ("lsass memory dump") e nenhuma aparece literal num título | o termo é quebrado em tokens de casamento; a frase inteira vira bônus |

Uma terceira, menor: `dump` casava `dumpbin` por prefixo — outro binário, para
outra finalidade — e a regra errada subia junto. O casamento passou a aceitar
só flexão (`dump` → `dumping`), não prefixo livre.

**Os parsers são os mesmos da Fase 1**, agora com uma entrada por texto além da
entrada por arquivo (`parse_sigma_text`, `parse_escu_text`, `parse_yaral_text`).
Uma segunda implementação para o caminho de rede divergiria da do disco na
primeira correção, e a divergência apareceria como metadado diferente para a
mesma regra conforme de onde ela veio. Depois do parse, `source_url` é
reescrito para o repositório onde a regra foi de fato encontrada: citar uma
regra do `tsale/Sigma_rules` com link para o `SigmaHQ` seria uma citação que
parece boa e leva a lugar nenhum.

---

## Avaliação

O harness está em [`eval/`](./eval/) e o relatório reproduzível em
[`eval/results.md`](./eval/results.md).

**Método.** As 30 regras-alvo foram sorteadas do corpus com semente fixa,
estratificadas por fonte, **antes** de qualquer pergunta ser escrita — sem
isso, seria trivial escolher depois só as regras que funcionam e publicar um
número bonito. As perguntas foram escritas a partir da descrição de cada regra,
em português (o corpus é em inglês), sem copiar o título; há um teste
verificando isso, além de testes de integridade do conjunto.

**Recortes do resultado (recall@5):**

| Tipo de pergunta | | Fonte da regra | |
|---|---:|---|---:|
| termo ATT&CK exato | 100% | Splunk ESCU | 100% |
| descrição semântica | 100% | YARA-L | 100% |
| identificador lexical | 92% | SigmaHQ | 92% |

**Duas limitações que o número carrega**, e que nenhum processo aqui elimina:

1. **É um piso, não a taxa real.** Só um `rule_uid` é aceito como correto por
   pergunta, mas o corpus tem regras equivalentes — uma busca que devolve outra
   regra igualmente válida para dump de LSASS conta como erro.
2. **Quem escreveu as perguntas conhecia o sistema.** O viés é real e não some
   por boa intenção. O que reduz seu efeito é a amostra ter sido fixada antes e
   nenhuma pergunta ter sido descartada depois de ver o resultado.

---

## Limitações conhecidas

- **Uma pergunta do conjunto ainda falha** (q09, sobre `tttracer.exe`): a regra
  certa existe e tem o termo na descrição, mas o corpus tem muitas regras de
  dump de LSASS e a descrição dela é curta.
- **O conjunto de avaliação tem um ponto cego**: as perguntas saem das
  descrições, então nenhuma testa busca por termo que só existe na lógica de
  detecção. É justamente o caso em que a perna de full-text poderia se
  justificar, e por isso a decisão de mantê-la desligada é provisória.
- **A responsividade em largura de celular não foi confirmada visualmente.** Os
  pontos de quebra existem e há teste de que estão na folha de estilo, mas a
  verificação em tela pequena não foi feita.
- **Sem autenticação, sem multi-tenant, sem upload de regras privadas** — fora
  de escopo por decisão, não por esquecimento. Isso vale também para a
  descoberta: qualquer um que alcance a aplicação pode cadastrar uma origem e
  aprovar uma regra. Numa demo local isso é o comportamento desejado; exposta
  na rede, a aplicação precisaria de autenticação antes de qualquer coisa.
- **A relevância da descoberta é lexical, não semântica.** Ela pontua por
  casamento de termo e técnica, não por embedding: embedar candidatos antes da
  aprovação gastaria chamadas de API para material que talvez seja recusado.
  O custo é perder a regra cujo título não usa nenhuma das palavras do pedido.
- **A busca lê no máximo 20 arquivos por origem.** É o teto de custo que mantém
  a busca interativa (~20 s em 7 origens). Uma regra que só apareceria na
  leitura 21 não é encontrada.
- **`k` do RRF e tamanho do pool não foram sintonizados.** Na configuração
  padrão existe uma única lista ranqueada, e o RRF preserva a ordem dela para
  qualquer `k`; a varredura só faz sentido com a perna de full-text ligada.

---

## Fontes e atribuição

Este repositório **não redistribui as regras de detecção**. `data/raw/` é
gitignored: as três fontes são clonadas por quem roda o projeto, direto dos
repositórios de origem, e cada uma continua sob a licença de quem a mantém.

| Fonte | Licença |
|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | regras sob [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License); a especificação Sigma é domínio público |
| [splunk/security_content](https://github.com/splunk/security_content) | Apache-2.0 |
| [chronicle/detection-rules](https://github.com/chronicle/detection-rules) | Apache-2.0 |

O que **é** redistribuído aqui é `data/attack/techniques.json` — 1.140 técnicas
(ID, nome, status e sucessor) derivadas do bundle STIX do MITRE ATT&CK®, geradas
por `src/ingestion/attack_names.py`. A licença do ATT&CK exige que qualquer
cópia reproduza a designação de direito autoral do MITRE:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with
> the permission of The MITRE Corporation.

Termos completos em
<https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>, e a nota
íntegra em [`data/attack/NOTICE.md`](./data/attack/NOTICE.md). O MITRE não
endossa este projeto.

---

## Stack

- Python 3.12, FastAPI + Pydantic v2
- Postgres + `pgvector` (índice HNSW, distância de cosseno)
- Provedor de LLM/embedding configurável via `.env` — nenhum SDK de provedor é
  importado fora de `src/providers/`, e há um teste que garante isso
- Interface sem framework e sem CDN de biblioteca: HTML, CSS e JS servidos pela
  própria aplicação
- 315 testes; os que exigem banco e chave estão marcados como `integration` e
  são pulados quando o ambiente não está montado

## Estrutura

```
src/
├── ingestion/   normaliza as 3 fontes num schema comum (Pydantic)
├── chunking/    separa o que vira vetor do que fica como contexto
├── providers/   abstração Anthropic / OpenAI / Voyage (LLM + embedding)
├── embeddings/  schema do pgvector e indexação
├── retrieval/   filtro por metadado + busca vetorial + fusão RRF
├── rag/         prompt, geração e verificação de citação
├── discovery/   busca de regras novas em repositórios confiáveis, com aprovação
├── api/         FastAPI
└── frontend/    interface de demonstração
eval/            conjunto de perguntas, harness e resultados
```

Para o histórico de decisões, incluindo as que foram revistas e o porquê, ver
[`PROGRESS.md`](./PROGRESS.md). O brief original do projeto está em
[`CLAUDE.md`](./CLAUDE.md).
