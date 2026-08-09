# Assistente de Detecção com RAG — Brief de Desenvolvimento

Este documento é o brief de engenharia e o ponto de partida para desenvolvimento
assistido por agente (Claude Code / Codex). Leia por completo antes de escrever
qualquer código.

---

## 1. Contexto e objetivo

Ferramenta de portfólio que demonstra, na prática, o funcionamento de vector DBs
e RAG. Indexa regras de detecção públicas (SigmaHQ, Splunk ESCU, detecções YARA-L
da comunidade do Google SecOps) e responde perguntas de analistas de segurança
citando a regra exata usada como fonte — nunca uma resposta inventada.

Critério de sucesso do projeto: um pipeline de RAG funcional, com decisões de
arquitetura documentadas e uma avaliação de qualidade de retrieval mensurável
(não "funciona no meu teste manual").

## 2. Escopo

**Dentro do escopo (v1):**
- Ingestão e normalização de regras públicas de 3 fontes (Sigma, ESCU, YARA-L)
- Chunking que separa campos narrativos da query bruta de detecção
- Embeddings + pgvector com metadados (plataforma, técnica MITRE)
- Busca híbrida (vetorial + filtro por metadado / full-text)
- Pipeline RAG completo com citação da fonte na resposta
- Harness de avaliação de retrieval (conjunto de perguntas com resposta conhecida)
- API + frontend de demonstração com identidade visual própria (ver seção 4)

**Fora do escopo (v1):**
- Fine-tuning de modelo de embedding ou de geração
- Autenticação de usuários / multi-tenant (esse é um projeto separado)
- Upload de regras privadas do usuário
- Deploy produtivo com alta disponibilidade

## 3. Stack técnica

- Python 3.12
- FastAPI + Pydantic v2 para a API
- Postgres + extensão `pgvector` para o armazenamento vetorial
- Docker Compose para subir o ambiente local (Postgres já com pgvector)
- Provedor de LLM e de embedding: **configurável**, com suporte tanto a Anthropic
  quanto a OpenAI (ver subseção abaixo)
- Frontend de demo: não é um item secundário — ver seção 4

### Provedores de LLM e embedding

O projeto deve suportar dois provedores intercambiáveis, escolhidos por variável
de ambiente, nunca hardcoded:

- `ANTHROPIC_API_KEY` — Claude via Anthropic API (padrão)
- `OPENAI_API_KEY` — modelos da OpenAI como alternativa

Implementar como uma camada de abstração simples em `src/providers/`, com uma
interface comum para geração de texto e para geração de embeddings, e uma
variável de configuração (`LLM_PROVIDER` / `EMBEDDING_PROVIDER` = `anthropic` |
`openai`) que decide qual implementação é usada em tempo de execução. Nenhuma
outra parte do código deve depender diretamente do SDK de um provedor
específico — só essa camada.

Isso resolve duas coisas ao mesmo tempo: dá flexibilidade prática (nem todo
mundo avaliando o projeto vai ter as duas chaves) e é, por si só, um sinal de
design maduro — evitar lock-in de provedor é uma decisão de arquitetura, não só
um detalhe de configuração. Registrar as duas variáveis (sem valores reais) em
`.env.example`, e documentar no README qual provedor foi usado por padrão na
avaliação (Fase 6), já que resultados de retrieval podem variar entre modelos
de embedding diferentes.

## 4. Design de frontend

A interface não é um detalhe secundário — é parte do que demonstra qualidade de
engenharia no portfólio. Ao construir o frontend, o agente deve seguir a skill
de design de frontend da Anthropic:

https://github.com/anthropics/skills/blob/main/skills/frontend-design/SKILL.md

**No Claude Code:** verificar primeiro se a skill já está disponível localmente
(ambientes com as skills públicas da Anthropic costumam tê-la em
`/mnt/skills/public/frontend-design/SKILL.md` ou equivalente) e usá-la
diretamente. Se não estiver disponível, buscar o conteúdo na URL acima antes de
desenhar qualquer tela.

**No Codex**, que não tem esse sistema de skills nativo: ler o conteúdo da URL
acima como referência de projeto antes de implementar o frontend, e seguir os
mesmos princípios.

Resumo dos princípios centrais (isto não substitui a leitura do documento
completo antes de implementar):

- Evitar o "look" genérico de design gerado por IA (fundo creme com serifada de
  alto contraste + accent terracota; fundo quase preto com um único accent
  vibrante; layout estilo jornal com regras finas) — a menos que haja um motivo
  específico do projeto para usar exatamente isso
- Processo em duas passadas: primeiro um plano de design compacto (paleta com
  4–6 cores nomeadas, tipografia com papéis definidos, conceito de layout, um
  elemento de assinatura), depois criticar esse plano antes de implementar
- Gastar a ousadia em um único elemento de assinatura; manter o resto disciplinado
- Piso de qualidade não negociável: responsivo até mobile, foco de teclado
  visível, `prefers-reduced-motion` respeitado
- Copy é material de design, não decoração — linguagem do ponto de vista de quem
  usa a interface, voz ativa, mensagens de erro específicas

*Critério de aceite da Fase 7 (ver roadmap): a interface deve refletir uma
decisão de design deliberada e específica para este projeto — não um template
genérico de dashboard.*

## 5. Estrutura de diretórios sugerida

```
.
├── CLAUDE.md              # este arquivo
├── PROGRESS.md            # memória de continuidade entre sessões (ver seção 8)
├── README.md              # documentação voltada a humanos / portfólio
├── .env.example           # ANTHROPIC_API_KEY / OPENAI_API_KEY / flags de provedor
├── docker-compose.yml
├── data/
│   └── raw/                # clones das fontes públicas — gitignored
├── src/
│   ├── ingestion/           # normalização das 3 fontes em schema comum
│   ├── chunking/             # separação narrativa vs query
│   ├── providers/              # abstração Anthropic / OpenAI (LLM + embedding)
│   ├── embeddings/               # geração e indexação no pgvector
│   ├── retrieval/                  # busca híbrida
│   ├── rag/                         # pipeline completo: retrieval -> prompt -> geração
│   ├── api/                          # FastAPI
│   └── frontend/                      # interface de demo (ver seção 4)
├── eval/
│   ├── questions.jsonl       # conjunto de avaliação (pergunta -> regra correta)
│   └── run_eval.py
└── tests/
```

## 6. Roadmap de desenvolvimento

Cada fase tem um critério de aceite claro. Não avance de fase sem cumprir o
critério — registre a conclusão em `PROGRESS.md`.

**Fase 0 — Setup**
Repositório, ambiente Docker Compose com Postgres+pgvector, esqueleto de
diretórios, `.env.example`. *Aceite: `docker compose up` sobe o banco com a
extensão pgvector habilitada.*

**Fase 1 — Coleta e normalização**
Clonar as 3 fontes, definir e implementar um schema comum (título, descrição,
query, plataforma, técnica MITRE, referências). *Aceite: as 3 fontes convertidas
para o mesmo schema, validado com Pydantic.*

**Fase 2 — Estratégia de chunking**
Separar campos narrativos (embeddados) da query bruta (preservada como contexto).
*Aceite: função de chunking testada com casos de cada uma das 3 fontes.*

**Fase 3 — Embeddings e ingestão**
Implementar a camada de provedores (`src/providers/`), escolher o modelo de
embedding padrão, gerar vetores, popular o pgvector com colunas de metadado.
*Aceite: base populada e consultável com pelo menos um dos dois provedores
funcionando ponta a ponta.*

**Fase 4 — Busca híbrida**
Combinar similaridade vetorial com filtro por metadado ou full-text do Postgres.
*Aceite: uma pergunta com termo exato (ex: "T1055") recupera corretamente mesmo
quando a similaridade semântica pura falharia.*

**Fase 5 — Pipeline RAG**
Pergunta → embedding → retrieval top-k → prompt com contexto → resposta gerada
citando a regra, usando o provedor de LLM configurado. *Aceite: resposta sempre
referencia a fonte real recuperada, nunca texto fora do contexto fornecido, e
funciona trocando `LLM_PROVIDER` entre `anthropic` e `openai`.*

**Fase 6 — Avaliação**
20–30 perguntas com regra correta conhecida; medir taxa de acerto do retrieval
nos top-k. *Aceite: resultado documentado em `eval/` com número reproduzível.*

**Fase 7 — Frontend e demo**
Interface seguindo a skill de frontend-design (seção 4) + endpoint FastAPI.
*Aceite: alguém de fora consegue rodar e testar sem contexto adicional, e a
interface não parece um template genérico.*

**Fase 8 — Documentação final**
README com as decisões de arquitetura e os resultados da avaliação.

## 7. Convenções de código

- Type hints obrigatórios; dados estruturados sempre como modelos Pydantic
- Testes unitários para lógica de chunking e de retrieval (são as partes com
  mais risco de erro silencioso)
- Commits pequenos, um por unidade lógica de trabalho, mensagem descrevendo o
  *porquê*, não só o *o quê*
- Nunca commitar os dados brutos clonados de terceiros (`data/raw/` no
  `.gitignore`) nem chaves de API reais (só `.env.example`, nunca `.env`)

## 8. Continuidade do projeto entre sessões

Este projeto será desenvolvido em múltiplas sessões, possivelmente alternando
entre Claude Code e Codex. Sem um mecanismo de memória explícito, cada nova
sessão perde o porquê das decisões já tomadas. Para resolver isso:

**Regra obrigatória para o agente, em toda sessão:**

1. **No início de qualquer sessão**, antes de escrever ou alterar qualquer
   código, ler `PROGRESS.md` na raiz do repositório. Se o arquivo não existir,
   criá-lo com a estrutura abaixo.
2. **Ao final da sessão**, ou imediatamente após concluir uma fase ou tomar uma
   decisão de arquitetura relevante (como a escolha do modelo de embedding
   padrão ou detalhes da camada de provedores), atualizar `PROGRESS.md`.
3. **Nunca sobrescrever** o histórico de sessões anteriores — apenas adicionar
   uma nova entrada datada ao final. Decisões antigas só são revisadas, nunca
   apagadas (se uma decisão for revertida, registrar o motivo, não deletar o
   registro original).

**Estrutura do `PROGRESS.md`:**

```markdown
# Progresso do projeto

## Status atual
- Fase atual: <número e nome da fase>
- Última atualização: <data>

## Decisões de arquitetura
- <decisão> — <por que foi tomada, alternativas consideradas e descartadas>

## Pendências / bloqueios
- <o que está travando avanço, se houver>

## Próximos passos
- <ação concreta e imediata para a próxima sessão>

## Histórico de sessões
### <data> — Sessão N (Claude Code / Codex)
- O que foi feito
- Decisões tomadas nesta sessão
- Estado em que a sessão foi deixada
```

`README.md` é para humanos avaliando o portfólio. `PROGRESS.md` é para o agente
manter continuidade. Não misture os dois propósitos no mesmo arquivo.

