# Resumo funcional — Assistente de Detecção com RAG

> Documento de leitura rápida: o que a aplicação faz, na prática. Para o
> porquê de cada decisão técnica, ver [`README.md`](./README.md); para o
> histórico de sessões e decisões revisadas, ver [`PROGRESS.md`](./PROGRESS.md).

## O que é

Uma ferramenta de busca para analistas de segurança: você descreve, em
linguagem natural, o que quer detectar — e ela responde citando a regra de
detecção pública exata que sustenta a resposta, nunca um texto inventado.

O acervo tem **5.664 regras de detecção** vindas de três fontes públicas:

| Fonte | Regras | O que é |
|---|---:|---|
| SigmaHQ | 3.141 | Regras Sigma, formato aberto multiplataforma |
| Splunk ESCU | 2.144 | Enterprise Security Content Update, da Splunk |
| YARA-L (Google SecOps) | 379 | Regras da comunidade Chronicle/Google SecOps |

## Como se usa

1. **Escreve a pergunta** na caixa de busca, em português ou inglês — ex.:
   *"tem regra pra T1055 no Windows?"* ou *"como detectar dump de memória do
   LSASS?"*. Há sugestões prontas para começar.
2. **Escolhe o modelo que redige a resposta** (opcional) — fichas com preço
   por 1M de tokens, de `gpt-5.4-nano` (mais barato) a `claude-opus-5` (mais
   caro). A escolha vale só para aquela pergunta; a busca não muda.
3. **Lê a resposta**, que vem com:
   - As regras citadas, numeradas (`[1]`, `[2]`...) e linkadas para a fonte
     real no GitHub.
   - Um **selo de ancoragem**: quantas citações da resposta foram conferidas
     contra as regras realmente recuperadas, e se alguma citação "furou".
     Isso não é um aviso de prompt — é uma checagem feita em código depois
     da resposta sair.
   - Se nenhuma regra do acervo cobre a pergunta, a aplicação diz isso
     explicitamente em vez de responder de memória.
4. **Filtra pelo catálogo de técnicas ATT&CK**, se preferir navegar em vez
   de perguntar: clicar numa técnica arma um filtro rígido para a próxima
   busca (inclui a faceta "sem técnica declarada", para as 458 regras que
   não trazem esse metadado).
5. **Traz a própria chave de API**, se quiser (painel "Configuração"):
   - A chave fica só no navegador de quem usa (`localStorage`), nunca é
     enviada para o `.env` do servidor nem devolvida por nenhum endpoint.
   - O painel mostra uma prévia mascarada de qualquer chave já colada
     (ex.: `sk-pro…abcd`), com opção de trocar ou remover a qualquer
     momento.
   - A interface avisa quando falta cobrir alguma das duas pontas do
     pipeline (embedding e geração são provedores independentes) e quando o
     modelo de embedding escolhido não bate com o que indexou o acervo.

## Como funciona por baixo (resumo)

```
pergunta em linguagem natural
      │
      ├─ cita uma técnica ATT&CK? ──► filtro rígido por metadado
      │                                (T1055 casa T1055 e todas as .subtécnicas)
      │
      └─ sempre ─────────────────► embedding da pergunta ──► busca vetorial
                                                               (pgvector, HNSW)
                                                                     │
                                                    top-5 regras mais parecidas
                                                                     │
                                        prompt com as regras numeradas, nada mais
                                                                     │
                                                            resposta gerada
                                                                     │
                                    verificação: toda citação existe no contexto?
```

Medido contra 30 perguntas de resposta conhecida: **97% de recall@5**, MRR de
**0,879**, e as 30 respostas geradas vieram ancoradas, sem nenhuma citação
inexistente. Método completo em [`eval/results.md`](./eval/results.md).

## O que a aplicação **não** faz (por escopo, não por limitação técnica)

- Não tem login nem separa usuários — é uma demonstração de portfólio, de
  uso local.
- Não aceita upload de regras próprias — só o acervo público indexado.
- Não guarda histórico de conversa entre perguntas; cada pergunta é
  independente.
- Não treina nem ajusta modelo nenhum — usa modelos prontos de LLM e de
  embedding via API.

## Rodando localmente

Resumo de três comandos (detalhes em [`README.md`](./README.md#rodando-localmente)):

```bash
docker compose up -d                                      # sobe o Postgres
uvicorn src.api.main:app --host 127.0.0.1 --port 8000      # sobe a aplicação
```

Abre `http://127.0.0.1:8000` — a interface é servida pela própria API, sem
passo de build.

## Stack, em uma linha

Python 3.12 · FastAPI · Postgres + pgvector · Anthropic/OpenAI/Voyage
(provedor escolhido por variável de ambiente) · frontend em HTML/CSS/JS puro,
sem framework.
