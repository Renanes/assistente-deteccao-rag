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

A ferramenta tem **quatro áreas**, escolhidas no menu do cabeçalho:

| Área | Para quê |
|---|---|
| **Consultar** | perguntar em linguagem natural e ler a resposta com as regras citadas |
| **Técnicas** | navegar o que o acervo cobre e armar filtros por técnica ATT&CK |
| **Ampliar** | procurar regras novas nos repositórios confiáveis e aprovar o que entra |
| **Repositórios** | ver, cadastrar e remover os repositórios em que a busca pode entrar |

Ao lado do menu fica a **Configuração**, onde se traz a própria chave de API.
O endereço acompanha a área (`#tecnicas`), então recarregar a página ou mandar
o link para alguém devolve a mesma tela.

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
4. **Filtra pelo catálogo de técnicas ATT&CK** (área "Técnicas"), se preferir
   navegar em vez de perguntar: clicar numa técnica arma um filtro rígido para
   a próxima busca (inclui a faceta "sem técnica declarada", para as 458 regras
   que não trazem esse metadado). O filtro age na pergunta, que está na área
   "Consultar" — a aba mostra quantos filtros estão armados, e há um botão de
   ida direto para o campo de pergunta.
5. **Amplia o acervo** (área "Ampliar"), quando o que você procura
   ainda não está indexado:
   - Descreve o que quer passar a detectar — ex.: *"abuso de LAPS e delegação
     Kerberos no Active Directory"* — e a aplicação procura regras em
     **repositórios confiáveis**, e só neles.
   - Cada regra encontrada volta como uma proposta com o repositório, o
     caminho do arquivo, o link, a lógica de detecção e o motivo de ter
     subido (que termo ou técnica casou).
   - **Nada entra no acervo sem aprovação.** Cada proposta tem dois botões:
     *Adicionar ao acervo*, que indexa a regra na hora e a torna consultável
     na busca; e *Recusar*, que não escreve nada. Uma regra recusada continua
     aparecendo em buscas futuras, marcada como recusada.
   - O relatório da busca mostra os termos usados, quantas origens foram
     consultadas, quantos arquivos foram lidos e quantas regras encontradas
     **já estavam** no acervo — que é uma informação sobre a cobertura atual,
     não ruído.
   - A lista de onde a busca pode entrar fica na área **Repositórios** — há um
     atalho para ela na própria tela de busca.

6. **Cuida dos repositórios confiáveis** (área "Repositórios"):
   - A lista completa do que está cadastrado, com o formato das regras de cada
     um, a pasta lida e por que aquela origem é confiável. Sete já vêm
     cadastradas depois do deploy.
   - **Cadastrar** um repositório novo: cola o endereço do GitHub (a URL
     inteira serve), escolhe o formato das regras e, se precisar, o branch e a
     pasta. A aplicação confere no GitHub que o repositório existe e descobre
     o branch padrão sozinha — nome errado é recusado na hora, com o motivo.
   - **Tirar** qualquer um, inclusive os que já vieram cadastrados. Removido,
     ele não volta sozinho.
   - Só entram repositórios cujas regras a aplicação sabe ler (Sigma e Splunk
     ESCU em YAML, YARA-L em `.yaral`). O formulário diz isso antes da
     tentativa, em vez de aceitar e nunca devolver nada.

7. **Traz a própria chave de API**, se quiser (painel "Configuração"):
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
- Não aceita upload de regras próprias — só o acervo público indexado, mais
  o que for aprovado pela descoberta (que também só lê repositórios públicos).
- A descoberta não navega na web aberta: ela lê exclusivamente os
  repositórios cadastrados como confiáveis, no GitHub. Não há campo para
  apontá-la para uma URL qualquer, e o código recusa qualquer host fora
  dessa lista.
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
