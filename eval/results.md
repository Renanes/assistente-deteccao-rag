# Avaliação de retrieval

- Data: 2026-08-22
- Perguntas: 30
- Corpus indexado: 5664 chunks
- Modelo de embedding: text-embedding-3-small
- Profundidade de busca: top-20

## Ablação

| Configuração | recall@1 | recall@3 | recall@5 | recall@10 | MRR |
|---|---|---|---|---|---|
| **Padrão**: filtro ATT&CK + vetorial | 80% | 97% | 97% | 97% | 0.879 |
| + perna de full-text | 67% | 93% | 93% | 93% | 0.786 |
| + inferência de plataforma | 73% | 87% | 87% | 87% | 0.796 |
| + ambas (híbrida original da Fase 4) | 63% | 83% | 83% | 83% | 0.724 |
| Vetorial pura, sem filtro (linha de base) | 73% | 97% | 97% | 97% | 0.846 |

## Recortes da configuração padrão (recall@5)

**Tipo de pergunta**

| | acertos | total | recall@5 |
|---|---|---|---|
| attack_id | 8 | 8 | 100% |
| lexical | 11 | 12 | 92% |
| semantic | 10 | 10 | 100% |

**Fonte da regra**

| | acertos | total | recall@5 |
|---|---|---|---|
| sigma | 11 | 12 | 92% |
| splunk_escu | 10 | 10 | 100% |
| yara_l | 8 | 8 | 100% |

## Perguntas fora do top-5 na configuração padrão

| id | posição | categoria | pergunta |
|---|---|---|---|
| q09 | 20 | lexical | uso do tttracer.exe para despejar a memoria de um processo como o lsas |

## Varredura do k do RRF

| Configuração | recall@1 | recall@3 | recall@5 | recall@10 | MRR |
|---|---|---|---|---|---|
| k = 10 | 80% | 97% | 97% | 97% | 0.879 |
| k = 30 | 80% | 97% | 97% | 97% | 0.879 |
| k = 60 | 80% | 97% | 97% | 97% | 0.879 |
| k = 100 | 80% | 97% | 97% | 97% | 0.879 |

## Ancoragem das respostas geradas

- Modelo de geração: anthropic/claude-opus-5
- Respostas ancoradas: 30/30
- Respostas com citação inexistente: 0/30

_Chamadas de embedding (com cache): 30_
