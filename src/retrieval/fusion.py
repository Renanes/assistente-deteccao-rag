"""Fusão de listas ranqueadas por Reciprocal Rank Fusion (RRF).

A busca híbrida produz duas listas de candidatos com pontuações que não se
comparam: similaridade de cosseno vive em [0, 1] e é razoavelmente bem
distribuída; `ts_rank` do Postgres é ilimitado para cima, costuma ficar na casa
de 0,0x e depende do tamanho do documento. Somar as duas exige normalizar, e
toda normalização aqui seria arbitrária — dividir pelo máximo do lote faz a
pontuação de um documento depender de quem mais veio no lote.

O RRF resolve isso descartando as pontuações e usando só a **posição**:

    score(d) = Σ  peso_l / (k + rank_l(d))
               l

Um documento bem colocado nas duas listas ganha das duas somas; um documento
que só aparece numa lista ainda pontua, mas menos. O `k` amortece o topo: com
k = 60, a diferença entre 1º e 2º lugar é pequena, o que evita que uma lista
ruim consiga empurrar seu primeiro colocado para o topo da fusão sozinha.

O valor 60 é o da publicação original (Cormack et al., 2009) e é o padrão de
fato; fica configurável para a Fase 6 poder variar e medir.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

RRF_K = 60


@dataclass(frozen=True)
class RankedList:
    """Uma lista de candidatos, do melhor para o pior."""

    name: str
    chunk_uids: Sequence[str]
    weight: float = 1.0


@dataclass
class FusedResult:
    """Um candidato depois da fusão."""

    chunk_uid: str
    score: float = 0.0
    #: Posição (1-indexada) em cada lista que trouxe este candidato. É o que
    #: permite explicar na interface *por que* uma regra apareceu.
    ranks: dict[str, int] = field(default_factory=dict)

    @property
    def matched_by(self) -> tuple[str, ...]:
        return tuple(sorted(self.ranks))


def reciprocal_rank_fusion(
    lists: Sequence[RankedList], k: int = RRF_K, limit: int | None = None
) -> list[FusedResult]:
    """Funde listas ranqueadas. Devolve os candidatos ordenados por score.

    Empates são desfeitos pelo `chunk_uid`, para a ordem ser determinística —
    sem isso, duas execuções idênticas poderiam devolver ordens diferentes e
    tornar a avaliação da Fase 6 irreproduzível.
    """
    if k <= 0:
        raise ValueError(f"k do RRF precisa ser positivo, recebi {k}")

    fused: dict[str, FusedResult] = {}

    for ranked in lists:
        for position, chunk_uid in enumerate(ranked.chunk_uids, start=1):
            result = fused.setdefault(chunk_uid, FusedResult(chunk_uid=chunk_uid))
            # Se um `chunk_uid` aparecer repetido dentro da mesma lista, vale a
            # primeira (melhor) posição — contar duas vezes inflaria o score.
            if ranked.name in result.ranks:
                continue
            result.ranks[ranked.name] = position
            result.score += ranked.weight / (k + position)

    ordered = sorted(fused.values(), key=lambda item: (-item.score, item.chunk_uid))
    return ordered[:limit] if limit is not None else ordered
