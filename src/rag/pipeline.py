"""Pipeline RAG completo: pergunta → retrieval → prompt → resposta citada.

A peça que não é óbvia aqui é a **verificação de citações**. O prompt pede que
o modelo cite só os índices existentes, mas pedir não é garantir: nada impede
uma resposta citar `[7]` com cinco regras no contexto. Como o critério de
aceite da fase é "a resposta sempre referencia a fonte real recuperada",
tratamos isso como propriedade a verificar, não a torcer para que aconteça.

`CitationCheck` diz, para cada resposta gerada: quais índices foram citados,
quais são inválidos, e se sobrou alguma afirmação sem citação nenhuma. Quem
consome (a API da Fase 7, a avaliação da Fase 6) decide o que fazer — mas
ninguém precisa adivinhar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import psycopg

from ..providers import EmbeddingProvider, LLMProvider
from ..retrieval.search import HybridRetriever, RetrievedRule, SearchFilters, SearchResponse
from .prompt import SYSTEM_PROMPT, build_prompt

# Teto de tokens da resposta. Uma resposta sobre regras de detecção não passa
# perto disso; o valor existe para o caso patológico, e `answer_truncated`
# sinaliza se chegou lá em vez de entregar um texto cortado sem avisar.
MAX_ANSWER_TOKENS = 4096

_CITATION_RE = re.compile(r"\[(\d+)\]")


@dataclass(frozen=True)
class CitationCheck:
    """O que a resposta citou, e se citou certo."""

    cited: tuple[int, ...] = ()
    invalid: tuple[int, ...] = ()
    #: True quando a resposta não citou nada apesar de haver regras no contexto.
    uncited: bool = False

    @property
    def is_grounded(self) -> bool:
        """A resposta se apoia só em regras que existem no contexto."""
        return not self.invalid and not self.uncited


@dataclass
class RagAnswer:
    """Resposta gerada, com tudo que a torna auditável."""

    question: str
    answer: str
    #: Só as regras efetivamente citadas, na ordem dos índices.
    citations: list[RetrievedRule] = field(default_factory=list)
    #: Tudo que foi recuperado, citado ou não — a Fase 6 mede recall com isto.
    retrieved: list[RetrievedRule] = field(default_factory=list)
    search: SearchResponse | None = None
    citation_check: CitationCheck = CitationCheck()
    llm_provider: str = ""
    llm_model: str = ""
    answer_truncated: bool = False
    #: Motivo de parada cru do provedor, para log.
    stop_reason: str | None = None
    #: True quando não houve regra recuperada e nem chegamos a chamar o modelo.
    answered_without_model: bool = False


def check_citations(answer: str, rule_count: int) -> CitationCheck:
    """Confere que os índices citados existem no contexto fornecido."""
    cited: list[int] = []
    invalid: list[int] = []

    for match in _CITATION_RE.findall(answer):
        index = int(match)
        if 1 <= index <= rule_count:
            if index not in cited:
                cited.append(index)
        elif index not in invalid:
            invalid.append(index)

    return CitationCheck(
        cited=tuple(sorted(cited)),
        invalid=tuple(sorted(invalid)),
        uncited=rule_count > 0 and not cited,
    )


NO_RULES_ANSWER = (
    "Não encontrei nenhuma regra no acervo que corresponda a essa pergunta. "
    "O acervo cobre regras públicas do SigmaHQ, do Splunk ESCU e das detecções "
    "YARA-L da comunidade do Google SecOps."
)


class RagPipeline:
    """Orquestra retrieval e geração."""

    def __init__(
        self,
        retriever: HybridRetriever,
        llm: LLMProvider,
        top_k: int = 5,
        max_answer_tokens: int = MAX_ANSWER_TOKENS,
    ) -> None:
        self._retriever = retriever
        self._llm = llm
        self._top_k = top_k
        self._max_answer_tokens = max_answer_tokens

    @classmethod
    def build(
        cls,
        conn: psycopg.Connection,
        embedding_provider: EmbeddingProvider,
        llm_provider: LLMProvider,
        top_k: int = 5,
    ) -> RagPipeline:
        return cls(HybridRetriever(conn, embedding_provider), llm_provider, top_k=top_k)

    def answer(
        self, question: str, top_k: int | None = None, filters: SearchFilters | None = None
    ) -> RagAnswer:
        """Responde à pergunta citando as regras recuperadas."""
        search = self._retriever.search(question, top_k=top_k or self._top_k, filters=filters)

        # Sem contexto não há o que citar, e chamar o modelo aqui só criaria a
        # oportunidade de ele responder de memória — exatamente o que a fase
        # precisa impedir. Responder sem modelo é a opção segura e mais barata.
        if not search.results:
            return RagAnswer(
                question=question,
                answer=NO_RULES_ANSWER,
                retrieved=[],
                search=search,
                llm_provider=self._llm.name,
                llm_model=self._llm.model,
                answered_without_model=True,
            )

        prompt = build_prompt(question, search)
        generation = self._llm.generate(
            system=SYSTEM_PROMPT, prompt=prompt, max_tokens=self._max_answer_tokens
        )

        check = check_citations(generation.text, len(search.results))
        citations = [search.results[index - 1] for index in check.cited]

        return RagAnswer(
            question=question,
            answer=generation.text,
            citations=citations,
            retrieved=list(search.results),
            search=search,
            citation_check=check,
            llm_provider=self._llm.name,
            llm_model=self._llm.model,
            # Vem do motivo de parada que o provedor reportou, não de heurística
            # sobre o texto: uma resposta terminada em bloco de código não tem
            # pontuação final e seria acusada de cortada sem ter sido.
            answer_truncated=generation.truncated,
            stop_reason=generation.stop_reason,
        )
