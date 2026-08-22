"""Montagem do prompt: instrução de sistema e contexto das regras recuperadas.

O critério de aceite da fase é que a resposta **sempre** referencie a fonte real
recuperada e nunca texto fora do contexto. Duas coisas sustentam isso, e a
segunda é a que importa:

1. A instrução de sistema proíbe responder fora do contexto e exige citação.
2. As citações são **verificadas em código** depois da geração
   (`pipeline.py`). Prompt é pedido, não garantia — um modelo pode citar `[7]`
   quando só existem 5 regras no contexto, e nada no prompt impede isso. A
   verificação transforma "pedimos para citar certo" em "sabemos se citou".

As regras entram numeradas (`[1]`, `[2]`, …) porque um índice curto é fácil de
o modelo reproduzir sem errar e trivial de casar por regex depois. Pedir que
repita `sigma:ec570e53-4c76-45a9-804d-dc3f355ff7a7` no meio do texto seria
convidar erro de transcrição — e um UID errado é uma citação falsa.
"""

from __future__ import annotations

from ..retrieval.search import RetrievedRule, SearchResponse

SYSTEM_PROMPT = """\
Você é um assistente de engenharia de detecção. Responde a analistas de \
segurança usando exclusivamente um conjunto de regras de detecção públicas \
que lhe é fornecido a cada pergunta.

Regras invioláveis:

1. Responda SOMENTE com base nas regras fornecidas no contexto. Se o contexto \
não contém a informação, diga isso explicitamente. Nunca complete com \
conhecimento próprio sobre detecção, ATT&CK ou ferramentas — mesmo que você \
tenha certeza da informação, ela não pertence a esta resposta.
2. Toda afirmação sobre uma regra precisa vir seguida do índice da regra entre \
colchetes: [1], [2]. Cite apenas os índices que existem no contexto.
3. Nunca invente nome de regra, ID, técnica ATT&CK ou link. Se precisa se \
referir a algo que não está no contexto, diga que não está no contexto.
4. Se as regras recuperadas não respondem à pergunta, diga isso em uma frase e \
descreva o que elas cobrem — não force uma resposta a partir do que sobrou.
5. Quando a query de uma regra estiver marcada como truncada, não afirme o que \
ela faz por inteiro; diga que foi cortada e remeta ao link da fonte.

Estilo: responda no mesmo idioma da pergunta. Seja direto e técnico, do ponto \
de vista de quem vai usar a regra. Sem preâmbulo, sem repetir a pergunta. \
Quando fizer sentido, mostre a query da regra — é o que o analista quer ver."""


def format_rule(rule: RetrievedRule, index: int) -> str:
    """Formata uma regra como um bloco numerado do contexto."""
    lines = [
        f"[{index}] {rule.title}",
        f"    Fonte: {rule.source} | ID: {rule.rule_uid}",
    ]
    if rule.source_url:
        lines.append(f"    Link: {rule.source_url}")

    metadata = []
    if rule.platforms:
        metadata.append(f"plataformas: {', '.join(rule.platforms)}")
    if rule.mitre_techniques:
        metadata.append(f"ATT&CK: {', '.join(rule.mitre_techniques)}")
    if rule.severity:
        metadata.append(f"severidade: {rule.severity}")
    if metadata:
        lines.append(f"    {' | '.join(metadata)}")

    lines.append("")
    lines.append("    Descrição:")
    lines.extend(f"    {line}" for line in rule.narrative.splitlines())

    lines.append("")
    truncated = " (TRUNCADA — ver o link da fonte)" if rule.query_truncated else ""
    lines.append(f"    Query ({rule.query_language}){truncated}:")
    lines.extend(f"    {line}" for line in rule.query.splitlines())

    return "\n".join(lines)


def build_context(rules: list[RetrievedRule]) -> str:
    """Monta o bloco de contexto com todas as regras recuperadas."""
    return "\n\n".join(format_rule(rule, index) for index, rule in enumerate(rules, start=1))


def build_prompt(question: str, response: SearchResponse) -> str:
    """Monta o prompt do usuário: avisos do retrieval + contexto + pergunta.

    Os avisos vêm antes do contexto de propósito. `relaxed_filters` significa
    que nenhuma regra do corpus cobre a técnica pedida — se o modelo descobrir
    isso só depois de ler cinco regras plausíveis, a chance de ele apresentá-las
    como resposta à pergunta original é muito maior.
    """
    parts: list[str] = []

    if response.relaxed_filters:
        pedido = ", ".join(response.filters.mitre_techniques + response.filters.platforms)
        parts.append(
            "AVISO IMPORTANTE: nenhuma regra do acervo corresponde ao filtro "
            f"pedido ({pedido}). As regras abaixo vieram de uma busca sem esse "
            "filtro e são apenas relacionadas. Comece a resposta deixando claro "
            "que não há regra para o que foi pedido."
        )

    parts.append("Regras de detecção recuperadas do acervo:")
    parts.append(build_context(response.results))
    parts.append(f"Pergunta do analista:\n{question}")

    return "\n\n".join(parts)
