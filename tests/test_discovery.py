"""Testes da descoberta de novos casos de uso (`src/discovery/`).

O foco aqui não é "a busca acha coisa boa" — isso depende do que os
repositórios publicaram hoje e não caberia num teste determinístico. O que é
testado é o que precisa valer **sempre**:

1. **A restrição é real.** Host fora da lista, repositório fora da lista e
   caminho fora do declarado são recusados antes de virar requisição. Estes
   testes são a razão de o módulo de rede existir separado.
2. **A pontuação não deixa passar o que não casou.** Foi o defeito da primeira
   execução real: plataforma sozinha qualificava candidato, e a busca gastava
   suas leituras em ordem alfabética.
3. **A decisão é humana.** Buscar não indexa; só `approve` escreve.

A rede é substituída por `httpx.MockTransport`, que intercepta na camada de
transporte — o cliente real, com os cabeçalhos e o tratamento de erro reais,
continua sendo exercitado. Um `GitHubClient` falso não testaria a checagem de
host, que é justamente o que interessa aqui.
"""

from __future__ import annotations



import httpx
import pytest

from src.discovery import github, proposals, search, sources
from src.discovery.search import SearchPlan, plan_search, rule_from_file, score_path, score_rule
from src.discovery.sources import RuleFormat, TrustedSource, normalize_slug
from src.ingestion.schema import RuleSource

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIGMA_YAML = """
title: LSASS Memory Dump via Comsvcs
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects credential dumping from LSASS using comsvcs.dll MiniDump.
author: Testes
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'comsvcs.dll'
  condition: selection
falsepositives:
  - Backup software
"""

YARAL_TEXT = """
rule suspicious_dns_tunneling {
  meta:
    author = "Testes"
    description = "Detects DNS tunneling by query length"
    rule_id = "mr_0001"
    mitre = "T1048"
    platform = "windows"
    severity = "High"
  events:
    $e.metadata.event_type = "NETWORK_DNS"
  condition:
    $e
}
"""


@pytest.fixture
def origem() -> TrustedSource:
    return TrustedSource(
        slug="exemplo/regras",
        ref="main",
        label="Exemplo",
        rule_format=RuleFormat.SIGMA,
        path_prefixes=["rules"],
    )


def cliente_falso(origem: TrustedSource, respostas: dict[str, httpx.Response]) -> github.GitHubClient:
    """Um `GitHubClient` real ligado a um transporte que não sai da máquina."""

    def handler(request: httpx.Request) -> httpx.Response:
        chave = f"{request.url.host}{request.url.path}"
        if chave in respostas:
            return respostas[chave]
        return httpx.Response(404, text="404: Not Found")

    return github.GitHubClient(
        [origem], client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )


def resposta_arvore(caminhos: list[str], truncated: bool = False) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "tree": [{"type": "blob", "path": caminho} for caminho in caminhos],
            "truncated": truncated,
        },
    )


# ---------------------------------------------------------------------------
# A lista de origens confiáveis
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entrada,esperado",
    [
        ("SigmaHQ/sigma", "SigmaHQ/sigma"),
        ("https://github.com/SigmaHQ/sigma", "SigmaHQ/sigma"),
        ("https://github.com/SigmaHQ/sigma.git", "SigmaHQ/sigma"),
        ("  owner/repo/  ", "owner/repo"),
    ],
)
def test_slug_aceita_o_que_a_pessoa_realmente_cola(entrada: str, esperado: str) -> None:
    """Colar a URL da barra de endereços é o caso comum, não o excepcional."""
    assert normalize_slug(entrada) == esperado


@pytest.mark.parametrize("ruim", ["sem-barra", "../../etc/passwd", "https://github.com/", "a//b"])
def test_slug_recusa_o_que_nao_e_repositorio(ruim: str) -> None:
    with pytest.raises(ValueError):
        normalize_slug(ruim)


def test_ref_recusa_travessia_de_caminho() -> None:
    """O `ref` entra na montagem de uma URL — `..` não pode chegar lá."""
    with pytest.raises(ValueError):
        TrustedSource(slug="a/b", ref="../../main", label="x", rule_format=RuleFormat.SIGMA)


def test_prefixo_de_caminho_recusa_travessia() -> None:
    with pytest.raises(ValueError):
        TrustedSource(
            slug="a/b", label="x", rule_format=RuleFormat.SIGMA, path_prefixes=["../segredo"]
        )


def test_aceita_so_arquivo_de_regra_dentro_do_caminho_declarado(origem: TrustedSource) -> None:
    assert origem.accepts("rules/windows/proc_creation.yml")
    assert not origem.accepts("README.md"), "extensão fora do formato"
    assert not origem.accepts("docs/rules/exemplo.yml"), "fora do prefixo declarado"
    assert not origem.accepts("rules/deprecated/velha.yml"), "diretório descontinuado"
    assert not origem.accepts("rules/tests/fixture.yml"), "material de teste não é regra"


def test_repositorio_inteiro_quando_nao_ha_prefixo() -> None:
    livre = TrustedSource(slug="a/b", label="x", rule_format=RuleFormat.SIGMA)
    assert livre.accepts("qualquer/lugar/regra.yaml")


def test_url_codifica_espaco_no_nome_do_arquivo() -> None:
    """Repositório de comunidade usa espaço em nome de arquivo o tempo todo."""
    livre = TrustedSource(slug="a/b", label="x", rule_format=RuleFormat.SIGMA)
    assert "%20" in livre.raw_url("cloud-azure/azure email rule.yaml")
    assert livre.raw_url("x/y.yaml").startswith("https://raw.githubusercontent.com/a/b/main/")


def test_sementes_sao_validas_e_sem_repeticao() -> None:
    """Uma semente quebrada só apareceria como 'a busca não acha nada'."""
    chaves = [source.key for source in sources.SEED_SOURCES]
    assert len(chaves) == len(set(chaves))
    for source in sources.SEED_SOURCES:
        assert source.is_seed and source.enabled
        assert source.rule_format in RuleFormat
        assert source.note, f"{source.slug} sem justificativa de confiança"


def test_as_tres_fontes_do_corpus_continuam_cadastradas() -> None:
    """Elas são o caminho para achar regra nova publicada upstream."""
    chaves = {source.key for source in sources.SEED_SOURCES}
    assert {"sigmahq/sigma", "splunk/security_content", "chronicle/detection-rules"} <= chaves


# ---------------------------------------------------------------------------
# A restrição de rede
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://exemplo.invalido/regra.yml",
        "https://github.com/SigmaHQ/sigma",  # o host do site não é o da API
        "http://localhost:8000/api/settings",
        "https://raw.githubusercontent.evil.com/a/b/main/x.yml",
    ],
)
def test_host_fora_da_lista_e_recusado(url: str) -> None:
    with pytest.raises(github.NotAllowedError):
        github._assert_host_allowed(url)


def test_repositorio_fora_da_lista_e_recusado_antes_da_rede(origem: TrustedSource) -> None:
    """A allowlist é conferida a cada chamada — não só no arranque."""
    intrusa = TrustedSource(slug="outro/repo", label="Outro", rule_format=RuleFormat.SIGMA)
    cliente = cliente_falso(origem, {})

    with pytest.raises(github.NotAllowedError):
        cliente.list_tree(intrusa)
    with pytest.raises(github.NotAllowedError):
        cliente.fetch_file(intrusa, "rules/x.yml")
    assert cliente.stats.requests == 0, "nenhuma requisição deveria ter saído"


def test_caminho_fora_do_declarado_e_recusado(origem: TrustedSource) -> None:
    cliente = cliente_falso(origem, {})
    with pytest.raises(github.NotAllowedError):
        cliente.fetch_file(origem, "../../etc/passwd")
    assert cliente.stats.requests == 0


def test_redirecionamento_nao_e_seguido(origem: TrustedSource) -> None:
    """Um 302 é o jeito de um host autorizado entregar conteúdo de outro."""
    cliente = cliente_falso(
        origem,
        {
            "raw.githubusercontent.com/exemplo/regras/main/rules/x.yml": httpx.Response(
                302, headers={"Location": "https://exemplo.invalido/x.yml"}
            )
        },
    )
    with pytest.raises(github.NotAllowedError):
        cliente.fetch_file(origem, "rules/x.yml")


def test_limite_de_requisicoes_vira_erro_proprio(origem: TrustedSource) -> None:
    """Esperar ou configurar token é uma saída diferente de qualquer outro erro."""
    cliente = cliente_falso(
        origem,
        {
            "api.github.com/repos/exemplo/regras/git/trees/main": httpx.Response(
                403, headers={"X-RateLimit-Remaining": "0"}, text="rate limited"
            )
        },
    )
    with pytest.raises(github.RateLimitError):
        cliente.list_tree(origem, use_cache=False)


def test_arvore_truncada_avisa_em_vez_de_falhar(origem: TrustedSource, tmp_path) -> None:
    """Meia árvore ainda acha regra; falhar deixaria a origem inacessível."""
    cliente = cliente_falso(
        origem,
        {
            "api.github.com/repos/exemplo/regras/git/trees/main": resposta_arvore(
                ["rules/a.yml", "rules/b.yml"], truncated=True
            )
        },
    )
    cliente._cache_dir = tmp_path
    caminhos = cliente.list_tree(origem, use_cache=False)

    assert caminhos == ["rules/a.yml", "rules/b.yml"]
    assert any("truncada" in aviso for aviso in cliente.stats.errors)


def test_busca_de_codigo_exige_token(origem: TrustedSource) -> None:
    """Sem token ela não existe — e a ferramenta continua funcionando sem ela."""
    cliente = cliente_falso(origem, {})
    assert cliente.search_code(origem, ["lsass"]) == []
    assert cliente.stats.requests == 0


# ---------------------------------------------------------------------------
# Plano de busca e pontuação
# ---------------------------------------------------------------------------


def test_plano_sem_modelo_ainda_extrai_identificador() -> None:
    """Quem não tem chave de geração continua conseguindo buscar."""
    plano = plan_search("tem regra pra T1055 com rundll32 no Windows?")

    assert plano.expanded_by_model is False
    assert plano.mitre_techniques == ["T1055"]
    assert "windows" in plano.platforms
    assert "rundll32" in plano.tokens


def test_tokens_descartam_palavra_generica_e_plataforma() -> None:
    """Palavra que casa com metade do acervo não separa nada."""
    plano = plan_search("detecção de processo suspeito no windows com mimikatz")

    assert "mimikatz" in plano.tokens
    for generica in ("detecção", "processo", "suspeito", "windows"):
        assert generica not in plano.tokens


def test_plano_usa_o_modelo_quando_ele_responde() -> None:
    class ModeloFalso:
        name = "falso"
        model = "modelo-de-teste"

        def generate(self, system: str, prompt: str, max_tokens: int = 2048):
            from src.providers.base import Generation

            return Generation(text="lsass memory dump, comsvcs.dll, procdump")

    plano = plan_search("dump de credenciais", llm=ModeloFalso())

    assert plano.expanded_by_model is True
    assert plano.model == "modelo-de-teste"
    assert "lsass memory dump" in plano.terms
    # A frase vira tokens: sem isso ela nunca casaria com um título de regra.
    assert {"lsass", "dump", "comsvcs.dll", "procdump"} <= set(plano.tokens)


def test_plano_cai_no_deterministico_quando_o_modelo_falha() -> None:
    class ModeloQuebrado:
        name = "falso"
        model = "modelo-de-teste"

        def generate(self, system: str, prompt: str, max_tokens: int = 2048):
            raise RuntimeError("cota esgotada")

    plano = plan_search("regra para mimikatz", llm=ModeloQuebrado())

    assert plano.expanded_by_model is False
    assert "mimikatz" in plano.tokens


def test_plataforma_sozinha_nao_qualifica_um_caminho() -> None:
    """O defeito da primeira execução real: 20 leituras gastas em ordem alfabética."""
    plano = SearchPlan(prompt="x", terms=["lsass"], tokens=["lsass"], platforms=["windows"])

    assert score_path("rules/windows/proc_creation_win_qualquer_coisa.yml", plano) == 0.0
    assert score_path("rules/windows/proc_creation_win_lsass_dump.yml", plano) > 0


def test_pontuacao_de_caminho_premia_o_token_no_nome() -> None:
    plano = SearchPlan(prompt="x", terms=["mimikatz"], tokens=["mimikatz"])

    nomeada = score_path("rules/win_mimikatz_execution.yml", plano)
    generica = score_path("rules/win_process_creation.yml", plano)
    assert nomeada > generica == 0.0


def test_regra_sem_casamento_nenhum_e_descartada() -> None:
    """Plataforma é desempate, nunca ingresso."""
    regra = rule_from_file(
        TrustedSource(slug="a/b", label="x", rule_format=RuleFormat.SIGMA),
        "rules/x.yml",
        SIGMA_YAML,
    )
    plano = SearchPlan(prompt="x", terms=["kerberoasting"], tokens=["kerberoasting"], platforms=["windows"])

    nota, termos, tecnicas = score_rule(regra, plano)
    assert (nota, termos, tecnicas) == (0.0, [], [])


def test_tecnica_pedida_pesa_mais_que_palavra_no_titulo() -> None:
    regra = rule_from_file(
        TrustedSource(slug="a/b", label="x", rule_format=RuleFormat.SIGMA),
        "rules/x.yml",
        SIGMA_YAML,
    )
    por_tecnica = score_rule(regra, SearchPlan(prompt="x", mitre_techniques=["T1003"]))
    por_palavra = score_rule(regra, SearchPlan(prompt="x", terms=["lsass"], tokens=["lsass"]))

    assert por_tecnica[0] > por_palavra[0] > 0
    assert por_tecnica[2] == ["T1003.001"], "pedir o pai casa a subtécnica"


def test_tecnica_casa_nos_dois_sentidos() -> None:
    regra = rule_from_file(
        TrustedSource(slug="a/b", label="x", rule_format=RuleFormat.SIGMA),
        "rules/x.yml",
        SIGMA_YAML,
    )
    # A regra declara T1003.001; pedir a subtécnica exata também tem que casar.
    _, _, tecnicas = score_rule(regra, SearchPlan(prompt="x", mitre_techniques=["T1003.001"]))
    assert tecnicas == ["T1003.001"]


@pytest.mark.parametrize(
    "token,titulo,casa",
    [
        ("dump", "Credential Dumping via LSASS", True),
        ("dump", "Dumpbin LOLBin proxy execution", False),
        ("lsass", "LSASS Memory Access", True),
        ("kerberos", "Kerberoasting detected", False),
    ],
)
def test_casamento_aceita_flexao_mas_nao_outra_palavra(token: str, titulo: str, casa: bool) -> None:
    """`dump` casa `dumping`; `dump` não pode casar `dumpbin`, que é outro binário."""
    plano = SearchPlan(prompt="x", terms=[token], tokens=[token])
    regra = rule_from_file(
        TrustedSource(slug="a/b", label="x", rule_format=RuleFormat.SIGMA),
        "rules/x.yml",
        SIGMA_YAML.replace("LSASS Memory Dump via Comsvcs", titulo).replace(
            "Detects credential dumping from LSASS using comsvcs.dll MiniDump.", "Sem pistas aqui."
        ),
    )
    assert bool(score_rule(regra, plano)[1]) is casa


# ---------------------------------------------------------------------------
# Normalização do que foi encontrado
# ---------------------------------------------------------------------------


def test_regra_encontrada_aponta_para_o_repositorio_onde_estava() -> None:
    """Citar a regra de um terceiro com link para o SigmaHQ seria citação falsa."""
    origem = TrustedSource(
        slug="tsale/Sigma_rules", label="Kostas", rule_format=RuleFormat.SIGMA
    )
    regra = rule_from_file(origem, "LOL_BINs/win_lsass.yml", SIGMA_YAML)

    assert regra is not None
    assert regra.source_url == "https://github.com/tsale/Sigma_rules/blob/main/LOL_BINs/win_lsass.yml"
    assert regra.source_path == "LOL_BINs/win_lsass.yml"
    # A fonte continua sendo o formato: uma regra Sigma é uma regra Sigma.
    assert regra.source is RuleSource.SIGMA
    assert regra.rule_uid == "sigma:11111111-2222-3333-4444-555555555555"


def test_cada_formato_usa_o_parser_da_fase_1() -> None:
    yaral = TrustedSource(
        slug="a/b", ref="main", label="x", rule_format=RuleFormat.YARA_L
    )
    regra = rule_from_file(yaral, "rules/dns.yaral", YARAL_TEXT)

    assert regra is not None
    assert regra.source is RuleSource.YARA_L
    assert regra.mitre_techniques == ["T1048"]
    assert regra.rule_uid == "yara_l:mr_0001"


def test_arquivo_que_nao_e_regra_devolve_none(origem: TrustedSource) -> None:
    assert rule_from_file(origem, "rules/leia-me.yml", "# só um comentário") is None


# ---------------------------------------------------------------------------
# A busca ponta a ponta (sem rede, sem banco)
# ---------------------------------------------------------------------------


def test_busca_propoe_sem_indexar_e_traz_a_procedencia(origem: TrustedSource, tmp_path) -> None:
    cliente = cliente_falso(
        origem,
        {
            "api.github.com/repos/exemplo/regras/git/trees/main": resposta_arvore(
                ["rules/win_lsass_dump.yml", "rules/win_outra_coisa.yml", "README.md"]
            ),
            "raw.githubusercontent.com/exemplo/regras/main/rules/win_lsass_dump.yml": httpx.Response(
                200, text=SIGMA_YAML
            ),
        },
    )
    cliente._cache_dir = tmp_path

    resultado = search.discover("dump de LSASS", [origem], cliente, llm=None)

    assert len(resultado.proposals) == 1
    proposta = resultado.proposals[0]
    assert proposta.source_slug == "exemplo/regras"
    assert proposta.source_path == "rules/win_lsass_dump.yml"
    assert proposta.source_url.startswith("https://github.com/exemplo/regras/blob/main/")
    assert proposta.status == "pending", "nada é aprovado pela busca"
    assert "lsass" in proposta.matched_terms
    # `win_outra_coisa.yml` não casou nenhum token: não foi nem lido.
    assert cliente.stats.files_read == 1


def test_busca_ignora_o_que_ja_esta_no_acervo(origem: TrustedSource, tmp_path) -> None:
    """Já indexada não é proposta — vira contagem de cobertura."""
    cliente = cliente_falso(
        origem,
        {
            "api.github.com/repos/exemplo/regras/git/trees/main": resposta_arvore(
                ["rules/win_lsass_dump.yml"]
            ),
            "raw.githubusercontent.com/exemplo/regras/main/rules/win_lsass_dump.yml": httpx.Response(
                200, text=SIGMA_YAML
            ),
        },
    )
    cliente._cache_dir = tmp_path

    resultado = search.discover(
        "dump de LSASS",
        [origem],
        cliente,
        known_uids={"sigma:11111111-2222-3333-4444-555555555555"},
        llm=None,
    )

    assert resultado.proposals == []
    assert resultado.already_indexed == 1


def test_busca_nao_entra_em_origem_desabilitada(origem: TrustedSource) -> None:
    desligada = origem.model_copy(update={"enabled": False})
    cliente = cliente_falso(origem, {})

    resultado = search.discover("lsass", [desligada], cliente, llm=None)

    assert resultado.sources_searched == []
    assert cliente.stats.requests == 0


def test_pedido_sem_termo_aproveitavel_avisa_em_vez_de_buscar(origem: TrustedSource) -> None:
    cliente = cliente_falso(origem, {})
    resultado = search.discover("o que você tem?", [origem], cliente, llm=None)

    assert resultado.proposals == []
    assert resultado.warnings, "o vazio precisa dizer o que fazer"
    assert cliente.stats.requests == 0


def test_a_mesma_regra_em_duas_origens_vira_uma_proposta(origem: TrustedSource, tmp_path) -> None:
    """Repositórios de comunidade se copiam; a decisão continua sendo uma."""
    segunda = TrustedSource(
        slug="outro/espelho", ref="main", label="Espelho", rule_format=RuleFormat.SIGMA
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            return resposta_arvore(["rules/win_lsass_dump.yml"])
        return httpx.Response(200, text=SIGMA_YAML)

    cliente = github.GitHubClient(
        [origem, segunda],
        client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    cliente._cache_dir = tmp_path

    resultado = search.discover("dump de LSASS", [origem, segunda], cliente, llm=None)

    assert len(resultado.proposals) == 1
    assert resultado.proposals[0].source_slug == "exemplo/regras", "fica a primeira da lista"


# ---------------------------------------------------------------------------
# Estado das propostas
# ---------------------------------------------------------------------------


def test_estados_de_proposta_sao_os_tres_esperados() -> None:
    assert {status.value for status in proposals.ProposalStatus} == {
        "pending",
        "approved",
        "rejected",
    }


def test_aprovar_confere_o_modelo_de_embedding_antes_de_escrever() -> None:
    """Vetor de outro modelo não quebra a busca — só a faz errar em silêncio."""

    class ConexaoFalsa:
        """Responde o que `describe_corpus` pergunta, na ordem em que pergunta."""

        def __init__(self) -> None:
            self.respostas = [
                (True,),  # a tabela existe
                (1536,),  # dimensão da coluna
                (5664,),  # linhas
            ]
            self.linhas = [("text-embedding-3-small",)]

        def execute(self, *args, **kwargs):
            self.ultimo = args
            return self

        def fetchone(self):
            return self.respostas.pop(0) if self.respostas else None

        def fetchall(self):
            return self.linhas

    class EmbeddingIncompativel:
        name = "voyage"
        model = "voyage-3"
        dimensions = 1024

    from src.providers.base import ProviderError

    with pytest.raises(ProviderError) as erro:
        proposals.check_embedding_compatibility(ConexaoFalsa(), EmbeddingIncompativel())

    assert "1536" in str(erro.value) and "1024" in str(erro.value)


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

from pathlib import Path  # noqa: E402 - usado só pelos testes de interface abaixo

FRONTEND = Path(__file__).resolve().parents[1] / "src" / "frontend"


@pytest.fixture(scope="module")
def js() -> str:
    return (FRONTEND / "app.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def html() -> str:
    return (FRONTEND / "index.html").read_text(encoding="utf-8")


def test_a_interface_nao_tem_caminho_que_ache_e_indexe_junto(js: str) -> None:
    """A separação entre buscar e decidir é o desenho, não uma etapa faltando."""
    corpo_da_busca = js.split('fetch("/api/discovery/search"')[1].split("}\n")[0]
    assert "decide" not in corpo_da_busca


def test_a_chave_acompanha_a_aprovacao(js: str) -> None:
    """Aprovar embeda a regra: sem a chave de quem usa, indexar falharia."""
    trecho = js.split('fetch("/api/discovery/decide"')[1][:600]
    assert "cabecalhosDeChave()" in trecho


def test_a_proposta_mostra_de_onde_a_regra_veio(js: str) -> None:
    """Aprovar sem ver a procedência é confiar num texto que apareceu na tela."""
    assert "proposta__repo" in js
    assert "source_url" in js and "source_path" in js


def test_os_repositorios_tem_area_propria_no_menu(html: str) -> None:
    """Pedido de quem usa: listar e cadastrar repositórios fora da busca.

    A lista é o limite do que a descoberta enxerga — quem avalia a ferramenta
    precisa conseguir ver e mudar esse limite sem antes disparar uma busca.
    """
    assert 'data-vista="repositorios"' in html
    assert 'id="vistaRepositorios"' in html
    # A lista e o formulário moram lá, não mais dentro da vista de Ampliar.
    repositorios = html.split('id="vistaRepositorios"')[1]
    assert 'id="sourceList"' in repositorios
    assert 'id="sourceForm"' in repositorios


def test_ampliar_leva_para_os_repositorios(html: str) -> None:
    """Separar as duas áreas cobra um caminho entre elas: a busca depende da
    lista, e quem está buscando precisa alcançá-la sem procurar no menu."""
    ampliar = html.split('id="vistaAmpliar"')[1].split('id="vistaRepositorios"')[0]
    assert 'data-vista="repositorios"' in ampliar


def test_o_formulario_de_origem_le_os_formatos_do_servidor(js: str, html: str) -> None:
    """Uma lista de formatos escrita no JS divergiria do backend na primeira mudança."""
    assert 'id="sourceFormat"' in html
    assert "data.formats" in js
    # O container nasce vazio no HTML e é preenchido pela resposta da API — em
    # rádios visíveis, não num menu suspenso (ver `test_api.py`, mesma regra do
    # seletor de modelos: escolha escondida não comunica que existe escolha).
    assert '<div class="formatos" id="sourceFormat"></div>' in html
    assert 'type="radio" name="rule_format"' in js


def test_a_tela_diz_que_a_busca_e_restrita(html: str) -> None:
    """A restrição é a característica da ferramenta — precisa estar escrita.

    Nas duas áreas: em Ampliar, porque é onde a busca é disparada; e em
    Repositórios, porque é onde a lista é editada e onde alguém poderia supor
    que existe um campo para apontar a busca a um endereço qualquer.
    """
    lower = html.lower()
    assert "a busca só entra nos repositórios confiáveis cadastrados" in lower
    assert "não há campo para apontá-la a um endereço qualquer" in lower


def test_a_busca_para_no_orcamento_de_tempo(origem: TrustedSource, tmp_path) -> None:
    """Endpoint síncrono com alguém olhando: travar é pior que trazer menos.

    Com o teto zerado, a busca devolve o que tem e diz que parou — não levanta
    erro. Meia busca com procedência é útil; um erro depois de 90 s não é.
    """
    cliente = cliente_falso(
        origem,
        {
            "api.github.com/repos/exemplo/regras/git/trees/main": resposta_arvore(
                ["rules/win_lsass_dump.yml"]
            )
        },
    )
    cliente._cache_dir = tmp_path

    resultado = search.discover("dump de LSASS", [origem], cliente, llm=None, max_seconds=0)

    assert resultado.proposals == []
    assert any("parou" in aviso for aviso in resultado.warnings)
