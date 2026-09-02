"""Testes da API e dos arquivos da interface (Fase 7).

O que é testado sem rede nem banco: a validação de entrada e a integridade dos
arquivos servidos. O caminho completo (`/api/ask`) exige Postgres, corpus
indexado e chave de LLM, e está marcado como integração.

O teste de integridade da interface existe por um motivo concreto: a página é
servida como arquivo estático, sem passo de build e sem compilador. Um `id`
renomeado no HTML e não no JS não quebra nada em tempo de importação — quebra
em silêncio, no navegador de quem for avaliar o projeto.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from src.api.schemas import AskRequest
from src.providers import CATALOG

FRONTEND = Path(__file__).resolve().parents[1] / "src" / "frontend"


# --------------------------------------------------------------------------
# Validação de entrada
# --------------------------------------------------------------------------


def test_ask_request_defaults() -> None:
    request = AskRequest(question="tem regra pra T1055?")
    assert request.top_k == 5


def test_ask_request_rejects_an_empty_question() -> None:
    with pytest.raises(ValueError):
        AskRequest(question="")


@pytest.mark.parametrize("top_k", [0, 21])
def test_ask_request_bounds_top_k(top_k: int) -> None:
    """Teto existe para uma requisição não conseguir montar um prompt gigante."""
    with pytest.raises(ValueError):
        AskRequest(question="pergunta", top_k=top_k)


def test_ask_request_rejects_an_overlong_question() -> None:
    with pytest.raises(ValueError):
        AskRequest(question="x" * 1001)


def test_ask_request_model_is_optional() -> None:
    """Sem escolha explícita a API usa o padrão do `.env` — o comportamento antigo."""
    assert AskRequest(question="pergunta").model is None
    assert AskRequest(question="pergunta", model="claude-haiku-4-5").model == "claude-haiku-4-5"


# --------------------------------------------------------------------------
# Integridade dos arquivos da interface
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def html() -> str:
    return (FRONTEND / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def js() -> str:
    return (FRONTEND / "app.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def css() -> str:
    return (FRONTEND / "styles.css").read_text(encoding="utf-8")


def test_frontend_files_exist() -> None:
    for name in ("index.html", "styles.css", "app.js"):
        assert (FRONTEND / name).is_file(), f"falta {name}"


def test_every_id_the_script_looks_up_exists_in_the_html(html: str, js: str) -> None:
    """Um `id` renomeado num arquivo e não no outro falha só no navegador."""
    referenced = set(re.findall(r'el\("([^"]+)"\)', js))
    present = set(re.findall(r'id="([^"]+)"', html))

    missing = sorted(referenced - present)
    assert not missing, f"app.js procura ids que o HTML não tem: {missing}"


def test_no_external_dependency_beyond_google_fonts(html: str) -> None:
    """A demo precisa subir com um comando, sem CDN de biblioteca."""
    external = re.findall(r'(?:src|href)="(https?://[^"]+)"', html)
    for url in external:
        assert "fonts.googleapis.com" in url or "fonts.gstatic.com" in url, (
            f"dependência externa inesperada: {url}"
        )
    assert "<script src=\"/static/app.js\"></script>" in html


def test_hidden_attribute_beats_author_display(css: str) -> None:
    """Regressão de um defeito real da Fase 7.

    `.resultado` declara `display: grid`, que vence o `display: none` que o
    navegador aplica via `[hidden]`. Sem a regra explícita, a página abria
    mostrando um selo de aferição vazio.
    """
    assert re.search(r"\[hidden\]\s*\{\s*display:\s*none\s*!important", css)
    assert ".resultado {" in css and "display: grid" in css


def test_quality_floor_is_present(css: str, html: str) -> None:
    """Piso não negociável da skill de frontend-design."""
    assert ":focus-visible" in css, "sem foco de teclado visível"
    assert "prefers-reduced-motion" in css, "movimento não condicionado"
    assert "@media (max-width: 620px)" in css, "sem quebra para mobile"
    # O tema escuro é assumido, não alternado (ver PROGRESS.md). Sem
    # `prefers-color-scheme`, o navegador precisa ser avisado — senão pinta os
    # controles nativos no esquema claro sobre um fundo escuro.
    assert 'name="color-scheme" content="dark"' in html, "tema não declarado ao navegador"
    assert "background: var(--petroleo)" in css, "o fundo precisa ser pintado explicitamente"


def test_wide_content_scrolls_inside_its_own_box(css: str) -> None:
    """Query de detecção é larga; a página não pode rolar na horizontal."""
    assert css.count("overflow-x: auto") >= 2


def test_script_escapes_html_before_rendering(js: str) -> None:
    """O texto vem de um LLM e não é confiável por construção."""
    assert "function escapeHtml" in js
    assert "escapeHtml(source)" in js, "markdown renderizado sem escapar antes"


def test_the_selector_reads_the_catalog_from_the_server(js: str) -> None:
    """A interface monta o seletor do catálogo da API, não de uma lista própria.

    Duplicar os ids no JS é exatamente como as duas listas passam a divergir: o
    seletor ofereceria um modelo que a API recusa, ou esconderia um que ela
    aceita. O teste trava a direção da dependência.
    """
    assert "/api/models" in js, "o seletor não lê o catálogo do servidor"
    for card in CATALOG:
        assert card.id not in js, (
            f"'{card.id}' está escrito no app.js — o catálogo deve vir só da API"
        )


def test_model_options_are_visible_without_interaction(html: str, js: str) -> None:
    """Regressão de um defeito real desta sessão.

    A primeira versão do seletor era um `<select>`. O usuário reportou não ter
    visto opção nenhuma para escolher o modelo — e estava certo: um menu
    suspenso esconde as opções até alguém clicar nele, então a página não
    mostrava que havia escolha a fazer. Um controle de escolha que só se revela
    sob clique não comunica que a escolha existe.
    """
    assert "<select" not in html, "as opções voltaram a ficar escondidas num <select>"
    assert 'type="radio"' in js, "as fichas de modelo deixaram de ser rádios"


# --------------------------------------------------------------------------
# Navegação em vistas
#
# A página deixou de ser uma pilha e virou áreas com um menu no cabeçalho.
# O risco de uma navegação feita em JS sobre HTML estático é o mesmo de sempre
# aqui: um `id` renomeado num lado e não no outro não quebra nada em tempo de
# importação — quebra em silêncio, no navegador de quem for avaliar.
# --------------------------------------------------------------------------


def test_cada_aba_aponta_para_uma_vista_que_existe(html: str) -> None:
    """`data-vista` é o contrato entre o menu e as seções; ele precisa fechar."""
    vistas = set(re.findall(r'data-vista="([^"]+)"', html))
    ids = set(re.findall(r'id="([^"]+)"', html))

    assert vistas, "nenhuma aba encontrada"
    for vista in vistas:
        esperado = f"vista{vista.capitalize()}"
        assert esperado in ids, f"a aba '{vista}' aponta para uma vista inexistente"


def test_o_menu_e_a_configuracao_dividem_a_mesma_faixa(html: str) -> None:
    """Pedido de quem usa: o menu ao lado da Configuração, não numa linha solta."""
    faixa = html.split('<div class="barra__interno">')[1].split("</header>")[0]
    assert 'id="abas"' in faixa
    assert 'id="configPanel"' in faixa


def test_abas_e_paineis_se_referenciam_nos_dois_sentidos(html: str) -> None:
    """`aria-controls` e `aria-labelledby` fechando é o que dá a navegação a quem
    usa leitor de tela — sem isso as abas são três botões sem relação com nada."""
    ids = set(re.findall(r'id="([^"]+)"', html))

    for controlado in re.findall(r'aria-controls="([^"]+)"', html):
        assert controlado in ids, f"aria-controls aponta para id inexistente: {controlado}"
    for rotulo in re.findall(r'aria-labelledby="([^"]+)"', html):
        assert rotulo in ids, f"aria-labelledby aponta para id inexistente: {rotulo}"


def test_so_uma_vista_abre_visivel(html: str) -> None:
    """Duas vistas visíveis é a pilha de volta; nenhuma é uma página em branco.

    A contagem é comparada com a de abas em vez de ser um número escrito aqui:
    o que precisa valer é que cada aba tenha uma vista, e acrescentar uma área
    não deve exigir editar este teste — só não deve deixar sobrar aba sem vista.
    """
    vistas = re.findall(r'<section class="vista"[^>]*>', html)
    abas = re.findall(r'role="tab"', html)
    assert len(vistas) == len(abas)

    visiveis = [vista for vista in vistas if "hidden" not in vista]
    assert len(visiveis) == 1 and "vistaConsultar" in visiveis[0]


def test_o_teclado_percorre_as_abas(js: str, html: str) -> None:
    """Roving tabindex e setas: sem isso o Tab atravessa o cabeçalho inteiro."""
    assert 'tabindex="-1"' in html, "as abas inativas precisam sair da ordem do Tab"
    assert "ArrowLeft" in js and "ArrowRight" in js


def test_o_mapa_e_redesenhado_ao_voltar_para_a_pergunta(js: str) -> None:
    """Regressão: canvas oculto tem largura zero, e `desenharMapa` desiste nesse
    caso. Sem redesenhar na troca, abrir a página em `#ampliar` e voltar deixava
    o elemento de assinatura em branco."""
    corpo = js.split("function mostrarVista")[1]
    trecho = corpo[: corpo.index("\nabas.addEventListener")]
    assert "desenharMapa" in trecho


def test_a_vista_vem_do_endereco(js: str) -> None:
    """Recarregar cai na mesma área, e o link leva alguém direto a ela."""
    assert "location.hash" in js
    assert "replaceState" in js, "atribuir hash empilharia histórico a cada clique"


def test_o_filtro_armado_aparece_na_aba_da_pergunta(js: str) -> None:
    """O filtro é armado numa vista e age noutra: sem selo e sem aviso, o clique
    não teria consequência visível."""
    assert "abaConsultarSelo" in js
    assert "armedNotice" in js and "armedText" in js


def test_palette_is_named_and_sized_as_planned(css: str) -> None:
    """Trava o plano de design: 6 cores nomeadas, não uma paleta improvisada."""
    for token in ("--petroleo", "--bancada", "--fresa", "--luz", "--vapor", "--latao"):
        assert f"{token}:" in css, f"cor {token} sumiu da paleta"


def test_type_roles_are_filled_by_distinct_families(css: str, html: str) -> None:
    """Três papéis tipográficos, e nenhum deles a escolha reflexa.

    A versão anterior usava Space Grotesk + IBM Plex, que é o par que qualquer
    projeto pega por padrão — parte do motivo de a tela ler como template.
    """
    for token in ("--display:", "--corpo:", "--mono:"):
        assert token in css, f"papel tipográfico {token} não definido"
    for family in ("Chakra+Petch", "Archivo", "JetBrains+Mono"):
        assert family in html, f"{family} não é carregada"


def test_corpus_map_is_drawn_from_the_real_corpus_size(js: str, html: str) -> None:
    """O elemento de assinatura precisa medir o acervo, não desenhar enfeite.

    O mapa só significa alguma coisa se cada célula for uma regra real e se a
    mesma regra cair sempre na mesma célula — daí o hash estável do `rule_uid`.
    """
    assert 'id="corpusCanvas"' in html
    assert "health.indexed_chunks" in js, "o mapa não lê o tamanho real do acervo"
    assert "hashUid" in js, "sem posição estável, a mesma regra pularia de célula"
    assert "prefers-reduced-motion" in js, "a cascata não respeita movimento reduzido"


def test_catalog_reads_counts_from_the_server_not_from_the_script(js: str) -> None:
    """O número exibido tem que ser o que o filtro devolve.

    `match_count` já vem do servidor com a expansão pai↔subtécnica aplicada.
    Se o JS passar a exibir `rule_count` como número principal, o catálogo
    anuncia "252" e o clique devolve 375 — sem erro nenhum, só um número errado.
    """
    assert "item.match_count" in js, "o catálogo não exibe a contagem do filtro"
    assert "renderCatalogo" in js and "/api/techniques" in js


def test_catalog_sends_the_chosen_filters_with_the_question(js: str) -> None:
    """Clicar no catálogo tem que chegar ao `/api/ask`."""
    assert "mitre_techniques: [...tecnicasEscolhidas]" in js
    assert "include_untagged: semTecnicaEscolhida" in js


def test_untagged_facet_is_visible_and_named(html: str, js: str) -> None:
    """A faceta das regras sem técnica é o motivo do catálogo existir.

    O rótulo vem do servidor (`untagged_label`), então a API e a interface não
    podem divergir no nome, e o sentinela `__sem__` nunca é um ID ATT&CK.
    """
    assert "data.untagged_label" in js
    assert '"__sem__"' in js
    assert 'id="activeFilters"' in html and 'id="catalogList"' in html


def test_catalog_does_not_hardcode_technique_ids(js: str, html: str) -> None:
    """A lista de técnicas é do acervo, não do código.

    Mesma direção de dependência já travada para o catálogo de modelos: se um
    ID aparecer escrito aqui, a interface passa a ofertar algo que o acervo
    pode não conter.
    """
    # Só o `app.js`: o HTML cita `T1055` legitimamente, como exemplo de
    # pergunta nos atalhos, e isso é copy e não catálogo.
    hardcoded = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", js)))
    assert not hardcoded, f"app.js tem ID ATT&CK hardcoded: {hardcoded}"


def test_settings_response_has_no_field_that_could_carry_a_key(js: str) -> None:
    """O contrato de `/api/settings` não pode ter onde caber uma chave.

    A tentação seria devolver os últimos caracteres "para conferir", e isso
    viraria vazamento parcial de credencial numa aplicação sem autenticação.
    O teste trava o formato: só booleano, nome de provedor e nome de cabeçalho.
    """
    from src.api.schemas import ProviderStatusOut, SettingsResponse

    assert set(ProviderStatusOut.model_fields) == {
        "provider",
        "configured_in_env",
        "roles",
        "header",
    }
    assert ProviderStatusOut.model_fields["configured_in_env"].annotation is bool
    proibidos = {"key", "api_key", "secret", "token", "value", "masked", "suffix"}
    assert not proibidos & set(SettingsResponse.model_fields)
    # E a interface não pode ler um campo desses nem que ele aparecesse.
    for nome in proibidos:
        assert f"data.{nome}" not in js


def test_the_key_never_leaves_the_browser_except_as_a_request_header(js: str) -> None:
    """A chave vai por cabeçalho em `/api/ask` e em lugar nenhum mais.

    Se aparecer um POST mandando a chave para o servidor guardar, o modelo de
    segurança escolhido foi desfeito — e o sintoma seria zero: continuaria
    funcionando, só que com o segredo em disco.
    """
    assert "cabecalhosDeChave()" in js
    assert "localStorage" in js and "KEY_PREFIX" in js
    # Nenhum corpo de requisição pode carregar a chave.
    assert "body: JSON.stringify" in js
    for suspeito in ("api_key:", "apiKey:", "key: chave", "chave: valor"):
        assert suspeito not in js, f"a chave parece ir num corpo de requisição: {suspeito}"


def test_the_key_field_is_masked_and_cleared_after_saving(html: str, js: str) -> None:
    """Piso de higiene do campo de senha."""
    assert 'type="password"' in js, "o campo da chave precisa ser mascarado"
    assert 'autocomplete="off"' in js
    # O valor sai do DOM assim que é guardado.
    assert "campo.value = \"\"" in js


def test_header_names_come_from_the_server_not_from_the_script(js: str) -> None:
    """Duas listas de cabeçalho divergiriam, e o sintoma seria mudo.

    A chave viajaria num cabeçalho que o backend ignora: "não funciona", sem
    erro nenhum. O JS lê `status.header` do `/api/settings`.
    """
    assert "status.header" in js
    for header in ("x-api-key-anthropic", "x-api-key-openai", "x-api-key-voyage"):
        assert header not in js, f"nome de cabeçalho hardcoded no app.js: {header}"


def test_settings_panel_ids_exist(html: str) -> None:
    for element_id in ("configPanel", "keyList", "configWarning", "configBadge"):
        assert f'id="{element_id}"' in html


# --------------------------------------------------------------------------
# Integração: exige banco indexado e chaves reais
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from src.api.main import app

    try:
        with TestClient(app) as test_client:
            response = test_client.get("/api/health")
            if response.status_code != 200:
                pytest.skip(f"ambiente indisponível: {response.text}")
            if response.json()["indexed_chunks"] == 0:
                pytest.skip("corpus não indexado")
            yield test_client
    except RuntimeError as error:  # provedor mal configurado no lifespan
        pytest.skip(f"provedores indisponíveis: {error}")


@pytest.mark.integration
def test_health_reports_the_running_configuration(client) -> None:  # type: ignore[no-untyped-def]
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["indexed_chunks"] > 0
    assert body["embedding_model"]
    assert body["llm_provider"] in {"anthropic", "openai"}


@pytest.mark.integration
def test_ask_returns_a_grounded_answer_with_citable_rules(client) -> None:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/ask", json={"question": "tem regra pra T1055 no Windows?", "top_k": 3}
    )
    assert response.status_code == 200
    body = response.json()

    assert body["answer"].strip()
    assert body["rules"], "nenhuma regra devolvida"
    assert body["grounding"]["is_grounded"], body["grounding"]
    assert body["grounding"]["invalid"] == []

    # O filtro ATT&CK precisa ter valido: toda regra devolvida cobre T1055.
    for rule in body["rules"]:
        assert any(t.startswith("T1055") for t in rule["mitre_techniques"]), rule["title"]
        assert rule["rule_uid"]
        assert rule["query"], "sem a lógica de detecção não há o que citar"

    # Os índices são 1..n e contíguos — o JS depende disso para casar `[n]`.
    assert [rule["index"] for rule in body["rules"]] == list(range(1, len(body["rules"]) + 1))


@pytest.mark.integration
def test_techniques_endpoint_inventories_the_real_corpus(client) -> None:  # type: ignore[no-untyped-def]
    body = client.get("/api/techniques").json()

    assert body["total_rules"] == body["tagged_count"] + body["untagged_count"]
    assert body["untagged_count"] > 0, "as regras sem técnica são a razão da faceta"
    assert body["untagged_label"]
    assert body["families"], "nenhuma família devolvida"
    assert body["attack_version"]

    # Nenhuma família pode ser vazia, e o total da família não pode ser menor
    # que a maior contagem dentro dela — seria rollup quebrado.
    for family in body["families"]:
        assert family["rule_count"] > 0
        assert family["rule_count"] >= family["parent"]["rule_count"]
        for sub in family["subtechniques"]:
            assert sub["is_subtechnique"] and sub["id"].startswith(family["parent"]["id"] + ".")


@pytest.mark.integration
def test_catalog_counts_match_what_the_filtered_search_returns(client) -> None:  # type: ignore[no-untyped-def]
    """A invariante do catálogo, conferida ponta a ponta contra o banco.

    O teste unitário prova o rollup; este prova que o rollup e o WHERE real do
    Postgres concordam. Confere a família mais volumosa e uma subtécnica dela,
    que é onde a expansão pai↔subtécnica tem efeito.
    """
    from src.embeddings import store
    from src.providers import get_settings
    from src.retrieval.search import TABLE_NAME, SearchFilters, _filter_sql

    body = client.get("/api/techniques").json()
    familia = body["families"][0]
    alvos = [familia["parent"]] + familia["subtechniques"][:3]

    with store.connect(get_settings().resolved_database_url()) as conn:
        for entry in alvos:
            where, params = _filter_sql(SearchFilters(mitre_techniques=(entry["id"],)))
            real = conn.execute(
                f"SELECT count(*) FROM {TABLE_NAME} WHERE {where}", params
            ).fetchone()[0]
            assert real == entry["match_count"], (
                f"{entry['id']}: catálogo diz {entry['match_count']}, filtro devolve {real}"
            )

        where, params = _filter_sql(SearchFilters(include_untagged=True))
        real = conn.execute(
            f"SELECT count(*) FROM {TABLE_NAME} WHERE {where}", params
        ).fetchone()[0]
        assert real == body["untagged_count"]


@pytest.mark.integration
def test_ask_honours_an_explicit_technique_filter(client) -> None:  # type: ignore[no-untyped-def]
    """Filtro escolhido no catálogo vence a técnica inferida da pergunta."""
    response = client.post(
        "/api/ask",
        json={
            "question": "quais regras existem aqui?",
            "top_k": 5,
            "mitre_techniques": ["T1003.001"],
        },
    )
    assert response.status_code == 200
    body = response.json()

    assert body["filtered_techniques"] == ["T1003.001"]
    assert not body["relaxed_filters"], "T1003.001 existe no acervo; não devia relaxar"
    for rule in body["rules"]:
        assert any(
            technique in ("T1003.001", "T1003") for technique in rule["mitre_techniques"]
        ), f"{rule['rule_uid']} escapou do filtro: {rule['mitre_techniques']}"


@pytest.mark.integration
def test_ask_with_the_untagged_facet_returns_only_untagged_rules(client) -> None:  # type: ignore[no-untyped-def]
    """A faceta é a única forma de alcançar as regras sem técnica."""
    response = client.post(
        "/api/ask",
        json={
            "question": "regras sobre acesso suspeito a contas",
            "top_k": 5,
            "include_untagged": True,
        },
    )
    assert response.status_code == 200
    body = response.json()

    assert body["filtered_untagged"] is True
    assert body["rules"], "a faceta devolveu vazio"
    for rule in body["rules"]:
        assert rule["mitre_techniques"] == [], (
            f"{rule['rule_uid']} tem técnica e não devia estar aqui"
        )


@pytest.mark.integration
def test_settings_endpoint_reports_state_without_any_key(client) -> None:  # type: ignore[no-untyped-def]
    """A resposta real, conferida contra as chaves reais do ambiente."""
    from src.providers import get_settings

    body = client.get("/api/settings").json()
    assert body["providers"], "nenhum provedor reportado"

    # Nenhum valor de chave pode aparecer em lugar nenhum da resposta.
    settings = get_settings()
    serializado = json.dumps(body)
    for chave in (
        settings.anthropic_api_key,
        settings.openai_api_key,
        settings.voyage_api_key,
    ):
        if chave:
            assert chave not in serializado
            assert chave[-6:] not in serializado, "sufixo da chave vazou"

    for provider in body["providers"]:
        assert isinstance(provider["configured_in_env"], bool)
        assert provider["roles"]


@pytest.mark.integration
def test_ask_rejects_a_malformed_visitor_key(client) -> None:  # type: ignore[no-untyped-def]
    """Chave com quebra de linha no meio é 400 com mensagem, não 500."""
    response = client.post(
        "/api/ask",
        json={"question": "teste", "top_k": 1},
        headers={"x-api-key-openai": "sk-proj-quebrada\naqui-no-meio-do-valor"},
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "openai" in detail.lower()
    assert "sk-proj-quebrada" not in detail, "a chave recusada voltou na resposta"


@pytest.mark.integration
def test_ask_rejects_an_invalid_request(client) -> None:  # type: ignore[no-untyped-def]
    assert client.post("/api/ask", json={"question": ""}).status_code == 422
    assert client.post("/api/ask", json={"question": "ok", "top_k": 99}).status_code == 422


@pytest.mark.integration
def test_models_endpoint_describes_the_whole_catalog(client) -> None:  # type: ignore[no-untyped-def]
    body = client.get("/api/models").json()

    assert {model["id"] for model in body["models"]} == {card.id for card in CATALOG}
    assert body["default_model"] in {card.id for card in CATALOG}
    # Exatamente um padrão, e ele tem que estar utilizável.
    defaults = [model for model in body["models"] if model["is_default"]]
    assert len(defaults) == 1 and defaults[0]["available"]

    for model in body["models"]:
        assert model["price_out"] > 0, model["id"]
        assert model["note"].strip()


@pytest.mark.integration
def test_ask_rejects_a_model_outside_the_catalog(client) -> None:  # type: ignore[no-untyped-def]
    """Pedido errado é 400, não 503: quem pediu é que corrige."""
    response = client.post(
        "/api/ask", json={"question": "tem regra pra T1055?", "model": "gpt-inventado"}
    )
    assert response.status_code == 400
    assert "catálogo" in response.json()["detail"]


@pytest.mark.integration
def test_html_and_static_revalidate_together(client) -> None:  # type: ignore[no-untyped-def]
    """Regressão de um defeito real, relatado por quem usa.

    O HTML era `no-cache` e os estáticos não. O navegador então aplicava
    frescor heurístico só no CSS e podia servir a folha antiga junto com o
    markup novo — nomes de classe velhos, página sem estilo. Os dois precisam
    revalidar, senão a incoerência volta na próxima mudança de interface.
    """
    for path in ("/", "/static/styles.css", "/static/app.js"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "no-cache" in response.headers.get("cache-control", ""), (
            f"{path} pode ser servido de cache sem revalidar"
        )


@pytest.mark.integration
def test_index_page_is_served(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/")
    assert response.status_code == 200
    assert "Assistente de detec" in response.text
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200
