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

import re
from pathlib import Path

import pytest

from src.api.schemas import AskRequest

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
    """Regressão de um defeito real desta fase.

    `.result` declara `display: grid`, que vence o `display: none` que o
    navegador aplica via `[hidden]`. Sem a regra explícita, a página abria
    mostrando um selo de ancoragem vazio.
    """
    assert re.search(r"\[hidden\]\s*\{\s*display:\s*none\s*!important", css)
    assert ".result {" in css and "display: grid" in css


def test_quality_floor_is_present(css: str) -> None:
    """Piso não negociável da skill de frontend-design."""
    assert ":focus-visible" in css, "sem foco de teclado visível"
    assert "prefers-reduced-motion" in css, "movimento não condicionado"
    assert "@media (max-width: 620px)" in css, "sem quebra para mobile"
    assert "prefers-color-scheme: dark" in css, "sem tema escuro"


def test_wide_content_scrolls_inside_its_own_box(css: str) -> None:
    """Query de detecção é larga; a página não pode rolar na horizontal."""
    assert css.count("overflow-x: auto") >= 2


def test_script_escapes_html_before_rendering(js: str) -> None:
    """O texto vem de um LLM e não é confiável por construção."""
    assert "function escapeHtml" in js
    assert "escapeHtml(source)" in js, "markdown renderizado sem escapar antes"


def test_palette_is_named_and_sized_as_planned(css: str) -> None:
    """Trava o plano de design: 6 cores nomeadas, não uma paleta improvisada."""
    for token in ("--papel", "--carta", "--tinta", "--grafite", "--verificado", "--ressalva"):
        assert f"{token}:" in css, f"cor {token} sumiu da paleta"


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
def test_ask_rejects_an_invalid_request(client) -> None:  # type: ignore[no-untyped-def]
    assert client.post("/api/ask", json={"question": ""}).status_code == 422
    assert client.post("/api/ask", json={"question": "ok", "top_k": 99}).status_code == 422


@pytest.mark.integration
def test_index_page_is_served(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/")
    assert response.status_code == 200
    assert "Mesa de refer" in response.text
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200
