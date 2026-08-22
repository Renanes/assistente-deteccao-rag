/* Mesa de referência — comportamento da interface.

   Sem framework e sem dependência externa: a página é servida pela mesma
   aplicação FastAPI e precisa subir com um comando só. O renderizador de
   markdown abaixo é mínimo de propósito — cobre o que o modelo realmente
   produz (títulos, listas, ênfase, código) e escapa HTML antes de qualquer
   coisa, porque o texto vem de um LLM e não é confiável por construção.
*/

"use strict";

const el = (id) => document.getElementById(id);

const form = el("askForm");
const input = el("question");
const submit = el("askSubmit");

const stateIdle = el("stateIdle");
const stateBusy = el("stateBusy");
const stateError = el("stateError");
const result = el("result");

/* ------------------------------------------------------------ utilidades */

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* Marcadores de citação viram botões que acendem a ficha correspondente.
   `validIndexes` decide a aparência: um índice que não existe no contexto é
   mostrado como quebrado em vez de virar link para lugar nenhum. */
function linkCitations(html, validIndexes) {
  return html.replace(/\[(\d+)\]/g, (match, digits) => {
    const index = Number(digits);
    if (validIndexes.has(index)) {
      return `<button type="button" class="cite" data-cite="${index}">[${index}]</button>`;
    }
    return `<span class="cite cite--invalid" title="Esta citação não corresponde a nenhuma regra recuperada">[${index}]</span>`;
  });
}

function renderInline(text) {
  return text
    .replace(/`([^`]+)`/g, (_, code) => `<code>${code}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])\*([^*\n]+)\*/g, "$1<em>$2</em>");
}

/* Markdown mínimo: blocos de código cercados, títulos, listas e parágrafos. */
function renderMarkdown(source) {
  const lines = escapeHtml(source).split("\n");
  const out = [];
  let inCode = false;
  let codeBuffer = [];
  let listType = null;
  let paragraph = [];

  const flushParagraph = () => {
    if (paragraph.length) {
      out.push(`<p>${renderInline(paragraph.join(" "))}</p>`);
      paragraph = [];
    }
  };
  const closeList = () => {
    if (listType) {
      out.push(`</${listType}>`);
      listType = null;
    }
  };

  for (const line of lines) {
    if (/^\s*```/.test(line)) {
      if (inCode) {
        out.push(`<pre><code>${codeBuffer.join("\n")}</code></pre>`);
        codeBuffer = [];
        inCode = false;
      } else {
        flushParagraph();
        closeList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeBuffer.push(line);
      continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      flushParagraph();
      closeList();
      const level = Math.min(heading[1].length + 1, 4);
      out.push(`<h${level}>${renderInline(heading[2])}</h${level}>`);
      continue;
    }

    const bullet = line.match(/^\s*[-*+]\s+(.*)$/);
    const numbered = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (bullet || numbered) {
      flushParagraph();
      const wanted = bullet ? "ul" : "ol";
      if (listType !== wanted) {
        closeList();
        out.push(`<${wanted}>`);
        listType = wanted;
      }
      out.push(`<li>${renderInline((bullet || numbered)[1])}</li>`);
      continue;
    }

    if (!line.trim()) {
      flushParagraph();
      closeList();
      continue;
    }
    paragraph.push(line.trim());
  }

  if (inCode && codeBuffer.length) {
    out.push(`<pre><code>${codeBuffer.join("\n")}</code></pre>`);
  }
  flushParagraph();
  closeList();
  return out.join("\n");
}

/* ------------------------------------------------------------ montagem */

function renderSeal(data) {
  const seal = el("seal");
  const title = el("sealTitle");
  const detail = el("sealDetail");
  const grounding = data.grounding;

  if (data.answered_without_model) {
    seal.classList.add("seal--broken");
    title.textContent = "Sem material para citar";
    detail.textContent = "nenhuma regra recuperada — o modelo não foi consultado";
    return;
  }

  if (grounding.is_grounded) {
    seal.classList.remove("seal--broken");
    title.textContent = "Resposta ancorada";
    detail.textContent =
      `${grounding.cited.length} de ${data.rules.length} regras citadas · ` +
      "0 citações inválidas";
  } else {
    seal.classList.add("seal--broken");
    title.textContent = grounding.uncited ? "Resposta sem citação" : "Citação não confere";
    detail.textContent = grounding.uncited
      ? "nenhuma regra recuperada foi citada no texto"
      : `${grounding.invalid.length} citação(ões) fora do contexto fornecido`;
  }
}

function renderNotices(data) {
  const relaxed = el("noticeRelaxed");
  relaxed.hidden = !data.relaxed_filters;
  if (data.relaxed_filters) {
    const asked = data.filtered_techniques.join(", ") || "o filtro pedido";
    el("noticeRelaxedDetail").textContent =
      `Nenhuma regra do acervo cobre ${asked}. As regras abaixo vieram de uma ` +
      "busca sem esse filtro e são apenas relacionadas.";
  }

  const invalid = el("noticeInvalid");
  const hasInvalid = data.grounding.invalid.length > 0;
  invalid.hidden = !hasInvalid;
  if (hasInvalid) {
    el("noticeInvalidDetail").textContent =
      `A resposta citou ${data.grounding.invalid.map((n) => `[${n}]`).join(", ")}, ` +
      "que não corresponde a nenhuma regra recuperada. Marcado no texto.";
  }
}

function renderCard(rule) {
  const li = document.createElement("li");
  li.className = "card" + (rule.cited ? " is-cited" : "");
  li.id = `card-${rule.index}`;

  const tags = [];
  tags.push(`<span class="tag">${escapeHtml(rule.source)}</span>`);
  for (const technique of rule.mitre_techniques.slice(0, 4)) {
    tags.push(`<span class="tag tag--attack">${escapeHtml(technique)}</span>`);
  }
  for (const platform of rule.platforms.slice(0, 3)) {
    tags.push(`<span class="tag">${escapeHtml(platform)}</span>`);
  }
  if (rule.severity) {
    tags.push(`<span class="tag">sev: ${escapeHtml(rule.severity)}</span>`);
  }

  const similarity = rule.similarity === null ? null : rule.similarity;
  const meterWidth = similarity === null ? 0 : Math.max(0, Math.min(1, similarity)) * 100;
  const provParts = [];
  if (similarity !== null) {
    provParts.push(`cosseno ${similarity.toFixed(3)}`);
  }
  if (rule.matched_by.length) {
    provParts.push(rule.matched_by.join(" + "));
  }

  const uidLine = rule.source_url
    ? `<a href="${escapeHtml(rule.source_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(rule.rule_uid)}</a>`
    : escapeHtml(rule.rule_uid);

  li.innerHTML = `
    <div class="card__top">
      <span class="card__index">${rule.index}</span>
      <h3 class="card__title">${escapeHtml(rule.title)}</h3>
    </div>
    <p class="card__uid">${uidLine}</p>
    <div class="tags">${tags.join("")}</div>
    <div class="prov">
      <span>${escapeHtml(provParts.join(" · ") || "recuperada")}</span>
      <span class="prov__meter" aria-hidden="true"><span style="width:${meterWidth}%"></span></span>
    </div>
    <details class="card__logic">
      <summary>lógica de detecção (${escapeHtml(rule.query_language)})</summary>
      <pre><code>${escapeHtml(rule.query)}</code></pre>
      ${rule.query_truncated ? '<p class="card__cut">Query truncada — veja a regra completa na fonte.</p>' : ""}
    </details>
  `;
  return li;
}

function highlight(index, on) {
  const card = el(`card-${index}`);
  if (card) card.classList.toggle("is-active", on);
  document
    .querySelectorAll(`.cite[data-cite="${index}"]`)
    .forEach((node) => node.classList.toggle("is-active", on));
}

function render(data) {
  renderSeal(data);
  renderNotices(data);

  el("answerMeta").textContent =
    `${data.llm_provider}/${data.llm_model} · ${data.elapsed_ms} ms` +
    (data.answer_truncated ? " · resposta cortada no limite de tokens" : "");

  const validIndexes = new Set(data.rules.map((rule) => rule.index));
  el("answerBody").innerHTML = linkCitations(renderMarkdown(data.answer), validIndexes);

  const cards = el("cards");
  cards.innerHTML = "";
  data.rules.forEach((rule) => cards.appendChild(renderCard(rule)));

  const citedCount = data.rules.filter((rule) => rule.cited).length;
  el("evidenceCount").textContent = `${citedCount}/${data.rules.length} citadas`;

  document.querySelectorAll(".cite[data-cite]").forEach((node) => {
    const index = Number(node.dataset.cite);
    node.addEventListener("click", () => {
      const card = el(`card-${index}`);
      if (card) card.scrollIntoView({ behavior: "smooth", block: "center" });
    });
    node.addEventListener("mouseenter", () => highlight(index, true));
    node.addEventListener("mouseleave", () => highlight(index, false));
    node.addEventListener("focus", () => highlight(index, true));
    node.addEventListener("blur", () => highlight(index, false));
  });
}

/* ------------------------------------------------------------ requisição */

function setState(name, detail) {
  stateIdle.hidden = name !== "idle";
  stateBusy.hidden = name !== "busy";
  stateError.hidden = name !== "error";
  result.hidden = name !== "result";
  submit.disabled = name === "busy";
  submit.textContent = name === "busy" ? "Consultando…" : "Consultar";
  if (name === "error") el("errorDetail").textContent = detail;
}

async function ask(question) {
  setState("busy");
  try {
    const response = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, top_k: 5 }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      // Mensagem de erro específica: o analista precisa saber o que consertar.
      throw new Error(body.detail || `a API respondeu ${response.status}`);
    }
    render(await response.json());
    setState("result");
  } catch (error) {
    setState("error", `${error.message}. Verifique se o Postgres está no ar e o corpus indexado.`);
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const question = input.value.trim();
  if (question) ask(question);
});

el("examples").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-q]");
  if (!button) return;
  input.value = button.dataset.q;
  ask(button.dataset.q);
});

/* Cabeçalho: o que o acervo tem, lido do próprio serviço. */
fetch("/api/health")
  .then((response) => (response.ok ? response.json() : Promise.reject(response)))
  .then((health) => {
    el("statChunks").textContent = `${health.indexed_chunks.toLocaleString("pt-BR")} regras`;
    el("statEmbedding").textContent = health.embedding_model;
    el("statLlm").textContent = `${health.llm_provider}/${health.llm_model}`;
  })
  .catch(() => {
    el("statChunks").textContent = "indisponível";
  });
