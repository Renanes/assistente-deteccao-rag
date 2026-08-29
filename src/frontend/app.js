/* Assistente de detecção — comportamento da interface.

   Sem framework e sem dependência externa: a página é servida pela mesma
   aplicação FastAPI e precisa subir com um comando só. O renderizador de
   markdown é mínimo de propósito — cobre o que o modelo realmente produz
   (títulos, listas, ênfase, código) e escapa HTML antes de qualquer coisa,
   porque o texto vem de um LLM e não é confiável por construção.
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

const emPortugues = (n) => n.toLocaleString("pt-BR");

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

/* ------------------------------------------------- mapa do acervo (assinatura)

   Uma célula por regra indexada. A consulta acende as que responderam, o que
   torna visível a única coisa que o produto faz: estreitar o acervo inteiro
   até as poucas regras que sustentam a resposta.

   Canvas, e não 5.664 nós no DOM: o navegador não deveria carregar uma árvore
   desse tamanho por causa de um elemento gráfico. A posição de cada regra vem
   de um hash do `rule_uid`, então uma regra cai sempre na mesma célula entre
   consultas — a estabilidade é o que faz o mapa significar alguma coisa.
*/

const canvas = el("corpusCanvas");
const corpusLegend = el("corpusLegend");
const semMovimento = window.matchMedia("(prefers-reduced-motion: reduce)");

const LINHAS = 31; // mantém a faixa em ~6:1 com 5.664 células, em qualquer largura

let corpusTotal = 0;
let acesas = [];
let animacao = null;

function hashUid(uid) {
  // FNV-1a de 32 bits: barato, determinístico e bem espalhado. Não precisa ser
  // criptográfico — precisa ser estável.
  let hash = 0x811c9dc5;
  for (let i = 0; i < uid.length; i += 1) {
    hash ^= uid.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function desenharMapa(progresso = 1) {
  if (!corpusTotal || !canvas.isConnected) return;

  const dpr = window.devicePixelRatio || 1;
  const largura = canvas.clientWidth;
  if (!largura) return;

  const colunas = Math.ceil(corpusTotal / LINHAS);
  const passo = largura / colunas;
  const altura = Math.round(passo * LINHAS);

  canvas.width = Math.round(largura * dpr);
  canvas.height = Math.round(altura * dpr);
  canvas.style.height = `${altura}px`;

  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, largura, altura);

  const lado = Math.max(1, passo - Math.min(1.4, passo * 0.28));
  const apagado = acesas.length > 0;

  for (let i = 0; i < corpusTotal; i += 1) {
    const x = (i % colunas) * passo;
    const y = Math.floor(i / colunas) * passo;
    // Variação determinística: dá textura de acervo real em vez de um bloco
    // chapado, sem sugerir informação que não existe.
    const ruido = ((i * 2654435761) >>> 0) % 100;
    const alfa = (apagado ? 0.055 : 0.1) + (ruido / 100) * (apagado ? 0.05 : 0.11);
    ctx.fillStyle = `rgba(134, 166, 176, ${alfa})`;
    ctx.fillRect(x, y, lado, lado);
  }

  acesas.forEach((celula, ordem) => {
    // Acende em cascata: cada regra entra um pouco depois da anterior.
    const inicio = ordem / Math.max(acesas.length, 1);
    const local = Math.max(0, Math.min(1, (progresso - inicio * 0.55) / 0.45));
    if (local <= 0) return;

    const x = (celula % colunas) * passo;
    const y = Math.floor(celula / colunas) * passo;
    const cresce = lado + local * Math.max(1.6, passo * 0.9);
    const desloca = (cresce - lado) / 2;

    ctx.fillStyle = `rgba(217, 164, 65, ${0.28 * local})`;
    ctx.fillRect(x - desloca * 2.2, y - desloca * 2.2, cresce + desloca * 3.4, cresce + desloca * 3.4);
    ctx.fillStyle = `rgba(232, 183, 87, ${local})`;
    ctx.fillRect(x - desloca, y - desloca, cresce, cresce);
  });
}

function animarMapa() {
  if (animacao) cancelAnimationFrame(animacao);

  if (semMovimento.matches || !acesas.length) {
    desenharMapa(1);
    return;
  }

  const comeco = performance.now();
  const passo = (agora) => {
    const progresso = Math.min(1, (agora - comeco) / 620);
    desenharMapa(progresso);
    if (progresso < 1) animacao = requestAnimationFrame(passo);
  };
  animacao = requestAnimationFrame(passo);
}

function acenderRegras(rules) {
  if (!corpusTotal) return;
  const colunas = Math.ceil(corpusTotal / LINHAS);
  const total = colunas * LINHAS;
  acesas = rules.map((rule) => hashUid(rule.rule_uid) % total);

  corpusLegend.innerHTML =
    `<b>${emPortugues(rules.length)}</b> de ${emPortugues(corpusTotal)} regras acesas — ` +
    "as que a resposta teve à disposição.";
  canvas.setAttribute(
    "aria-label",
    `Mapa do acervo: ${rules.length} de ${corpusTotal} regras recuperadas para esta consulta.`
  );
  animarMapa();
}

function prepararMapa(total) {
  corpusTotal = total;
  corpusLegend.textContent =
    `${emPortugues(total)} regras indexadas. A consulta acende as que responderem.`;
  canvas.setAttribute("aria-label", `Mapa do acervo: ${total} regras indexadas.`);
  desenharMapa(1);
}

let redesenho = null;
window.addEventListener("resize", () => {
  clearTimeout(redesenho);
  redesenho = setTimeout(() => desenharMapa(1), 120);
});

/* --------------------------------------------------- seletor de modelo */

/* A escolha do modelo é de quem usa, não do `.env`: rodar a demonstração
   inteira no modelo mais caro do catálogo é a diferença entre centavos e
   dezenas de dólares.

   As opções são fichas de rádio à vista, e não um `<select>`. Um menu suspenso
   esconde as opções até alguém clicar nele, então a página não mostrava que
   havia escolha a fazer — foi reportado por quem usa, na primeira versão desta
   tela. O motivo do controle existir é comparar preço; esconder o preço anula
   o controle. */

const MODEL_KEY = "mesa.modelo";
const modelOptions = el("modelOptions");
const modelNote = el("modelNote");

let catalog = [];
let chosenModel = null;

/* O cabeçalho anuncia qual modelo responderá a próxima pergunta. Enquanto a
   escolha vinha só do `.env`, `/api/health` era a fonte certa; agora que ela é
   de quem usa, o seletor é que manda. A bandeira evita que a resposta de
   `/api/health`, que chega depois, sobrescreva a escolha. */
let generationStatOwned = false;

/* localStorage falha em aba privativa e com cookies bloqueados. Como isto é
   conveniência e não estado essencial, engolir a falha e seguir com o padrão
   do servidor é o comportamento correto. */
function readStored() {
  try {
    return localStorage.getItem(MODEL_KEY);
  } catch {
    return null;
  }
}

function storeChoice(id) {
  try {
    localStorage.setItem(MODEL_KEY, id);
  } catch {
    /* sem persistência: a escolha vale só para esta sessão */
  }
}

function describeModel(id) {
  const card = catalog.find((item) => item.id === id);
  if (!card) return;

  modelNote.textContent = card.available
    ? `${card.note} US$ ${card.price_in.toFixed(2)} entrada · US$ ${card.price_out.toFixed(2)} saída por 1M.`
    : `Indisponível: falta a chave de API do provedor ${card.provider} no .env.`;

  generationStatOwned = true;
  el("statLlm").textContent = `${card.provider}/${card.id}`;
}

function selectModel(id) {
  chosenModel = id;
  storeChoice(id);
  describeModel(id);
  for (const chip of modelOptions.querySelectorAll(".ficha-modelo")) {
    chip.classList.toggle("is-on", chip.dataset.model === id);
  }
}

function buildModelPicker(data) {
  catalog = data.models;
  modelOptions.innerHTML = "";

  const groups = new Map();
  for (const card of catalog) {
    if (!groups.has(card.provider)) {
      const group = document.createElement("div");
      group.className = "modelos__grupo";
      group.innerHTML = `<span class="modelos__marca">${escapeHtml(card.provider)}</span>`;
      groups.set(card.provider, group);
      modelOptions.appendChild(group);
    }

    // Rádio real dentro de um fieldset: navegação por setas, papel de grupo e
    // foco de teclado vêm do navegador, sem reimplementar nada disso à mão.
    const chip = document.createElement("label");
    chip.className = "ficha-modelo" + (card.available ? "" : " ficha-modelo--off");
    chip.dataset.model = card.id;
    chip.innerHTML = `
      <input type="radio" name="modelo" value="${escapeHtml(card.id)}"${
        card.available ? "" : " disabled"
      }>
      <span class="ficha-modelo__nome">${escapeHtml(card.label)}</span>
      <span class="ficha-modelo__preco">${
        card.available ? card.price_out.toFixed(2) : "sem chave"
      }</span>
    `;
    groups.get(card.provider).appendChild(chip);
  }

  const stored = readStored();
  const usable = catalog.filter((card) => card.available).map((card) => card.id);
  const chosen =
    (stored && usable.includes(stored) && stored) ||
    (usable.includes(data.default_model) && data.default_model) ||
    usable[0];

  if (!chosen) {
    modelNote.textContent =
      "Nenhum provedor de geração configurado. Preencha ANTHROPIC_API_KEY ou OPENAI_API_KEY no .env.";
    return;
  }

  const radio = modelOptions.querySelector(`input[value="${CSS.escape(chosen)}"]`);
  if (radio) radio.checked = true;
  selectModel(chosen);
}

modelOptions.addEventListener("change", (event) => {
  const radio = event.target.closest("input[name='modelo']");
  if (radio) selectModel(radio.value);
});

/* ------------------------------------------- índice de técnicas ATT&CK

   O catálogo responde a pergunta que o pipeline não respondia: *o que o acervo
   cobre?* Até aqui só dava para descobrir perguntando e vendo o que voltava.

   Duas decisões de comportamento:

   1. **Clicar arma um filtro, não dispara uma busca.** A página é dirigida por
      pergunta; a técnica é a restrição, não a consulta. Clicar em "Sem técnica
      declarada" sem pergunta nenhuma não teria o que responder.

   2. **O número exibido é sempre o que o filtro devolve**, já com a expansão
      pai↔subtécnica que o backend aplica — não o número de regras que declaram
      o ID. Mostrar "252" e devolver 375 ao clicar seria um número que mente, e
      é justamente por isso que a contagem vem do servidor, da mesma função que
      monta o WHERE. */

const catalogo = el("catalogo");
const catalogList = el("catalogList");
const catalogSearch = el("catalogSearch");
const catalogSummary = el("catalogSummary");
const catalogNote = el("catalogNote");
const catalogEmpty = el("catalogEmpty");
const activeFilters = el("activeFilters");
const activeFilterList = el("activeFilterList");

const tecnicasEscolhidas = new Set();
let semTecnicaEscolhida = false;
let rotuloSemTecnica = "Sem técnica declarada";
let contagemSemTecnica = 0;
/* Nome por ID, para o chip do filtro não repetir a varredura do DOM. */
const nomePorId = new Map();

function contaFiltros() {
  return tecnicasEscolhidas.size + (semTecnicaEscolhida ? 1 : 0);
}

function renderChips() {
  activeFilters.hidden = contaFiltros() === 0;
  activeFilterList.innerHTML = "";

  const itens = [...tecnicasEscolhidas].sort();
  if (semTecnicaEscolhida) itens.unshift("__sem__");

  for (const id of itens) {
    const li = document.createElement("li");
    const rotulo =
      id === "__sem__" ? rotuloSemTecnica : `${id}${nomePorId.get(id) ? ` · ${nomePorId.get(id)}` : ""}`;
    li.innerHTML = `
      <button type="button" class="chip" data-drop="${escapeHtml(id)}">
        <span>${escapeHtml(rotulo)}</span>
        <span class="chip__x" aria-hidden="true">×</span>
        <span class="visualmente-oculto">remover filtro</span>
      </button>`;
    activeFilterList.appendChild(li);
  }
}

function sincronizarBotoes() {
  for (const botao of catalogList.querySelectorAll("[data-pick]")) {
    const id = botao.dataset.pick;
    const ativo = id === "__sem__" ? semTecnicaEscolhida : tecnicasEscolhidas.has(id);
    botao.setAttribute("aria-pressed", String(ativo));
    botao.classList.toggle("is-on", ativo);
  }
  renderChips();
}

function alternarFiltro(id) {
  if (id === "__sem__") {
    semTecnicaEscolhida = !semTecnicaEscolhida;
  } else if (tecnicasEscolhidas.has(id)) {
    tecnicasEscolhidas.delete(id);
  } else {
    tecnicasEscolhidas.add(id);
  }
  sincronizarBotoes();
}

/* Uma linha de técnica: alvo clicável, contagem que o clique honra, e o estado
   no ATT&CK quando ele não é o normal. */
function linhaTecnica(item, ehSub) {
  const nome = item.name || "";
  if (nome) nomePorId.set(item.id, nome);

  const marcas = [];
  if (item.status === "revoked") {
    marcas.push(
      `<span class="tecnica__marca tecnica__marca--rev">revogada${
        item.superseded_by ? ` → ${escapeHtml(item.superseded_by)}` : ""
      }</span>`
    );
  } else if (item.status === "deprecated") {
    marcas.push('<span class="tecnica__marca">descontinuada</span>');
  } else if (item.status === "unknown") {
    marcas.push('<span class="tecnica__marca tecnica__marca--rev">fora do ATT&amp;CK</span>');
  }

  // A contagem própria só aparece quando difere da que o clique devolve —
  // repetir o mesmo número duas vezes seria ruído.
  const diretas =
    item.rule_count !== item.match_count
      ? `<span class="tecnica__diretas">${emPortugues(item.rule_count)} diretas</span>`
      : "";

  return `
    <button type="button" class="tecnica__pick${ehSub ? " tecnica__pick--sub" : ""}"
            data-pick="${escapeHtml(item.id)}" aria-pressed="false">
      <code class="tecnica__id">${escapeHtml(item.id)}</code>
      <span class="tecnica__nome">${escapeHtml(nome || "—")}</span>
      ${marcas.join("")}
    </button>
    <span class="tecnica__conta">${emPortugues(item.match_count)}</span>
    ${diretas}`;
}

function renderCatalogo(data) {
  rotuloSemTecnica = data.untagged_label;
  contagemSemTecnica = data.untagged_count;

  catalogSummary.textContent =
    `${emPortugues(data.distinct_techniques)} técnicas · ` +
    `${emPortugues(data.families.length)} famílias · ` +
    `${emPortugues(data.untagged_count)} regras sem técnica`;

  const pendencias = [];
  if (data.unknown_ids.length) {
    pendencias.push(`${data.unknown_ids.length} fora do ATT&CK (${data.unknown_ids.slice(0, 3).join(", ")})`);
  }
  if (data.revoked_ids.length) {
    pendencias.push(`${data.revoked_ids.length} revogadas`);
  }
  if (data.deprecated_ids.length) {
    pendencias.push(`${data.deprecated_ids.length} descontinuadas`);
  }

  catalogNote.innerHTML =
    `O número é quantas regras o filtro devolve, já com a expansão pai↔subtécnica — ` +
    `não quantas declaram o ID. Conferido contra o ATT&amp;CK v${escapeHtml(data.attack_version)}` +
    (pendencias.length ? `: ${escapeHtml(pendencias.join(" · "))}.` : ".");

  catalogList.innerHTML = "";

  // A faceta "Sem técnica" abre a lista, e não fica no fim como sobra: são
  // 458 regras que nenhum filtro por técnica alcança, e é a única forma de
  // pedi-las. Enterrá-la no rodapé anularia o motivo de ela existir.
  const semLi = document.createElement("li");
  semLi.className = "tecnica tecnica--sem";
  semLi.dataset.busca = "sem tecnica técnica declarada nenhuma";
  semLi.innerHTML = `
    <div class="tecnica__cabeca">
      <button type="button" class="tecnica__pick" data-pick="__sem__" aria-pressed="false">
        <code class="tecnica__id">—</code>
        <span class="tecnica__nome">${escapeHtml(data.untagged_label)}</span>
      </button>
      <span class="tecnica__conta">${emPortugues(data.untagged_count)}</span>
    </div>`;
  catalogList.appendChild(semLi);

  for (const familia of data.families) {
    const li = document.createElement("li");
    li.className = "tecnica";

    const textos = [familia.parent.id, familia.parent.name || ""];
    const subs = familia.subtechniques
      .map((sub) => {
        textos.push(sub.id, sub.name || "");
        return `<li class="tecnica__sub">${linhaTecnica(sub, true)}</li>`;
      })
      .join("");

    li.dataset.busca = textos.join(" ").toLowerCase();

    const expandir = familia.subtechniques.length
      ? `<button type="button" class="tecnica__mais" aria-expanded="false">
           ${familia.subtechniques.length} sub</button>`
      : "";
    // Família cujo pai ninguém declara existe só pelas subtécnicas. O filtro
    // por ele funciona (devolve a família inteira), mas dizer isso evita a
    // leitura errada de que há regras marcadas com o ID do pai.
    const soSubs = familia.parent_declared
      ? ""
      : '<span class="tecnica__marca">só via subtécnicas</span>';

    li.innerHTML = `
      <div class="tecnica__cabeca">
        ${linhaTecnica(familia.parent, false)}
        ${soSubs}
        ${expandir}
      </div>
      ${subs ? `<ul class="tecnica__subs" hidden>${subs}</ul>` : ""}`;
    catalogList.appendChild(li);
  }

  sincronizarBotoes();
}

catalogList.addEventListener("click", (event) => {
  const pick = event.target.closest("[data-pick]");
  if (pick) {
    alternarFiltro(pick.dataset.pick);
    return;
  }
  const mais = event.target.closest(".tecnica__mais");
  if (mais) {
    const subs = mais.closest(".tecnica").querySelector(".tecnica__subs");
    if (subs) {
      subs.hidden = !subs.hidden;
      mais.setAttribute("aria-expanded", String(!subs.hidden));
    }
  }
});

activeFilterList.addEventListener("click", (event) => {
  const chip = event.target.closest("[data-drop]");
  if (chip) alternarFiltro(chip.dataset.drop);
});

el("clearFilters").addEventListener("click", () => {
  tecnicasEscolhidas.clear();
  semTecnicaEscolhida = false;
  sincronizarBotoes();
});

catalogSearch.addEventListener("input", () => {
  const termo = catalogSearch.value.trim().toLowerCase();
  let visiveis = 0;

  for (const li of catalogList.children) {
    const casa = !termo || (li.dataset.busca || "").includes(termo);
    li.hidden = !casa;
    if (casa) visiveis += 1;

    // Se o termo casou uma subtécnica, abrir a família: deixar fechada
    // esconderia justamente a linha que o filtro encontrou.
    const subs = li.querySelector(".tecnica__subs");
    if (casa && termo && subs) {
      const dentro = [...subs.querySelectorAll("[data-pick]")].some((botao) =>
        botao.textContent.toLowerCase().includes(termo)
      );
      if (dentro) {
        subs.hidden = false;
        const mais = li.querySelector(".tecnica__mais");
        if (mais) mais.setAttribute("aria-expanded", "true");
      }
    }
  }

  catalogEmpty.hidden = visiveis > 0;
});

/* ------------------------------------------------------------- montagem */

function renderAfericao(data) {
  const seal = el("seal");
  const title = el("sealTitle");
  const detail = el("sealDetail");
  const grounding = data.grounding;

  if (data.answered_without_model) {
    seal.classList.add("afericao--rompida");
    title.textContent = "Sem material para citar";
    detail.textContent = "nenhuma regra recuperada — o modelo não foi consultado";
    return;
  }

  if (grounding.is_grounded) {
    seal.classList.remove("afericao--rompida");
    title.textContent = "Resposta ancorada";
    detail.textContent =
      `${grounding.cited.length} de ${data.rules.length} regras citadas · 0 citações inválidas`;
  } else {
    seal.classList.add("afericao--rompida");
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
    // A faceta "Sem técnica" não é um ID e precisa ser nomeada por extenso —
    // listar só `filtered_techniques` deixaria a frase falando de "o filtro
    // pedido" quando o filtro tinha nome.
    const partes = [...data.filtered_techniques];
    if (data.filtered_untagged) partes.push(rotuloSemTecnica.toLowerCase());
    const asked = partes.join(", ") || "o filtro pedido";
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

function renderFicha(rule) {
  const li = document.createElement("li");
  li.className = "ficha" + (rule.cited ? " is-cited" : "");
  li.id = `card-${rule.index}`;

  const tags = [`<span class="etiqueta">${escapeHtml(rule.source)}</span>`];
  for (const technique of rule.mitre_techniques.slice(0, 4)) {
    tags.push(`<span class="etiqueta etiqueta--attack">${escapeHtml(technique)}</span>`);
  }
  for (const platform of rule.platforms.slice(0, 3)) {
    tags.push(`<span class="etiqueta">${escapeHtml(platform)}</span>`);
  }
  if (rule.severity) {
    tags.push(`<span class="etiqueta">sev ${escapeHtml(rule.severity)}</span>`);
  }

  const similarity = rule.similarity === null ? null : rule.similarity;
  const meterWidth = similarity === null ? 0 : Math.max(0, Math.min(1, similarity)) * 100;
  const prov = [];
  if (similarity !== null) prov.push(`cos ${similarity.toFixed(3)}`);
  if (rule.matched_by.length) prov.push(rule.matched_by.join(" + "));

  const uidLine = rule.source_url
    ? `<a href="${escapeHtml(rule.source_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(rule.rule_uid)}</a>`
    : escapeHtml(rule.rule_uid);

  li.innerHTML = `
    <div class="ficha__topo">
      <span class="ficha__indice">[${rule.index}]</span>
      <h3 class="ficha__titulo">${escapeHtml(rule.title)}</h3>
    </div>
    <p class="ficha__uid">${uidLine}</p>
    <div class="etiquetas">${tags.join("")}</div>
    <div class="procedencia">
      <span>${escapeHtml(prov.join(" · ") || "recuperada")}</span>
      <span class="medidor-barra" aria-hidden="true"><span style="width:${meterWidth}%"></span></span>
    </div>
    <details class="ficha__logica">
      <summary>lógica de detecção (${escapeHtml(rule.query_language)})</summary>
      <pre><code>${escapeHtml(rule.query)}</code></pre>
      ${rule.query_truncated ? '<p class="ficha__corte">Query truncada — veja a regra completa na fonte.</p>' : ""}
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
  renderAfericao(data);
  renderNotices(data);

  el("answerMeta").textContent =
    `${data.llm_provider}/${data.llm_model} · ${data.elapsed_ms} ms` +
    (data.answer_truncated ? " · resposta cortada no limite de tokens" : "");

  const validIndexes = new Set(data.rules.map((rule) => rule.index));
  el("answerBody").innerHTML = linkCitations(renderMarkdown(data.answer), validIndexes);

  const cards = el("cards");
  cards.innerHTML = "";
  data.rules.forEach((rule) => cards.appendChild(renderFicha(rule)));

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

  acenderRegras(data.rules);
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
      // `model` só vai quando há escolha válida; sem ele o servidor usa o padrão.
      // Os filtros vão sempre: vazios, o servidor volta a deduzir a técnica do
      // texto da pergunta, que é o comportamento de antes do catálogo existir.
      body: JSON.stringify({
        question,
        top_k: 5,
        model: chosenModel,
        mitre_techniques: [...tecnicasEscolhidas],
        include_untagged: semTecnicaEscolhida,
      }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      // Mensagem específica: quem consulta precisa saber o que consertar.
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

/* -------------------------------------------------------------- arranque */

fetch("/api/models")
  .then((response) => (response.ok ? response.json() : Promise.reject(response)))
  .then(buildModelPicker)
  .catch(() => {
    modelOptions.innerHTML = "";
    modelNote.textContent = "Não deu para ler o catálogo de modelos — a resposta usará o padrão.";
  });

fetch("/api/techniques")
  .then((response) => (response.ok ? response.json() : Promise.reject(response)))
  .then(renderCatalogo)
  .catch(() => {
    catalogSummary.textContent = "indisponível";
    catalogNote.textContent =
      "O índice de técnicas não respondeu. Verifique se o Postgres está no ar e o corpus indexado.";
  });

fetch("/api/health")
  .then((response) => (response.ok ? response.json() : Promise.reject(response)))
  .then((health) => {
    el("statChunks").textContent = `${emPortugues(health.indexed_chunks)} regras`;
    el("statEmbedding").textContent = health.embedding_model;
    if (!generationStatOwned) {
      el("statLlm").textContent = `${health.llm_provider}/${health.llm_model}`;
    }
    prepararMapa(health.indexed_chunks);
  })
  .catch(() => {
    el("statChunks").textContent = "indisponível";
    corpusLegend.textContent =
      "O acervo não respondeu. Verifique se o Postgres está no ar e o corpus indexado.";
  });
