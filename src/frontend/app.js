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

/* --------------------------------------------------------------- vistas

   Quatro áreas, um menu no cabeçalho. A troca é de vista, não de documento:
   nada é rebuscado no servidor ao mudar de aba, e o estado de cada área
   (filtros armados, propostas pendentes, resposta na tela) sobrevive à
   troca — voltar para a pergunta não custa refazer a consulta.

   Duas decisões de comportamento:

   1. **O endereço acompanha a vista** (`#tecnicas`). Recarregar a página cai
      na mesma área, e o link pode ser mandado para alguém. `replaceState` em
      vez de atribuir `location.hash` porque a segunda forma empilha entrada
      no histórico a cada clique — o botão "voltar" do navegador viraria um
      desfazer de abas, que não é o que ninguém espera dele.

   2. **O que acontece numa vista aparece nas outras.** Armar um filtro em
      Técnicas age no campo de pergunta, que está noutra área; sem um selo na
      aba e um aviso com o caminho de volta, o clique não teria consequência
      visível. É o custo de separar as áreas, e é ele que precisa ser pago
      aqui. */

const abas = el("abas");
const armedNotice = el("armedNotice");
const armedText = el("armedText");

const VISTAS = {
  consultar: "vistaConsultar",
  tecnicas: "vistaTecnicas",
  ampliar: "vistaAmpliar",
  repositorios: "vistaRepositorios",
};

let vistaAtual = "consultar";

function mostrarVista(nome, { foco = false } = {}) {
  const alvo = VISTAS[nome] ? nome : "consultar";
  vistaAtual = alvo;

  for (const [chave, id] of Object.entries(VISTAS)) {
    el(id).hidden = chave !== alvo;
  }

  for (const aba of abas.querySelectorAll(".aba")) {
    const ativa = aba.dataset.vista === alvo;
    aba.classList.toggle("is-on", ativa);
    aba.setAttribute("aria-selected", String(ativa));
    // Roving tabindex: o Tab entra e sai do menu por um ponto só, e as setas
    // percorrem as abas. É o padrão de tablist, e sem ele o teclado precisa
    // de três Tabs para atravessar o cabeçalho.
    aba.tabIndex = ativa ? 0 : -1;
    if (ativa && foco) aba.focus();
  }

  if (location.hash.slice(1) !== alvo) {
    history.replaceState(null, "", `#${alvo}`);
  }

  // O canvas não tem largura enquanto a vista está oculta, e `desenharMapa`
  // desiste nesse caso. Redesenhar ao voltar é o que faz o mapa existir mesmo
  // quando a página abriu direto em outra área (`#ampliar`, por exemplo).
  if (alvo === "consultar") desenharMapa(1);
}

abas.addEventListener("keydown", (event) => {
  const passo = { ArrowLeft: -1, ArrowRight: 1 }[event.key];
  const nomes = Object.keys(VISTAS);
  let destino = null;

  if (passo !== undefined) {
    destino = nomes[(nomes.indexOf(vistaAtual) + passo + nomes.length) % nomes.length];
  } else if (event.key === "Home") {
    destino = nomes[0];
  } else if (event.key === "End") {
    destino = nomes[nomes.length - 1];
  }

  if (destino) {
    event.preventDefault();
    mostrarVista(destino, { foco: true });
  }
});

/* Qualquer `[data-vista]` leva à área correspondente — as abas e também o
   "Ir para a pergunta" que fecha o ciclo do filtro armado. */
document.addEventListener("click", (event) => {
  const gatilho = event.target.closest("[data-vista]");
  if (gatilho) mostrarVista(gatilho.dataset.vista);
});

window.addEventListener("hashchange", () => mostrarVista(location.hash.slice(1)));

/* Um selo na aba: o número que a área tem para você agora. Escondido quando é
   zero — um "0" permanente é ruído, não informação. */
function marcarAba(id, texto) {
  const selo = el(id);
  selo.textContent = texto || "";
  selo.hidden = !texto;
}

/* O aviso dentro de Técnicas, com o caminho de volta. Sem ele, clicar numa
   técnica aqui não teria efeito visível: o filtro age no campo de pergunta,
   que está em outra vista. */
function renderArmado() {
  const quantos = contaFiltros();
  armedNotice.hidden = quantos === 0;
  armedText.textContent =
    quantos === 1
      ? "1 filtro armado. Ele restringe a próxima pergunta."
      : `${quantos} filtros armados. Eles restringem a próxima pergunta.`;
  marcarAba("abaConsultarSelo", quantos ? `${quantos} filtro${quantos > 1 ? "s" : ""}` : "");
}

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

  modelNote.textContent = modeloUsavel(card)
    ? `${card.note} US$ ${card.price_in.toFixed(2)} entrada · US$ ${card.price_out.toFixed(2)} saída por 1M.`
    : `Indisponível: falta a chave de ${card.provider}. Informe em Configuração, ` +
      "ou preencha no .env do servidor.";

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

/* Um modelo é usável se há chave para o provedor dele — do `.env` do servidor
   ou trazida por quem usa. `card.available` sozinho só conhece o `.env`, então
   sem isto uma chave colada na Configuração não destravaria o modelo. */
function modeloUsavel(card) {
  return card.available || Boolean(lerChave(card.provider));
}

function renderModelAvailability() {
  for (const chip of modelOptions.querySelectorAll(".ficha-modelo")) {
    const card = catalog.find((item) => item.id === chip.dataset.model);
    if (!card) continue;

    const usavel = modeloUsavel(card);
    chip.classList.toggle("ficha-modelo--off", !usavel);
    chip.querySelector("input").disabled = !usavel;

    const preco = chip.querySelector(".ficha-modelo__preco");
    preco.textContent = usavel ? preco.dataset.price : "sem chave";
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
    chip.className = "ficha-modelo";
    chip.dataset.model = card.id;
    chip.dataset.provider = card.provider;
    chip.innerHTML = `
      <input type="radio" name="modelo" value="${escapeHtml(card.id)}">
      <span class="ficha-modelo__nome">${escapeHtml(card.label)}</span>
      <span class="ficha-modelo__preco" data-price="${card.price_out.toFixed(2)}"></span>
    `;
    groups.get(card.provider).appendChild(chip);
  }

  renderModelAvailability();

  const stored = readStored();
  const usable = catalog.filter((card) => modeloUsavel(card)).map((card) => card.id);
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

/* ----------------------------------------------------- chaves de API

   A chave vive só aqui, no navegador de quem usa, e viaja num cabeçalho por
   requisição. Nunca vai para o `.env`, nunca é gravada no servidor e nenhum
   endpoint a devolve — `/api/settings` responde com booleanos, não com valores.

   O motivo é que a aplicação não tem autenticação (fora do escopo da v1 pelo
   `CLAUDE.md`). Um endpoint que gravasse a chave no servidor deixaria qualquer
   um que alcance a porta trocar a chave do operador e gastar o dinheiro dele.
   Assim, hospedar a demo publicamente continua seguro: cada visitante traz e
   paga a própria chave.

   O que isto NÃO resolve, e a interface diz por extenso: `localStorage` é
   legível por qualquer script desta página. É conveniência de demonstração,
   não cofre. */

const KEY_PREFIX = "mesa.chave.";
const configPanel = el("configPanel");
const configBadge = el("configBadge");
const configWarning = el("configWarning");
const keyList = el("keyList");

let providerStatus = [];
let corpusEmbeddingModel = "";

function lerChave(provider) {
  try {
    return localStorage.getItem(KEY_PREFIX + provider) || "";
  } catch {
    return "";
  }
}

function gravarChave(provider, valor) {
  try {
    if (valor) localStorage.setItem(KEY_PREFIX + provider, valor);
    else localStorage.removeItem(KEY_PREFIX + provider);
    return true;
  } catch {
    return false;
  }
}

/* Mostra as pontas da chave já guardada, como um painel de faturamento
   mostra ("sk-ant-…f8a2") — o bastante para reconhecer qual chave é sem
   expor o suficiente para reconstruí-la olhando por cima do ombro. Isto não
   é uma chamada ao servidor: a chave já está no localStorage deste
   navegador, então mascarar aqui não abre nenhuma superfície nova — é o
   mesmo dado que `lerChave` já lê para montar o cabeçalho da pergunta. */
function mascararChave(valor) {
  const limpa = valor.trim();
  // 6 do início + 4 do fim: abaixo de 11 caracteres as duas fatias se tocam
  // ou se sobrepõem e "mascarar" mostraria a chave inteira, char por char.
  if (limpa.length <= 10) return "•".repeat(limpa.length);
  return `${limpa.slice(0, 6)}…${limpa.slice(-4)}`;
}

/* Os cabeçalhos que acompanham cada pergunta. O nome de cada um vem do
   servidor (`/api/settings`), e não escrito aqui: duas listas divergiriam na
   primeira mudança, e o sintoma seria a chave viajar num cabeçalho que o
   backend ignora — ou seja, "minha chave não funciona" sem nenhum erro. */
function cabecalhosDeChave() {
  const headers = {};
  for (const status of providerStatus) {
    const chave = lerChave(status.provider);
    if (chave) headers[status.header] = chave;
  }
  return headers;
}

function temChaveUtil(provider) {
  const status = providerStatus.find((item) => item.provider === provider);
  return Boolean(lerChave(provider)) || Boolean(status && status.configured_in_env);
}

/* Um provedor cobre a etapa de embedding? É a checagem que evita o modo de
   falha mais confuso: a pergunta vira vetor ANTES de virar resposta, então
   quem trouxe só chave da Anthropic não consegue nem consultar. */
function embeddingCoberto() {
  return providerStatus.some(
    (status) => status.roles.includes("embedding") && temChaveUtil(status.provider)
  );
}

function geracaoCoberta() {
  return providerStatus.some(
    (status) => status.roles.includes("geração") && temChaveUtil(status.provider)
  );
}

function renderAvisosDeChave() {
  const faltas = [];
  if (!embeddingCoberto()) {
    faltas.push(
      "<strong>Falta chave de embedding.</strong> A pergunta precisa virar vetor " +
        "antes de virar resposta, então sem ela nenhuma consulta roda — nem com " +
        "chave de geração configurada. Serve OpenAI ou Voyage."
    );
  }
  if (!geracaoCoberta()) {
    faltas.push(
      "<strong>Falta chave de geração.</strong> A busca funciona, mas não há " +
        "quem redija a resposta. Serve Anthropic ou OpenAI."
    );
  }
  // O acervo foi indexado com um modelo específico, e vetores de modelos
  // diferentes não são comparáveis: o sintoma seria resultado ruim, não erro.
  if (corpusEmbeddingModel && embeddingCoberto()) {
    const status = providerStatus.find(
      (item) => item.roles.includes("embedding") && temChaveUtil(item.provider)
    );
    if (status && status.provider === "voyage" && corpusEmbeddingModel.startsWith("text-embedding")) {
      faltas.push(
        `<strong>Modelo de embedding incompatível com o acervo.</strong> O corpus ` +
          `foi indexado com <code>${escapeHtml(corpusEmbeddingModel)}</code>. Usar a ` +
          "Voyage exige reindexar (<code>python -m src.embeddings.run --reset</code>), " +
          "senão a busca compara vetores de modelos diferentes e devolve regra errada."
      );
    }
  }

  configWarning.hidden = faltas.length === 0;
  configWarning.innerHTML = faltas.map((texto) => `<p>${texto}</p>`).join("");

  const pendentes = (!embeddingCoberto() ? 1 : 0) + (!geracaoCoberta() ? 1 : 0);
  configBadge.textContent = pendentes ? `${pendentes} pendente${pendentes > 1 ? "s" : ""}` : "";
  configBadge.classList.toggle("config__selo--alerta", pendentes > 0);
}

function renderChaves() {
  keyList.innerHTML = "";

  for (const status of providerStatus) {
    const valorGuardado = lerChave(status.provider);
    const guardada = Boolean(valorGuardado);
    const li = document.createElement("li");
    li.className = "chave" + (guardada ? " chave--on" : "");

    const origem = guardada
      ? '<span class="chave__origem chave__origem--local">neste navegador</span>'
      : status.configured_in_env
        ? '<span class="chave__origem">vem do .env do servidor</span>'
        : '<span class="chave__origem chave__origem--falta">não configurada</span>';

    const preview = guardada
      ? `<p class="chave__preview" title="Só as pontas aparecem — o resto não sai do localStorage deste navegador.">${escapeHtml(mascararChave(valorGuardado))}</p>`
      : "";

    li.innerHTML = `
      <div class="chave__cabeca">
        <span class="chave__nome">${escapeHtml(status.provider)}</span>
        <span class="chave__papeis">${escapeHtml(status.roles.join(" · "))}</span>
        ${origem}
      </div>
      ${preview}
      <div class="chave__acao">
        <label class="visualmente-oculto" for="key-${escapeHtml(status.provider)}">
          Chave de API de ${escapeHtml(status.provider)}
        </label>
        <input type="password" id="key-${escapeHtml(status.provider)}"
               class="chave__campo" autocomplete="off" spellcheck="false"
               placeholder="${guardada ? "colar para trocar" : "colar a chave"}"
               data-input="${escapeHtml(status.provider)}">
        <button type="button" class="chave__salvar" data-save="${escapeHtml(status.provider)}">
          ${guardada ? "trocar" : "salvar"}
        </button>
        <button type="button" class="chave__remover" data-drop-key="${escapeHtml(status.provider)}"
                ${guardada ? "" : "disabled"}>remover</button>
      </div>
      <p class="chave__erro" data-error="${escapeHtml(status.provider)}" hidden></p>`;
    keyList.appendChild(li);
  }

  renderAvisosDeChave();
  // A disponibilidade do seletor de modelos muda com a chave nova.
  if (catalog.length) renderModelAvailability();
}

keyList.addEventListener("click", (event) => {
  const salvar = event.target.closest("[data-save]");
  const remover = event.target.closest("[data-drop-key]");
  if (!salvar && !remover) return;

  const provider = (salvar || remover).dataset.save || (salvar || remover).dataset.dropKey;
  const erro = keyList.querySelector(`[data-error="${CSS.escape(provider)}"]`);
  erro.hidden = true;

  if (remover) {
    gravarChave(provider, "");
    renderChaves();
    return;
  }

  const campo = keyList.querySelector(`[data-input="${CSS.escape(provider)}"]`);
  const valor = campo.value.trim();
  if (!valor) {
    erro.textContent = "Cole a chave antes de salvar.";
    erro.hidden = false;
    return;
  }
  if (!gravarChave(provider, valor)) {
    erro.textContent =
      "Este navegador não permite armazenamento local (aba privativa?). " +
      "A chave não pôde ser guardada.";
    erro.hidden = false;
    return;
  }
  // O valor sai do DOM assim que é guardado: não há motivo para ele continuar
  // legível num campo da página depois de salvo.
  campo.value = "";
  renderChaves();
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
  renderArmado();
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
  // A mesma contagem na aba: quem está noutra área precisa saber o tamanho do
  // que há aqui sem vir olhar.
  el("abaTecnicasNota").textContent = `${emPortugues(data.families.length)} famílias ATT&CK`;

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

/* ------------------------------------------- ampliar o acervo (descoberta)

   Duas propriedades desta tela, que são as mesmas do backend:

   1. **A busca não decide.** O botão de procurar nunca escreve no acervo. As
      propostas ficam na tela com dois caminhos explícitos, e é o clique que
      indexa. Nada aqui aprova em lote.

   2. **A procedência viaja com a proposta.** Repositório, caminho e link vêm
      em cada ficha. Aprovar uma regra sem ver de onde ela saiu seria confiar
      num texto que apareceu na tela — que é exatamente o que este projeto
      inteiro existe para não fazer. */

const discoveryForm = el("discoveryForm");
const discoveryPrompt = el("discoveryPrompt");
const discoverySubmit = el("discoverySubmit");
const discoverySummary = el("discoverySummary");
const discoveryReadout = el("discoveryReadout");
const discoveryWarnings = el("discoveryWarnings");
const discoveryList = el("discoveryList");
const discoveryEmpty = el("discoveryEmpty");

/* Os repositórios confiáveis são uma área própria do menu, e não mais um
   painel dentro da busca: eles são o limite do que a descoberta enxerga, e
   quem avalia a ferramenta precisa poder ver e mudar a lista sem antes fazer
   uma busca. O código abaixo é o mesmo — só o lugar mudou. */
const sourceList = el("sourceList");
const sourceForm = el("sourceForm");
const sourceFormat = el("sourceFormat");
const sourceError = el("sourceError");
const sourcesCount = el("sourcesCount");
const sourcesTokenNote = el("sourcesTokenNote");

/* Como cada formato aparece na tela. O `value` vem do servidor
   (`/api/sources`); só o rótulo legível mora aqui, porque nome de produto não
   é dado de configuração. Formato desconhecido cai no próprio identificador,
   em vez de sumir do seletor. */
const ROTULO_FORMATO = {
  sigma: "Sigma (YAML)",
  splunk_escu: "Splunk ESCU (YAML)",
  yara_l: "YARA-L (.yaral)",
};

let origens = [];

function formatoEscolhido() {
  const marcado = sourceFormat.querySelector("input:checked");
  return marcado ? marcado.value : "";
}

/* Quantas propostas ainda esperam decisão — é isso que a aba precisa dizer,
   não quantas foram encontradas. Uma lista inteira já decidida não deve
   continuar chamando ninguém de volta. */
function atualizarSeloAmpliar() {
  const pendentes = discoveryList.querySelectorAll(".proposta:not(.is-decidida)").length;
  marcarAba("abaAmpliarSelo", pendentes ? `${pendentes} por decidir` : "");
}

function renderOrigens(data) {
  origens = data.sources || [];
  sourcesCount.textContent = `${origens.length} cadastrado${origens.length === 1 ? "" : "s"}`;
  el("abaRepositoriosNota").textContent =
    `${origens.length} confiáve${origens.length === 1 ? "l" : "is"}`;

  sourcesTokenNote.textContent = data.has_github_token
    ? "O servidor tem token do GitHub: a busca também procura dentro do conteúdo das regras."
    : "Sem token do GitHub no servidor, a busca lê a árvore de arquivos de cada repositório e pontua pelo nome. Configure GITHUB_TOKEN no .env para procurar também dentro do conteúdo.";

  sourceList.innerHTML = "";
  for (const source of origens) {
    const li = document.createElement("li");
    li.className = "origem";
    const formato = ROTULO_FORMATO[source.rule_format] || source.rule_format;
    const pastas = source.path_prefixes.length
      ? source.path_prefixes.join(", ")
      : "repositório inteiro";
    li.innerHTML = `
      <span class="origem__slug">${escapeHtml(source.slug)}@${escapeHtml(source.ref)}</span>
      <span class="origem__formato">${escapeHtml(formato)}</span>
      <span class="origem__semente">${escapeHtml(pastas)}${source.is_seed ? " · pré-cadastrado" : ""}</span>
      <button type="button" class="origem__tirar" data-drop-source="${escapeHtml(source.slug)}">tirar</button>
      ${source.note ? `<p class="origem__nota">${escapeHtml(source.note)}</p>` : ""}`;
    sourceList.appendChild(li);
  }

  // Rádios, não um menu suspenso: escolher o formato errado não produz erro,
  // produz uma origem que nunca devolve nada. As opções ficam à vista.
  const anterior = formatoEscolhido();
  sourceFormat.innerHTML = "";
  (data.formats || []).forEach((formato, indice) => {
    const marcado = anterior ? formato === anterior : indice === 0;
    const label = document.createElement("label");
    label.className = "formato" + (marcado ? " is-on" : "");
    label.innerHTML = `
      <input type="radio" name="rule_format" value="${escapeHtml(formato)}" ${marcado ? "checked" : ""}>
      <span>${escapeHtml(ROTULO_FORMATO[formato] || formato)}</span>`;
    sourceFormat.appendChild(label);
  });

}

sourceList.addEventListener("click", async (event) => {
  const botao = event.target.closest("[data-drop-source]");
  if (!botao) return;

  const slug = botao.dataset.dropSource;
  botao.disabled = true;
  sourceError.hidden = true;
  try {
    const response = await fetch(`/api/sources/${slug}`, { method: "DELETE" });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || `a API respondeu ${response.status}`);
    }
    renderOrigens(await response.json());
  } catch (error) {
    botao.disabled = false;
    sourceError.textContent = `${slug} continua cadastrado: ${error.message}.`;
    sourceError.hidden = false;
  }
});

sourceFormat.addEventListener("change", () => {
  for (const label of sourceFormat.querySelectorAll(".formato")) {
    label.classList.toggle("is-on", Boolean(label.querySelector("input:checked")));
  }
});

sourceForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = el("sourceSubmit");
  const slug = el("sourceSlug").value.trim();
  if (!slug) return;

  sourceError.hidden = true;
  submit.disabled = true;
  submit.textContent = "Conferindo…";

  try {
    const response = await fetch("/api/sources", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        slug,
        rule_format: formatoEscolhido(),
        ref: el("sourceRef").value.trim() || null,
        // Uma caixa só, separada por vírgula: pedir uma linha por pasta seria
        // um formulário maior para o caso raro de haver mais de uma.
        path_prefixes: el("sourcePaths")
          .value.split(",")
          .map((item) => item.trim())
          .filter(Boolean),
      }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || `a API respondeu ${response.status}`);
    }
    renderOrigens(await response.json());
    sourceForm.reset();
    sourceFormat.dispatchEvent(new Event("change"));
  } catch (error) {
    sourceError.textContent = error.message;
    sourceError.hidden = false;
  } finally {
    submit.disabled = false;
    submit.textContent = "Cadastrar";
  }
});

function renderRelatorio(data) {
  discoveryReadout.hidden = false;
  el("discoveryTerms").textContent = data.terms.length
    ? data.terms.join(" · ")
    : "nenhum termo aproveitável";
  el("discoverySources").textContent = `${data.sources_searched.length}`;
  el("discoveryFiles").textContent = `${data.files_read}`;
  el("discoveryKnown").textContent = `${data.already_indexed}`;

  const tecnicas = data.techniques.length ? ` · filtro por ${data.techniques.join(", ")}` : "";
  el("discoveryPlanSource").textContent = data.expanded_by_model
    ? `Termos traduzidos por ${data.model}${tecnicas} · ${data.rules_parsed} regras lidas em ${data.elapsed_ms} ms`
    : `Termos extraídos do próprio pedido, sem modelo${tecnicas} · ${data.rules_parsed} regras lidas em ${data.elapsed_ms} ms`;

  discoveryWarnings.hidden = data.warnings.length === 0;
  discoveryWarnings.innerHTML = data.warnings
    .map((aviso) => `<p>${escapeHtml(aviso)}</p>`)
    .join("");
}

function renderProposta(proposal) {
  const li = document.createElement("li");
  li.className = "proposta" + (proposal.status === "pending" ? "" : " is-decidida");
  li.id = `proposta-${proposal.rule_uid}`;

  const etiquetas = [
    ...proposal.mitre_techniques.map(
      (id) => `<span class="etiqueta etiqueta--attack">${escapeHtml(id)}</span>`
    ),
    ...proposal.platforms.map((p) => `<span class="etiqueta">${escapeHtml(p)}</span>`),
    proposal.severity ? `<span class="etiqueta">${escapeHtml(proposal.severity)}</span>` : "",
  ].join("");

  // Por que esta regra subiu. Sem isso, a nota é um número sem defesa.
  const razoes = [];
  if (proposal.matched_techniques.length) {
    razoes.push(`técnica ${proposal.matched_techniques.join(", ")}`);
  }
  if (proposal.matched_terms.length) razoes.push(proposal.matched_terms.join(", "));
  if (proposal.found_by.length) razoes.push(`achada pela ${proposal.found_by.join(" e ")}`);

  const jaDecidida = proposal.status !== "pending";
  const estado =
    proposal.status === "approved"
      ? '<span class="proposta__estado proposta__estado--ok">no acervo</span>'
      : proposal.status === "rejected"
        ? '<span class="proposta__estado proposta__estado--no">recusada antes</span>'
        : "";

  li.innerHTML = `
    <div class="proposta__topo">
      <h3 class="proposta__titulo">${escapeHtml(proposal.title)}</h3>
      <span class="proposta__nota" title="Nota de relevância: ${escapeHtml(razoes.join(" · ") || "sem casamento")}">${proposal.score.toFixed(1)}</span>
    </div>
    ${proposal.description ? `<p class="proposta__descricao">${escapeHtml(proposal.description)}</p>` : ""}
    <div class="etiquetas">${etiquetas}</div>
    <p class="proposta__origem">
      <span class="proposta__repo">${escapeHtml(proposal.source_slug)}</span>
      <a href="${escapeHtml(proposal.source_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(proposal.source_path)}</a>
    </p>
    ${razoes.length ? `<p class="proposta__origem">casou: ${escapeHtml(razoes.join(" · "))}</p>` : ""}
    <details class="proposta__logica">
      <summary>ver a lógica de detecção (${escapeHtml(proposal.query_language)})</summary>
      <pre><code>${escapeHtml(proposal.query)}</code></pre>
      ${proposal.query_truncated ? '<p class="proposta__corte">Lógica cortada no mesmo limite que o acervo aplica — a regra completa está no arquivo de origem.</p>' : ""}
    </details>
    <div class="proposta__acao">
      <button type="button" class="proposta__add" data-approve="${escapeHtml(proposal.rule_uid)}" ${jaDecidida ? "disabled" : ""}>
        Adicionar ao acervo
      </button>
      <button type="button" class="proposta__no" data-reject="${escapeHtml(proposal.rule_uid)}" ${jaDecidida ? "disabled" : ""}>
        Recusar
      </button>
      ${estado}
    </div>`;
  return li;
}

function renderPropostas(data) {
  discoveryList.innerHTML = "";
  data.proposals.forEach((proposal) => discoveryList.appendChild(renderProposta(proposal)));

  atualizarSeloAmpliar();

  const total = data.proposals.length;
  discoverySummary.textContent = total
    ? `${total} regra${total === 1 ? "" : "s"} para revisar`
    : "nenhuma regra nova nesta busca";

  if (total) {
    discoveryEmpty.hidden = true;
    return;
  }
  // Vazio não é erro, e cada motivo de vazio pede uma ação diferente.
  discoveryEmpty.hidden = false;
  discoveryEmpty.textContent = data.already_indexed
    ? `Nenhuma regra nova: as ${data.already_indexed} encontradas já estão no acervo. Tente um comportamento mais específico, ou cadastre outra origem.`
    : "Nenhuma regra casou com esse pedido nas origens cadastradas. Descreva o comportamento a detectar — a ferramenta, o binário, o evento — em vez de fazer uma pergunta.";
}

async function procurarRegras(prompt) {
  discoverySubmit.disabled = true;
  discoverySubmit.textContent = "Procurando…";
  discoveryEmpty.hidden = true;
  try {
    const response = await fetch("/api/discovery/search", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...cabecalhosDeChave() },
      body: JSON.stringify({ prompt, limit: 12 }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || `a API respondeu ${response.status}`);
    }
    const data = await response.json();
    renderRelatorio(data);
    renderPropostas(data);
  } catch (error) {
    discoveryList.innerHTML = "";
    discoveryReadout.hidden = true;
    discoveryEmpty.hidden = false;
    discoveryEmpty.textContent = `A busca não completou: ${error.message}.`;
  } finally {
    discoverySubmit.disabled = false;
    discoverySubmit.textContent = "Procurar";
  }
}

discoveryForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const prompt = discoveryPrompt.value.trim();
  if (prompt) procurarRegras(prompt);
});

discoveryList.addEventListener("click", async (event) => {
  const aprovar = event.target.closest("[data-approve]");
  const recusar = event.target.closest("[data-reject]");
  if (!aprovar && !recusar) return;

  const botao = aprovar || recusar;
  const ruleUid = botao.dataset.approve || botao.dataset.reject;
  const ficha = el(`proposta-${ruleUid}`);
  const acoes = ficha.querySelectorAll("button");
  acoes.forEach((item) => (item.disabled = true));
  botao.textContent = aprovar ? "Indexando…" : "Recusando…";

  try {
    const response = await fetch("/api/discovery/decide", {
      method: "POST",
      // A chave de embedding acompanha a aprovação: é ela que transforma a
      // regra em vetor. Recusar não usa chave nenhuma, mas o cabeçalho é o
      // mesmo caminho e não custa nada.
      headers: { "Content-Type": "application/json", ...cabecalhosDeChave() },
      body: JSON.stringify({ rule_uid: ruleUid, decision: aprovar ? "approve" : "reject" }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || `a API respondeu ${response.status}`);
    }
    const data = await response.json();

    ficha.classList.add("is-decidida");
    atualizarSeloAmpliar();
    botao.textContent = aprovar ? "Adicionar ao acervo" : "Recusar";
    const estado = document.createElement("span");
    estado.className = `proposta__estado proposta__estado--${aprovar ? "ok" : "no"}`;
    estado.textContent = data.message;
    ficha.querySelector(".proposta__acao").appendChild(estado);

    // O acervo cresceu: o medidor e o mapa precisam dizer o número novo, senão
    // a regra aprovada some da tela sem aparecer em lugar nenhum.
    if (aprovar && data.indexed_chunks) atualizarAcervo();
  } catch (error) {
    acoes.forEach((item) => (item.disabled = false));
    botao.textContent = aprovar ? "Adicionar ao acervo" : "Recusar";
    const falha = document.createElement("span");
    falha.className = "proposta__estado proposta__estado--erro";
    falha.textContent = error.message;
    ficha.querySelector(".proposta__acao").appendChild(falha);
  }
});

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
      // A chave de quem usa vai por cabeçalho, uma por provedor, e só nesta
      // requisição — o servidor a usa e descarta.
      headers: { "Content-Type": "application/json", ...cabecalhosDeChave() },
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

/* A vista vem do endereço: recarregar cai na mesma área, e o link leva alguém
   direto a ela. Endereço vazio ou desconhecido abre a pergunta, que é o que a
   ferramenta faz. */
mostrarVista(location.hash.slice(1));

fetch("/api/models")
  .then((response) => (response.ok ? response.json() : Promise.reject(response)))
  .then(buildModelPicker)
  .catch(() => {
    modelOptions.innerHTML = "";
    modelNote.textContent = "Não deu para ler o catálogo de modelos — a resposta usará o padrão.";
  });

fetch("/api/settings")
  .then((response) => (response.ok ? response.json() : Promise.reject(response)))
  .then((data) => {
    providerStatus = data.providers;
    corpusEmbeddingModel = data.corpus_embedding_model || "";
    renderChaves();
    // Painel aberto de saída quando falta chave: quem acabou de clonar o
    // repositório precisa ver o que fazer, não descobrir na primeira pergunta
    // que falhou.
    if (!embeddingCoberto() || !geracaoCoberta()) configPanel.open = true;
  })
  .catch(() => {
    keyList.innerHTML =
      "<li class='chave'>Não deu para ler a configuração do servidor.</li>";
  });

fetch("/api/techniques")
  .then((response) => (response.ok ? response.json() : Promise.reject(response)))
  .then(renderCatalogo)
  .catch(() => {
    catalogSummary.textContent = "indisponível";
    catalogNote.textContent =
      "O índice de técnicas não respondeu. Verifique se o Postgres está no ar e o corpus indexado.";
  });

/* O tamanho do acervo é lido no arranque e relido sempre que uma regra nova é
   aprovada — o medidor e o mapa precisam mostrar o número que o banco tem, não
   o que ele tinha quando a página abriu. */
function atualizarAcervo() {
  return fetch("/api/health")
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
}

atualizarAcervo();
fetch("/api/sources")
  .then((response) => (response.ok ? response.json() : Promise.reject(response)))
  .then(renderOrigens)
  .catch(() => {
    sourcesCount.textContent = "indisponível";
    sourcesTokenNote.textContent =
      "A lista de repositórios confiáveis não respondeu. Verifique se o Postgres está no ar.";
  });

// As propostas pendentes de sessões anteriores voltam sozinhas: uma decisão
// adiada não deveria exigir refazer a busca (e gastar cota do GitHub) para ser
// reencontrada.
fetch("/api/discovery/proposals?status=pending")
  .then((response) => (response.ok ? response.json() : Promise.reject(response)))
  .then((data) => {
    if (!data.proposals.length) return;
    data.proposals.forEach((proposal) =>
      discoveryList.appendChild(renderProposta(proposal))
    );
    discoverySummary.textContent = `${data.pending} regra${data.pending === 1 ? "" : "s"} esperando decisão`;
    atualizarSeloAmpliar();
  })
  .catch(() => {
    /* Sem pendências recuperadas a tela abre vazia, que é o estado normal. */
  });

