// Conch Web UI. Everything goes through the daemon's API; names come
// from subscriptions and are untrusted, so the DOM is built with
// textContent only, never innerHTML.

const $ = (sel) => document.querySelector(sel);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v; // CSSOM: allowed by the CSP
    else if (v !== false && v != null) el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// fill replaces an element's children, skipping empty values and
// flattening nested lists the way h() does.
function fill(el, ...children) {
  el.replaceChildren(...children.flat(Infinity).filter((c) => c != null && c !== false));
}

class APIError extends Error {
  constructor(status, body) {
    super(body.error || `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

async function api(method, path, body) {
  const res = await fetch("/api/v1" + path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    const data = await res.json().catch(() => ({}));
    if (path !== "/login") showLogin();
    throw new APIError(401, { error: data.error || "需要登录" });
  }
  const data = res.status === 204 ? null : await res.json().catch(() => ({}));
  if (!res.ok) throw new APIError(res.status, data || {});
  return data;
}

function showError(err) {
  const lines = [err.message, ...(err.body?.diagnostics || [])];
  if (err.body?.where) lines.push("位置：" + err.body.where);
  alert(lines.join("\n"));
}

// ---- login ----

function showLogin() {
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#password").focus();
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("POST", "/login", { password: $("#password").value });
    location.reload();
  } catch (err) {
    $("#login-error").hidden = false;
    $("#login-error").textContent = err.message;
  }
});

$("#logout").addEventListener("click", async () => {
  await api("POST", "/logout");
  location.reload();
});

// ---- tabs and mode ----

let currentTab = "overview";

function showTab(name) {
  if (!document.querySelector(`[data-page="${name}"]`)) name = "overview";
  currentTab = name;
  for (const x of document.querySelectorAll("#tabs button")) x.classList.toggle("active", x.dataset.tab === name);
  for (const s of document.querySelectorAll("[data-page]")) s.hidden = s.dataset.page !== name;
  refresh();
}

for (const b of document.querySelectorAll("#tabs button")) {
  b.addEventListener("click", () => { location.hash = b.dataset.tab; });
}
window.addEventListener("hashchange", () => showTab(location.hash.slice(1)));

$("#sysproxy").addEventListener("change", (e) => {
  api("PUT", "/sysproxy", { enabled: e.target.checked }).then(renderStatus).catch((err) => { e.target.checked = !e.target.checked; showError(err); });
});

$("#tun").addEventListener("change", (e) => {
  api("PUT", "/tun", { enabled: e.target.checked }).then(renderStatus).catch((err) => { e.target.checked = !e.target.checked; showError(err); });
});

for (const b of document.querySelectorAll("#modes button")) {
  b.addEventListener("click", () => api("PUT", "/mode", { mode: b.dataset.mode }).then(renderStatus).catch(showError));
}

// ---- formatting ----

// Dates and times as the CLI prints them, whatever language the browser uses.
const pad = (n) => String(n).padStart(2, "0");
const dateText = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const timeText = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;

function bytes(n = 0) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

const kindNames = { select: "手动选择", "url-test": "自动最快", fallback: "故障转移", "load-balance": "负载均衡" };
const stateNames = { running: "运行中", starting: "启动中", crashed: "已崩溃，正在重启", stopped: "已停止" };

// ---- kernel ----

let switching = false;

async function loadKernels() {
  try {
    const list = await api("GET", "/kernels");
    fill($("#backend"), list.map((k) => h("option", { value: k.name, selected: k.current },
      k.name + (!k.installed ? "（切换时下载）" : k.unverified ? `（${k.version} 未经验证）` : ""))));
  } catch (err) {
    // the status shows what is wrong
  }
}

$("#backend").addEventListener("change", async (e) => {
  const name = e.target.value;
  switching = true;
  e.target.disabled = true;
  $("#kernel").textContent = "正在切换内核……";
  try {
    await api("PUT", "/kernel", { backend: name });
  } catch (err) {
    showError(err);
  } finally {
    switching = false;
    e.target.disabled = false;
    await loadKernels();
    renderStatus(await api("GET", "/status"));
    refresh();
  }
});

// ---- overview ----

let status = null;

function renderStatus(s) {
  status = s;
  const k = s.kernel || {};
  $("#kernel").textContent = switching ? "正在切换内核……" : stateNames[k.state] || k.state;
  if (!switching && $("#backend").value !== s.backend) loadKernels();
  $("#kernel").className = "pill " + (k.state || "");
  for (const b of document.querySelectorAll("#modes button")) b.classList.toggle("active", b.dataset.mode === s.mode);
  $("#sysproxy").checked = !!s.sysproxy;
  $("#tun").checked = !!s.tun;

  const problems = [s.error, ...(s.diagnostics || [])].filter(Boolean);
  $("#banner").hidden = problems.length === 0;
  $("#banner").textContent = s.error ? "配置有问题，内核继续使用上一份可用的配置：\n" + problems.join("\n") : problems.join("\n");

  const rows = [
    ["内核", `${s.backend}${s.kernelVersion ? " " + s.kernelVersion : ""}（${stateNames[k.state] || k.state}${k.restarts ? `，重启过 ${k.restarts} 次` : ""}）` +
      (s.unverified ? "。这个版本没有经过这个 conch 验证，可以运行 conch kernel install " + s.backend + " 安装验证过的版本，再重启 conch daemon" : "")],
    ["代理端口", s.mixedPort ? `127.0.0.1:${s.mixedPort}（HTTP 和 SOCKS5）` : "-"],
    ["配置文件", s.profile],
  ];
  fill($("#status"), ...rows.flatMap(([t, d]) => [h("dt", {}, t), h("dd", {}, d)]));

  const subs = Object.entries(s.subscriptions || {});
  fill($("#subs"), ...(subs.length ? subs.map(([name, info]) => {
    const parts = [info.summary ? `${name}：${info.summary}` : name];
    if (info.total) parts.push(`已用 ${bytes((info.upload || 0) + (info.download || 0))} / ${bytes(info.total)}`);
    if (info.expire) parts.push(`到期 ${dateText(new Date(info.expire * 1000))}`);
    if (info.fetchedAt) {
      const at = new Date(info.fetchedAt);
      parts.push(`更新于 ${dateText(at)} ${timeText(at)}`);
    }
    const update = (e) => {
      const b = e.currentTarget;
      b.disabled = true;
      b.textContent = "更新中…";
      api("POST", `/subscriptions/${encodeURIComponent(name)}/update`).then(renderStatus).catch(showError)
        .finally(() => { b.disabled = false; b.textContent = "更新"; });
    };
    return h("p", {}, parts.join(" · "), " ", h("button", { onclick: update }, "更新"));
  }) : ["没有订阅"]));
}

const samples = [];
function addTraffic(t) {
  $("#up").textContent = bytes(t.up) + "/s";
  $("#down").textContent = bytes(t.down) + "/s";
  samples.push(t);
  if (samples.length > 120) samples.shift();
  drawChart();
}

function drawChart() {
  const c = $("#chart");
  const ctx = c.getContext("2d");
  const w = c.width, hgt = c.height;
  ctx.clearRect(0, 0, w, hgt);
  const max = Math.max(1024, ...samples.map((s) => Math.max(s.up, s.down)));
  const line = (key, color) => {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    samples.forEach((s, i) => {
      const x = (i / 119) * w, y = hgt - (s[key] / max) * (hgt - 4) - 2;
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
  };
  line("down", "#2563eb");
  line("up", "#16a34a");
}

// ---- outbounds ----

let outbounds = [];

function showDelay(el, r) {
  if (r.error) {
    el.textContent = "失败";
    el.className = "delay bad";
    el.title = r.error;
  } else {
    el.textContent = `${r.delay} ms`;
    el.className = "delay " + (r.delay < 300 ? "good" : "");
    el.title = "";
  }
}

// delayButton tests an outbound. onHops receives a chain's per-hop results.
function delayButton(name, onHops) {
  const b = h("button", { class: "delay", title: "测速" }, "测速");
  b.addEventListener("click", async (e) => {
    e.stopPropagation();
    b.textContent = "…";
    try {
      const r = await api("POST", "/delay", { name });
      showDelay(b, r);
      if (r.hops && onHops) onHops(r.hops);
    } catch (err) {
      showDelay(b, { error: err.message });
    }
  });
  return b;
}

// hopLabel shows a group hop with the member it uses: 香港自动[HK 03].
function hopLabel(name) {
  const g = outbounds.find((o) => o.name === name && o.kind === "group");
  return g && g.now ? `${name}[${g.now}]` : name;
}

// nameSpan holds an outbound's name, cut short with "…" when it does not
// fit; the whole name is in its tooltip.
function nameSpan(name, title = name) {
  return h("span", { class: "name", title }, name);
}

// removeButton deletes an outbound added from the UIs.
function removeButton(kind, name) {
  return h("button", { class: "link remove", title: "删除", onclick: (e) => {
    e.stopPropagation();
    if (!confirm(`删除${{ chains: "链", nodes: "节点", groups: "出口组" }[kind]} ${name}？`)) return;
    api("DELETE", `/${kind}/${encodeURIComponent(name)}`).then(loadOutbounds).catch(showError);
  } }, "×");
}

function chainRow(c) {
  const hopDelays = c.hops.map(() => h("span", { class: "hop-delay" }));
  const hops = c.hops.flatMap((hop, i) => [i ? " → " : null, hopLabel(hop), hopDelays[i]]);
  return h("p", { class: "chain" }, h("b", {}, c.name), "：", hops, " ",
    c.udp ? h("span", { class: "badge", title: "UDP 流量（例如 QUIC、游戏、语音）也能经由这条链" }, "UDP") : null, " ",
    h("span", { class: "chip static" }, delayButton(c.name, (results) => results.forEach((r, i) => {
      if (!hopDelays[i]) return;
      hopDelays[i].textContent = r.error ? " 失败" : ` ${r.delay} ms`;
      hopDelays[i].className = "hop-delay " + (r.error ? "bad" : "");
      hopDelays[i].title = r.error ? r.error : `经由前 ${i + 1} 跳的延迟`;
    }))),
    c.managed ? removeButton("chains", c.name) : h("span", { class: "src", title: "写在 profile.yaml 里，请在那里修改" }, " " + (c.source || "")));
}

// hopSelect picks one hop of a new chain: the first may be a group or a
// chain, later ones must be nodes.
function hopSelect(first) {
  const usable = outbounds.filter((o) => o.kind === "node" || (first && (o.kind === "group" || o.kind === "chain") && o.name !== "GLOBAL"));
  return h("select", { class: "hop" }, usable.map((o) => h("option", { value: o.name }, o.kind === "node" ? o.name : `${o.name}（${o.kind === "group" ? "出口组" : "链"}）`)));
}

function resetChainForm() {
  fill($("#chain-hops"), hopSelect(true), " → ", hopSelect(false));
}

$("#chain-add-hop").addEventListener("click", () => $("#chain-hops").append(" → ", hopSelect(false)));

$("#chain-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#chain-name").value.trim();
  const hops = [...document.querySelectorAll("#chain-hops select")].map((s) => s.value);
  try {
    await api("PUT", `/chains/${encodeURIComponent(name)}`, { hops });
    $("#chain-name").value = "";
    resetChainForm();
    loadOutbounds();
  } catch (err) {
    showError(err);
  }
});

// renderMembers lists what a new group can hold, keeping what is ticked
// (in the order it was ticked) across refreshes.
let groupPicks = [];
function renderMembers(list) {
  const usable = list.filter((o) => o.name !== "GLOBAL");
  fill($("#group-members"), ...usable.map((o) => {
    const box = h("input", { type: "checkbox", value: o.name });
    box.checked = groupPicks.includes(o.name);
    box.addEventListener("change", () => {
      groupPicks = box.checked ? [...groupPicks, o.name] : groupPicks.filter((n) => n !== o.name);
    });
    const kind = { group: "（出口组）", chain: "（链）", builtin: o.name === "DIRECT" ? "（直连）" : "（屏蔽）" }[o.kind] || "";
    return h("label", {}, box, " ", o.name + kind);
  }));
}

$("#group-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#group-name").value.trim();
  try {
    await api("POST", "/groups", { name, type: $("#group-type").value, members: groupPicks });
    $("#group-name").value = "";
    $("#group-type").value = "select";
    groupPicks = [];
    loadOutbounds();
  } catch (err) {
    showError(err);
  }
});

$("#node-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const added = await api("POST", "/nodes", { link: $("#node-link").value.trim() });
    $("#node-link").value = "";
    await loadOutbounds();
    const names = added.names || [added.name];
    const lines = [names.length > 1 ? `已添加 ${names.length} 个节点：` + names.join("、") : `已添加节点 ${names[0]}`];
    if (added.skipped?.length) lines.push("", `${added.skipped.length} 条无法识别，已跳过：`, ...added.skipped);
    alert(lines.join("\n"));
  } catch (err) {
    showError(err);
  }
});

// Ctrl+Enter (⌘+Enter) adds; Enter alone is a new line, for pasting many.
for (const [box, form] of [["#node-link", "#node-form"], ["#node-yaml", "#node-yaml-form"]]) {
  $(box).addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      $(form).requestSubmit();
    }
  });
}

// ---- nodes written by hand ----
//
// The form is the daemon's (GET /nodeform): which fields each protocol
// has and when they show. It edits the node's mapping as profile.yaml
// has it, so keys it has no field for are kept. The daemon checks what
// is typed, for the running kernel, and writes the YAML; the "profile
// 写法" tab edits that YAML directly.

const editor = { schema: null, node: null, editing: "", more: false, tab: "", checked: 0 };

const getPath = (m, key) => key.split(".").reduce((v, k) => (v && typeof v === "object" ? v[k] : undefined), m);

function setPath(m, key, v) {
  const parts = key.split(".");
  const chain = [m];
  for (const k of parts.slice(0, -1)) {
    const cur = chain[chain.length - 1];
    if (cur[k] == null || typeof cur[k] !== "object") {
      if (v == null) return;
      cur[k] = {};
    }
    chain.push(cur[k]);
  }
  const last = parts[parts.length - 1];
  if (v == null) delete chain[chain.length - 1][last];
  else chain[chain.length - 1][last] = v;
  // mappings left empty go too
  for (let i = chain.length - 1; i > 0; i--) {
    if (Object.keys(chain[i]).length) break;
    delete chain[i - 1][parts[i - 1]];
  }
}

const textOf = (v) => (v == null ? "" : Array.isArray(v) ? v.join(", ") : String(v));

function valueOf(f, text) {
  text = String(text);
  if (f.kind !== "secret") text = text.trim(); // a password is what was typed
  if (text === "") return null;
  if (f.kind === "number") return /^\d+$/.test(text) ? Number(text) : text;
  if (f.kind === "list") {
    const items = text.split(/[,，]/).map((x) => x.trim()).filter(Boolean);
    return items.length ? items.map((x) => (f.key === "reserved" && /^\d+$/.test(x) ? Number(x) : x)) : null;
  }
  return text;
}

function visible(f, m) {
  if (f.types?.length && !f.types.includes(textOf(m.type))) return false;
  return Object.entries(f.when || {}).every(([k, vals]) => vals.includes(textOf(getPath(m, k))));
}

function newNode(type) {
  const m = { type };
  for (const f of editor.schema.fields) if (f.default !== undefined && visible(f, m)) setPath(m, f.key, f.default);
  return m;
}

// Fields others depend on: a change to them shows and hides fields.
const deciders = () => new Set(["type", ...editor.schema.fields.flatMap((f) => Object.keys(f.when || {}))]);

// dropHidden takes out the values of fields that do not show, such as
// the uuid of a node that became trojan.
function dropHidden(m) {
  const shown = new Set(editor.schema.fields.filter((f) => visible(f, m)).map((f) => f.key));
  for (const f of editor.schema.fields) if (!shown.has(f.key) && getPath(m, f.key) !== undefined) setPath(m, f.key, null);
}

function fieldInput(f) {
  const id = "nf-" + f.key.replace(/[^a-z0-9]/gi, "-");
  const cur = getPath(editor.node, f.key);
  const changed = (v) => {
    setPath(editor.node, f.key, v);
    if (f.key === "type") {
      for (const d of editor.schema.fields) {
        if (d.default !== undefined && getPath(editor.node, d.key) === undefined && visible(d, editor.node)) setPath(editor.node, d.key, d.default);
      }
    }
    if (deciders().has(f.key)) {
      dropHidden(editor.node);
      renderFields();
    }
    checkSoon();
  };
  let input;
  if (f.kind === "bool") {
    input = h("input", { type: "checkbox", id });
    input.checked = cur === true || cur === "true";
    input.addEventListener("change", () => changed(input.checked ? true : null));
  } else if (f.kind === "select") {
    const options = [...f.options];
    if (cur != null && !options.some((o) => o.value === textOf(cur))) options.push({ value: textOf(cur), label: textOf(cur) });
    input = h("select", { id }, options.map((o) => h("option", { value: o.value }, o.label)));
    input.value = textOf(cur);
    input.addEventListener("change", () => changed(input.value === "" ? null : input.value));
  } else {
    input = h("input", { id, type: f.kind === "secret" ? "password" : f.kind === "number" ? "number" : "text", placeholder: f.hint || "", autocomplete: "off", spellcheck: "false" });
    input.value = textOf(cur);
    input.addEventListener("input", () => changed(valueOf(f, input.value)));
    if (f.kind === "secret") {
      const show = h("button", { type: "button", class: "link", title: "显示或隐藏" }, "显示");
      show.addEventListener("click", () => {
        input.type = input.type === "password" ? "text" : "password";
        show.textContent = input.type === "password" ? "显示" : "隐藏";
      });
      input = h("span", { class: "secret" }, input, show);
    }
  }
  return [h("label", { for: id, class: f.required ? "required" : "" }, f.label), input];
}

function renderFields() {
  const shown = editor.schema.fields.filter((f) => visible(f, editor.node));
  const folded = shown.filter((f) => f.more && getPath(editor.node, f.key) === undefined);
  const rows = shown.filter((f) => editor.more || !folded.includes(f));
  fill($("#node-field-list"), rows.map(fieldInput));
  $("#node-more").hidden = !folded.length;
  $("#node-more").textContent = editor.more ? "收起更多选项" : `更多选项（${folded.length}）`;
}

$("#node-more").addEventListener("click", () => {
  editor.more = !editor.more;
  renderFields();
});

// check asks the daemon what it makes of what is typed, and shows it;
// answers to older questions are dropped.
async function check(body) {
  const n = ++editor.checked;
  try {
    const c = await api("POST", "/nodes/check", { ...body, editing: editor.editing });
    if (n === editor.checked) showCheck(c);
    return c;
  } catch (err) {
    if (n === editor.checked) showCheck({ errors: [err.message] });
    return null;
  }
}

function showCheck(c) {
  fill($("#node-check"),
    (c.errors || []).map((e) => h("p", { class: "err" }, e)),
    (c.warnings || []).map((w) => h("p", { class: "warn" }, "注意：" + w)),
    editor.tab === "form" && c.yaml ? h("div", { class: "preview", title: "保存后在 managed.yaml 里是这样" }, c.yaml.trim()) : null);
}

let checkTimer;
function checkSoon() {
  clearTimeout(checkTimer);
  checkTimer = setTimeout(() => {
    if (editor.tab === "form") check({ node: editor.node });
    else if (editor.tab === "yaml" && $("#node-yaml").value.trim()) check({ yaml: $("#node-yaml").value });
    else fill($("#node-check"));
  }, 400);
}

$("#node-yaml").addEventListener("input", checkSoon);

async function switchTab(tab) {
  if (tab === editor.tab) return;
  if (tab !== "link") {
    if (!editor.schema) editor.schema = await api("GET", "/nodeform");
    if (!editor.node) editor.node = newNode(editor.schema.types[0].value);
  }
  // What the form has goes along, unless it is untouched.
  const untouched = editor.node && JSON.stringify(editor.node) === JSON.stringify(newNode(editor.node.type));
  if (editor.tab === "form" && tab === "yaml" && !untouched) {
    const c = await check({ node: editor.node });
    if (c?.yaml) $("#node-yaml").value = c.yaml;
  }
  if (editor.tab === "yaml" && tab === "form" && $("#node-yaml").value.trim()) {
    const c = await check({ yaml: $("#node-yaml").value });
    if (!c?.nodes?.length) return; // the errors show; stay on the YAML
    if (c.nodes.length > 1) {
      showCheck({ errors: [`这里写了 ${c.nodes.length} 个节点，表单一次只能填一个；请在这里保存`] });
      return;
    }
    editor.node = c.nodes[0];
  }
  editor.tab = tab;
  for (const b of document.querySelectorAll("#nodes-card [data-editor]")) {
    if (b.tagName === "BUTTON") b.classList.toggle("active", b.dataset.editor === tab);
    else b.hidden = b.dataset.editor !== tab;
  }
  if (tab === "form") renderFields();
  fill($("#node-check"));
  checkSoon();
}

for (const b of document.querySelectorAll(".tabs [data-editor]")) b.addEventListener("click", () => switchTab(b.dataset.editor).catch(showError));
switchTab("link");

function setEditing(name) {
  editor.editing = name;
  $("#node-editing").hidden = !name;
  $("#node-editing-name").textContent = name;
  $(".tabs [data-editor=link]").disabled = !!name;
  for (const b of document.querySelectorAll(".save-node")) b.textContent = name ? "保存修改" : "添加节点";
}

async function editNode(name) {
  try {
    const v = await api("GET", `/nodes/${encodeURIComponent(name)}`);
    if (!editor.schema) editor.schema = await api("GET", "/nodeform");
    setEditing(name);
    editor.node = v.node;
    $("#node-yaml").value = v.yaml;
    if (editor.tab === "link") await switchTab("form");
    else if (editor.tab === "form") renderFields();
    checkSoon();
    $("#nodes-card").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    showError(err);
  }
}

function resetEditor() {
  setEditing("");
  editor.node = editor.schema ? newNode(editor.schema.types[0].value) : null;
  editor.more = false;
  $("#node-yaml").value = "";
  if (editor.tab === "form") renderFields();
}

$("#node-cancel-edit").addEventListener("click", () => {
  resetEditor();
  fill($("#node-check"));
});

async function saveNodes(body) {
  try {
    const path = editor.editing ? `/nodes/${encodeURIComponent(editor.editing)}` : "/nodes";
    const saved = await api(editor.editing ? "PUT" : "POST", path, body);
    const verb = editor.editing ? "已保存" : "已添加";
    resetEditor();
    await loadOutbounds();
    fill($("#node-check"), h("p", { class: "ok" }, `${verb}节点 ${saved.names.join("、")}`));
  } catch (err) {
    showCheck({ errors: [err.message, ...(err.body?.diagnostics || []), err.body?.where ? "位置：" + err.body.where : null].filter(Boolean) });
  }
}

$("#node-fields").addEventListener("submit", (e) => {
  e.preventDefault();
  saveNodes({ node: editor.node });
});

$("#node-yaml-form").addEventListener("submit", (e) => {
  e.preventDefault();
  saveNodes({ yaml: $("#node-yaml").value });
});

function renderOutbounds(list) {
  outbounds = list;
  const groups = list.filter((o) => o.kind === "group");
  fill($("#groups"), ...groups.map((g) => h("div", { class: "card group" },
    h("h3", {}, nameSpan(g.name), h("span", { class: "kind" }, kindNames[g.type] || g.type),
      g.type !== "select" && g.now ? h("span", { class: "kind" }, "当前 " + g.now) : null,
      g.managed ? removeButton("groups", g.name) : null),
    h("div", { class: "chips" }, g.members.map((m) => {
      const chip = h("span", { class: "chip" + ((g.now || g.selected) === m ? " selected" : ""), title: g.type === "select" ? "点击选择" : "" }, nameSpan(m), delayButton(m));
      if (g.type === "select") {
        chip.style.cursor = "pointer";
        chip.addEventListener("click", () => api("PUT", `/groups/${encodeURIComponent(g.name)}`, { selected: m }).then(loadOutbounds).catch(showError));
      }
      return chip;
    })),
  )));
  const chains = list.filter((o) => o.kind === "chain");
  fill($("#chains"), ...(chains.length ? chains.map(chainRow) : ["没有链"]));
  const nodes = list.filter((o) => o.kind === "node");
  fill($("#nodes"), h("div", { class: "chips" }, nodes.map((n) => h("span", { class: "chip" }, nameSpan(n.name, `${n.name}\n${n.type} ${n.server}${n.udp ? "，支持 UDP" : ""}`), delayButton(n.name),
    n.managed ? h("button", { class: "link edit", title: "修改", onclick: (e) => { e.stopPropagation(); editNode(n.name); } }, "✎") : null,
    n.managed ? removeButton("nodes", n.name) : null))));
  if (!document.querySelector("#chain-hops select")) resetChainForm();
  renderMembers(list);
  fill($("#add-via"), ...list.map((o) => h("option", { value: o.name }, o.kind === "builtin" ? { DIRECT: "直连", REJECT: "屏蔽" }[o.name] : o.name)));
}

const loadOutbounds = () => api("GET", "/outbounds").then(renderOutbounds).catch(() => {});

// ---- routes ----

function routeRow(e, extra = "") {
  const del = e.managed ? h("button", { onclick: () => api("DELETE", "/routes?target=" + encodeURIComponent(e.target)).then(loadRoutes).catch(showError) }, "删除") : null;
  return h("tr", {},
    h("td", { class: "target", style: `padding-left:${8 + (e.depth || 0) * 18}px` }, e.target),
    h("td", {}, e.via, extra),
    h("td", {},
      e.forRun ? h("div", { class: "temp" }, "临时，本次运行")
        : e.expires ? h("div", { class: "temp" }, "临时，到 " + timeText(new Date(e.expires)))
        : h("div", { class: "src" }, e.source || ""),
      del),
  );
}

function section(title, rows) {
  if (!rows.length) return null;
  return h("div", { class: "card" }, h("h2", {}, title),
    h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "目标"), h("th", {}, "出口"), h("th", {}, "来源"))), h("tbody", {}, rows)));
}

function renderRoutes(t) {
  const lists = (t.lists || []).map((l, i) => h("tr", {},
    h("td", { class: "target" }, `${i + 1}. ${l.name}`),
    h("td", {}, l.subscription ? `订阅自带的规则（${l.rules} 条）` : l.via),
    h("td", {}, h("div", { class: "src" }, l.source || ""))));
  fill($("#table"), ...[
    section("应用条目", (t.apps || []).map((e) => routeRow(e))),
    section("手动条目（越具体越优先，与书写顺序无关）", (t.domains || []).map((e) => routeRow(e))),
    section("IP 条目（前缀越长越优先）", (t.ips || []).map((e) => routeRow(e, e.resolve ? "（也匹配解析后的域名）" : ""))),
    section("规则列表（从上到下）", lists),
    h("div", { class: "card" }, h("h2", {}, "默认出口"), t.default || "-",
      t.builtins ? h("p", { class: "muted" }, `另有内置的 lan 条目 ${t.builtins} 条：局域网和本机地址走直连。`) : null),
  ].filter(Boolean));
}

const loadRoutes = () => api("GET", "/routes").then(renderRoutes).catch(() => {});

$("#explain-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const v = await api("GET", "/route/explain?target=" + encodeURIComponent($("#explain-target").value.trim()));
    $("#explain").hidden = false;
    $("#explain").className = "card explain";
    fill($("#explain"), 
      h("p", {}, h("b", {}, $("#explain-target").value.trim()), " → ", h("b", {}, v.target), v.uncertain?.length ? "（不一定，见下）" : ""),
      h("p", {}, "命中：", v.matched),
      v.resolved ? h("p", { class: "muted" }, `本机解析为 ${v.resolved} 后按 IP 匹配`) : null,
      h("p", {}, "出口：", v.outbound),
      v.shadowed?.length ? [h("p", { class: "muted" }, "也匹配，但被压过了："), h("ul", {}, v.shadowed.map((s) => h("li", {}, s)))] : null,
      v.uncertain?.length ? [h("p", { class: "muted" }, "排在前面、这里判断不了的规则（命中的话会走别的出口）："), h("ul", {}, v.uncertain.map((s) => h("li", {}, s)))] : null,
      v.apps?.length ? [h("p", { class: "muted" }, "如果连接来自这些应用，会走别的出口："), h("ul", {}, v.apps.map((s) => h("li", {}, s)))] : null,
    );
  } catch (err) {
    showError(err);
  }
});

$("#add-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("PUT", "/routes", { target: $("#add-target").value.trim(), via: $("#add-via").value, ttl: $("#add-ttl").value });
    $("#add-target").value = "";
    loadRoutes();
  } catch (err) {
    showError(err);
  }
});

// ---- connections ----

// routeDialog asks where a host should go and adds the entry.
async function routeDialog(host) {
  const [suggestions] = await Promise.all([api("GET", "/suggest?host=" + encodeURIComponent(host)), outbounds.length ? null : loadOutbounds()]);
  $("#route-dialog-host").textContent = host;
  fill($("#route-dialog-target"), suggestions.map((s, i) => h("option", { value: s }, i === 0 && suggestions.length > 1 ? `${s}（包含所有子域名）` : s)));
  fill($("#route-dialog-via"), outbounds.map((o) => h("option", { value: o.name }, o.kind === "builtin" ? { DIRECT: "直连", REJECT: "屏蔽" }[o.name] : o.name)));
  const dialog = $("#route-dialog");
  dialog.returnValue = "";
  dialog.showModal();
  await new Promise((r) => dialog.addEventListener("close", r, { once: true }));
  if (dialog.returnValue !== "ok") return;
  try {
    await api("PUT", "/routes", { target: $("#route-dialog-target").value, via: $("#route-dialog-via").value, ttl: $("#route-dialog-ttl").value });
  } catch (err) {
    showError(err);
  }
}

function renderFailed(list) {
  fill($("#failed"), list.length ? h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "网站"), h("th", {}, "失败"), h("th", {}, ""))),
    h("tbody", {}, list.map((f) => h("tr", {},
      h("td", { class: "target" }, `${f.host}:${f.port}`),
      h("td", {}, `${f.count} 次，经由 ${f.via}`, h("div", { class: "src", title: f.error }, f.error.slice(0, 80))),
      h("td", {}, h("button", { onclick: () => routeDialog(f.host) }, "分流…")))))) : "还没有失败的连接");
}

function renderConns(list) {
  const caps = status?.caps || {};
  // Kernels without a connection list (xray) report recently opened ones.
  $("#conns-title").textContent = caps.liveConnections ? "当前连接" : "最近的连接";
  $("#conns-note").hidden = !!caps.liveConnections;
  fill($("#conns"), list.length ? h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "目标"), h("th", {}, "命中 / 出口"), h("th", {}, ""))),
    h("tbody", {}, list.map((c) => h("tr", {},
      h("td", { class: "target" }, `${c.host}:${c.port}`, c.process ? h("div", { class: "src" }, c.process) : null),
      h("td", {}, c.matched, h("div", { class: "src" }, (c.via || []).join(" → ") +
        (caps.liveConnections ? ` · ↑${bytes(c.upload)} ↓${bytes(c.download)}` : ` · ${new Date(c.start).toLocaleTimeString("zh-CN", { hour12: false })}`))),
      h("td", {}, h("div", { class: "actions" },
        h("button", { onclick: () => routeDialog(c.host) }, "改出口"),
        caps.closeConnection ? h("button", { onclick: () => api("DELETE", `/connections/${encodeURIComponent(c.id)}`).then(loadConns).catch(showError) }, "断开") : null)))))) : "没有连接");
}

function loadConns() {
  api("GET", "/failed").then(renderFailed).catch(() => {});
  api("GET", "/connections").then(renderConns).catch((err) => fill($("#conns"), err.message));
}

$("#clear-failed").addEventListener("click", () => api("DELETE", "/failed").then(loadConns).catch(showError));
setInterval(() => { if (currentTab === "connections" && !document.hidden) loadConns(); }, 2000);

// ---- browser extensions ----

async function loadPairings() {
  const list = await api("GET", "/pairings").catch(() => []);
  fill($("#pairings"), list.length ? h("table", {}, h("tbody", {}, list.map((p) => h("tr", {},
    h("td", {}, p.name, h("div", { class: "src" }, p.origin || "")),
    h("td", {}, h("div", { class: "src" }, "配对于 " + dateText(new Date(p.created)) + " " + timeText(new Date(p.created)))),
    h("td", {}, h("button", { onclick: () => api("DELETE", `/pairings/${encodeURIComponent(p.id)}`).then(loadPairings).catch(showError) }, "取消配对")))))) : null);
}

let pairTimer = null;
$("#pair").addEventListener("click", async () => {
  try {
    const { code, expires } = await api("POST", "/pair/code");
    $("#pair-code").textContent = code;
    const tick = () => {
      const left = Math.round((new Date(expires) - Date.now()) / 1000);
      $("#pair-expires").textContent = left > 0 ? `${left} 秒内有效，只能用一次` : "已过期，请关闭后重新获取";
      if (left <= 0) clearInterval(pairTimer);
    };
    clearInterval(pairTimer);
    tick();
    pairTimer = setInterval(tick, 1000);
    $("#pair-dialog").showModal();
    $("#pair-dialog").addEventListener("close", () => { clearInterval(pairTimer); loadPairings(); }, { once: true });
  } catch (err) {
    showError(err);
  }
});

// ---- logs ----

const logLines = [];
function addLog(line) {
  logLines.push(line);
  if (logLines.length > 500) logLines.shift();
  if (currentTab === "logs") $("#logs").textContent = logLines.join("\n");
}

// ---- startup ----

function refresh() {
  if (currentTab === "overview") loadPairings();
  if (currentTab === "outbounds") loadOutbounds();
  if (currentTab === "routes") { loadRoutes(); loadOutbounds(); }
  if (currentTab === "connections") { loadConns(); loadOutbounds(); }
  if (currentTab === "logs") $("#logs").textContent = logLines.join("\n");
}

async function start() {
  const session = await fetch("/api/v1/session").then((r) => r.json());
  try {
    renderStatus(await api("GET", "/status"));
  } catch {
    return; // showLogin was called
  }
  $("#app").hidden = false;
  $("#logout").hidden = !session.auth;
  showTab(location.hash.slice(1));
  (await api("GET", "/logs")).forEach(addLog);
  const events = new EventSource("/api/v1/events");
  events.addEventListener("state", (e) => { renderStatus(JSON.parse(e.data)); refresh(); });
  events.addEventListener("traffic", (e) => addTraffic(JSON.parse(e.data)));
  events.addEventListener("log", (e) => addLog(JSON.parse(e.data)));
}

start();
