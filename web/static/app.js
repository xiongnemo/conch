// Nautilus Web UI. Everything goes through the daemon's API; names come
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
    showLogin();
    throw new APIError(401, { error: "需要登录" });
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

for (const b of document.querySelectorAll("#modes button")) {
  b.addEventListener("click", () => api("PUT", "/mode", { mode: b.dataset.mode }).then(renderStatus).catch(showError));
}

// ---- formatting ----

function bytes(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

const kindNames = { select: "手动选择", "url-test": "自动最快", fallback: "故障转移", "load-balance": "负载均衡" };
const stateNames = { running: "运行中", starting: "启动中", crashed: "已崩溃，正在重启", stopped: "已停止" };

// ---- overview ----

let status = null;

function renderStatus(s) {
  status = s;
  const k = s.kernel || {};
  $("#kernel").textContent = `${s.backend} · ${stateNames[k.state] || k.state}`;
  $("#kernel").className = "pill " + (k.state || "");
  for (const b of document.querySelectorAll("#modes button")) b.classList.toggle("active", b.dataset.mode === s.mode);
  $("#sysproxy").checked = !!s.sysproxy;

  const problems = [s.error, ...(s.diagnostics || [])].filter(Boolean);
  $("#banner").hidden = problems.length === 0;
  $("#banner").textContent = s.error ? "配置有问题，内核继续使用上一份可用的配置：\n" + problems.join("\n") : problems.join("\n");

  const rows = [
    ["内核", `${s.backend}（${stateNames[k.state] || k.state}${k.restarts ? `，重启过 ${k.restarts} 次` : ""}）`],
    ["代理端口", s.mixedPort ? `127.0.0.1:${s.mixedPort}（HTTP 和 SOCKS5）` : "-"],
    ["配置文件", s.profile],
  ];
  fill($("#status"), ...rows.flatMap(([t, d]) => [h("dt", {}, t), h("dd", {}, d)]));

  const subs = Object.entries(s.subscriptions || {});
  fill($("#subs"), ...(subs.length ? subs.map(([name, info]) => {
    const parts = [name];
    if (info.total) parts.push(`已用 ${bytes(info.upload + info.download)} / ${bytes(info.total)}`);
    if (info.expire) parts.push(`到期 ${new Date(info.expire * 1000).toLocaleDateString()}`);
    if (info.fetchedAt) parts.push(`更新于 ${new Date(info.fetchedAt).toLocaleString()}`);
    return h("p", {}, parts.join(" · "), " ", h("button", { onclick: () => api("POST", `/subscriptions/${encodeURIComponent(name)}/update`).then(renderStatus).catch(showError) }, "更新"));
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

function delayButton(name) {
  const b = h("button", { class: "delay", title: "测速" }, "测速");
  b.addEventListener("click", async (e) => {
    e.stopPropagation();
    b.textContent = "…";
    try {
      const r = await api("POST", "/delay", { name });
      b.textContent = `${r.delay} ms`;
      b.className = "delay " + (r.delay < 300 ? "good" : "");
    } catch (err) {
      b.textContent = "失败";
      b.className = "delay bad";
      b.title = err.message;
    }
  });
  return b;
}

function renderOutbounds(list) {
  outbounds = list;
  const groups = list.filter((o) => o.kind === "group");
  fill($("#groups"), ...groups.map((g) => h("div", { class: "card group" },
    h("h3", {}, g.name, h("span", { class: "kind" }, kindNames[g.type] || g.type)),
    h("div", { class: "chips" }, g.members.map((m) => {
      const chip = h("span", { class: "chip" + (g.selected === m ? " selected" : ""), title: g.type === "select" ? "点击选择" : "" }, m, delayButton(m));
      if (g.type === "select") {
        chip.style.cursor = "pointer";
        chip.addEventListener("click", () => api("PUT", `/groups/${encodeURIComponent(g.name)}`, { selected: m }).then(loadOutbounds).catch(showError));
      }
      return chip;
    })),
  )));
  const chains = list.filter((o) => o.kind === "chain");
  fill($("#chains"), ...(chains.length ? chains.map((c) => h("p", {}, h("b", {}, c.name), "：", c.hops.join(" → "), " ", h("span", { class: "chip static" }, delayButton(c.name)))) : ["没有链"]));
  const nodes = list.filter((o) => o.kind === "node");
  fill($("#nodes"), h("div", { class: "chips" }, nodes.map((n) => h("span", { class: "chip", title: `${n.type} ${n.server}` }, n.name, delayButton(n.name)))));
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
      e.expires
        ? h("div", { class: "temp" }, "临时，到 " + new Date(e.expires).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false }))
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
      h("p", {}, h("b", {}, $("#explain-target").value.trim()), " → ", h("b", {}, v.target)),
      h("p", {}, "命中：", v.matched),
      v.resolved ? h("p", { class: "muted" }, `本机解析为 ${v.resolved} 后按 IP 匹配`) : null,
      h("p", {}, "出口：", v.outbound),
      v.shadowed?.length ? [h("p", { class: "muted" }, "也匹配，但被压过了："), h("ul", {}, v.shadowed.map((s) => h("li", {}, s)))] : null,
      v.uncertain?.length ? [h("p", { class: "muted" }, "要等到运行时才能确定的规则："), h("ul", {}, v.uncertain.map((s) => h("li", {}, s)))] : null,
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
  fill($("#conns"), list.length ? h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "目标"), h("th", {}, "命中 / 出口"), h("th", {}, ""))),
    h("tbody", {}, list.map((c) => h("tr", {},
      h("td", { class: "target" }, `${c.host}:${c.port}`, c.process ? h("div", { class: "src" }, c.process) : null),
      h("td", {}, c.matched, h("div", { class: "src" }, (c.via || []).join(" → ") + ` · ↑${bytes(c.upload)} ↓${bytes(c.download)}`)),
      h("td", {}, h("div", { class: "actions" },
        h("button", { onclick: () => routeDialog(c.host) }, "改出口"),
        h("button", { onclick: () => api("DELETE", `/connections/${encodeURIComponent(c.id)}`).then(loadConns).catch(showError) }, "断开"))))))) : "没有连接");
}

function loadConns() {
  api("GET", "/failed").then(renderFailed).catch(() => {});
  api("GET", "/connections").then(renderConns).catch((err) => fill($("#conns"), err.message));
}

$("#clear-failed").addEventListener("click", () => api("DELETE", "/failed").then(loadConns).catch(showError));
setInterval(() => { if (currentTab === "connections" && !document.hidden) loadConns(); }, 2000);

// ---- logs ----

const logLines = [];
function addLog(line) {
  logLines.push(line);
  if (logLines.length > 500) logLines.shift();
  if (currentTab === "logs") $("#logs").textContent = logLines.join("\n");
}

// ---- startup ----

function refresh() {
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
