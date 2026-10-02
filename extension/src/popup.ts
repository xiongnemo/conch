// The popup: where the current site goes and why, a form to send it
// elsewhere, and the hosts this page failed to load. Names come from
// subscriptions and are untrusted, so the DOM is built with text only.

import { APIError, Daemon, defaultBase, loadPairing, pair, savePairing, type Explanation, type Outbound, type Pairing } from "./api.ts";
import { describe, hostOf, newestFirst, rejects, tabKey, type TabFailures } from "./failures.ts";

type Child = Node | string | null | undefined | false | Child[];

function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, unknown> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v as EventListener);
    else if (k === "class") el.className = String(v);
    else if (v !== false && v != null) el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}

function append(el: Element, children: Child[]) {
  for (const c of children) {
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.append(c);
    else if (c) el.append(document.createTextNode(c));
  }
}

function fill(el: Element, ...children: Child[]) {
  el.replaceChildren();
  append(el, children);
}

const app = document.getElementById("app")!;

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---- which page ----

interface Page {
  tabId?: number;
  host?: string; // empty for pages that do not go through a proxy
}

// The popup describes the active tab; #tab=<id> picks another (for tests).
async function currentPage(): Promise<Page> {
  const fromHash = /^#tab=(\d+)$/.exec(location.hash);
  const tab = fromHash ? await chrome.tabs.get(Number(fromHash[1])) : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab) return {};
  const page: Page = { tabId: tab.id };
  try {
    const u = new URL(tab.url ?? "");
    if (u.protocol === "http:" || u.protocol === "https:") page.host = hostOf(u.href);
  } catch {}
  return page;
}

// ---- pairing ----

function browserName(): string {
  return navigator.userAgent.includes("Firefox/") ? "Firefox" : navigator.userAgent.includes("Edg/") ? "Edge" : "Chrome";
}

function isLoopback(base: string): boolean {
  const host = new URL(base).hostname;
  return host === "localhost" || host === "[::1]" || host.startsWith("127.");
}

function showPairing(note?: string) {
  const base = h("input", { id: "base", value: defaultBase, required: true, spellcheck: "false" });
  const code = h("input", { id: "code", inputmode: "numeric", maxlength: "6", pattern: "\\d{6}", placeholder: "6 位数字", required: true, autocomplete: "off" });
  const error = h("p", { class: "error", hidden: true });
  const form = h("form", { class: "pair" },
    h("h1", {}, "连接 conch"),
    note ? h("p", { class: "error" }, note) : null,
    h("p", { class: "muted" }, "在终端运行 ", h("code", {}, "conch pair"), "，或在 Web UI 里点「配对浏览器扩展」，把配对码填在这里。"),
    h("label", {}, "daemon 地址", base),
    h("label", {}, "配对码", code),
    h("button", { type: "submit" }, "配对"),
    error,
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.hidden = true;
    let url: string;
    try {
      url = new URL(base.value.trim()).origin;
    } catch {
      error.hidden = false;
      error.textContent = "daemon 地址应该像 http://127.0.0.1:9277 这样";
      return;
    }
    // The extension may only talk to loopback addresses unless allowed.
    if (!isLoopback(url) && !(await chrome.permissions.request({ origins: [url + "/*"] }))) {
      error.hidden = false;
      error.textContent = "需要允许扩展访问 " + url + " 才能连接";
      return;
    }
    try {
      await savePairing(await pair(url, code.value.trim(), browserName() + " 扩展"));
      await start();
    } catch (err) {
      error.hidden = false;
      error.textContent = message(err);
    }
  });
  fill(app, form);
  code.focus();
}

// ---- the site ----

const kindNames: Record<string, string> = { group: "出口组", chain: "链", node: "节点", builtin: "" };

function outboundOptions(list: Outbound[], current: string): HTMLOptGroupElement[] {
  // GLOBAL is what global mode uses, not a place to route to.
  const usable = list.filter((o) => o.name !== "GLOBAL");
  const groups: [string, Outbound[]][] = [
    ["出口组", usable.filter((o) => o.kind === "group")],
    ["链", usable.filter((o) => o.kind === "chain")],
    ["直连 / 屏蔽", usable.filter((o) => o.kind === "builtin")],
    ["节点", usable.filter((o) => o.kind === "node")],
  ];
  const label = (o: Outbound) => ({ DIRECT: "DIRECT（直连）", REJECT: "REJECT（屏蔽）" })[o.name] ?? (o.kind === "group" && o.now ? `${o.name}（当前 ${o.now}）` : o.name);
  return groups.filter(([, os]) => os.length).map(([name, os]) =>
    h("optgroup", { label: name }, os.map((o) => h("option", { value: o.name, selected: o.name === current }, label(o)))));
}

function explanation(host: string, ex: Explanation): HTMLElement {
  const delay = h("span", { class: "delay muted" });
  return h("section", { class: "site" },
    h("div", { class: "host" }, host),
    h("div", { class: "via" }, "→ ", h("b", {}, ex.target), ex.uncertain?.length ? "（不一定）" : "", " ", delay),
    h("div", { class: "muted small" }, ex.outbound),
    h("div", { class: "small" }, "命中：", ex.matched),
    ex.resolved ? h("div", { class: "muted small" }, `本机解析为 ${ex.resolved} 后按 IP 匹配`) : null,
    ex.shadowed?.length ? h("details", { class: "small" }, h("summary", {}, `也匹配但被压过的 ${ex.shadowed.length} 条`), h("ul", {}, ex.shadowed.map((s) => h("li", {}, s)))) : null,
    ex.uncertain?.length ? h("details", { class: "small" }, h("summary", {}, "这里判断不了、可能命中的规则"), h("ul", {}, ex.uncertain.map((s) => h("li", {}, s)))) : null,
  );
}

async function showDelay(d: Daemon, target: string, el: Element) {
  if (target === "REJECT") return;
  el.textContent = "测速中…";
  try {
    const r = await d.delay(target);
    el.textContent = r.error ? "连不通" : `${r.delay} ms`;
    el.className = "delay " + (r.error ? "bad" : r.delay < 300 ? "good" : "warn");
    if (r.error) el.setAttribute("title", r.error);
  } catch (err) {
    el.textContent = "";
    el.setAttribute("title", message(err));
  }
}

// showSite explains where host goes and offers to send it elsewhere.
async function showSite(d: Daemon, host: string, into: Element) {
  fill(into, h("p", { class: "muted" }, "正在查询 " + host + " ……"));
  let ex: Explanation, outbounds: Outbound[], targets: string[];
  try {
    [ex, outbounds, targets] = await Promise.all([d.explain(host), d.outbounds(), d.suggest(host)]);
  } catch (err) {
    fill(into, h("p", { class: "error" }, message(err)));
    return;
  }
  const box = explanation(host, ex);
  const target = h("select", { id: "target" }, targets.map((t, i) => h("option", { value: t }, i === 0 && targets.length > 1 ? `${t}（包含所有子域名）` : t)));
  const via = h("select", { id: "via" }, outboundOptions(outbounds, ex.target));
  const ttl = h("select", { id: "ttl" }, h("option", { value: "" }, "永久"), h("option", { value: "1h" }, "1 小时"), h("option", { value: "8h" }, "8 小时"), h("option", { value: "run" }, "本次运行（conch 停止前）"));
  const status = h("p", { class: "small", hidden: true });
  const form = h("form", { class: "route" },
    h("label", {}, "目标", target),
    h("label", {}, "出口", via),
    h("label", {}, "有效期", ttl),
    h("button", { type: "submit" }, "让它走这个出口"),
    status,
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const [t, v] = [target.value, via.value];
    let change: { undo: string };
    try {
      change = await d.setRoute(t, v, ttl.value);
    } catch (err) {
      status.hidden = false;
      status.className = "small error";
      status.textContent = message(err);
      return;
    }
    await showSite(d, host, into);
    const undo = h("button", { class: "link", type: "button" }, "撤销");
    undo.addEventListener("click", async () => {
      try {
        await d.undoRoute(change.undo); // what the change replaced comes back
        await showSite(d, host, into);
      } catch (err) {
        undo.replaceWith(message(err));
      }
    });
    into.prepend(h("p", { class: "notice small" }, `已让 ${t} 走 ${v}。`, undo));
  });
  fill(into, box, form);
  showDelay(d, ex.target, box.querySelector(".delay")!);
}

// ---- failed hosts ----

const allSites = { origins: ["<all_urls>"] };

async function showFailures(d: Daemon, page: Page, site: Element, into: Element) {
  if (!(await chrome.permissions.contains(allSites))) {
    const enable = h("button", { type: "button", class: "secondary" }, "开启：记录网页加载失败的网站");
    enable.addEventListener("click", async () => {
      if (await chrome.permissions.request(allSites)) {
        fill(into, h("p", { class: "muted small" }, "已开启。刷新网页后，加载失败的网站会列在这里。"));
      }
    });
    fill(into, h("h2", {}, "本页加载失败的网站"), h("p", { class: "muted small" }, "需要允许扩展观察所有网站的请求；扩展只记录失败的域名，不会读取网页内容。"), enable);
    return;
  }
  const key = tabKey(page.tabId ?? -1);
  const failures = ((await chrome.storage.session.get(key))[key] ?? {}) as TabFailures;
  // Hosts the user's rules block (ads, usually) fail on purpose: say so,
  // and list them after the real failures.
  const outbounds = await d.outbounds().catch(() => []);
  const list = await Promise.all(newestFirst(failures).map(async (f) => {
    const ex = await d.explain(f.host).catch(() => null);
    return { f, blocked: ex && rejects(ex.target, outbounds) ? ex.matched : "" };
  }));
  list.sort((a, b) => Number(!!a.blocked) - Number(!!b.blocked));
  fill(into, h("h2", {}, "本页加载失败的网站"), list.length ? h("ul", { class: "failures" }, list.map(({ f, blocked }) => {
    const route = h("button", { type: "button", class: "small-button" }, "分流…");
    route.addEventListener("click", () => {
      showSite(d, f.host, site);
      site.scrollIntoView();
    });
    const why = blocked
      ? h("span", { class: "muted small", title: "命中：" + blocked }, `按规则屏蔽 · ${f.count} 次`)
      : h("span", { class: "muted small", title: f.error }, `${describe(f.error)} · ${f.count} 次`);
    return h("li", {}, h("span", { class: "host", title: f.url }, f.host), why, route);
  })) : h("p", { class: "muted small" }, "没有加载失败的请求。"));
}

// ---- the whole popup ----

async function showMain(p: Pairing) {
  const d = new Daemon(p);
  const page = await currentPage();
  const header = h("header", {}, h("strong", {}, "Conch"), h("span", { class: "pill" }, "…"));
  const site = h("div", { id: "site" });
  const failures = h("div", { id: "failures" });
  const webUI = h("button", { type: "button", class: "link" }, "打开 Web UI");
  webUI.addEventListener("click", () => chrome.tabs.create({ url: p.base + "/" }));
  const unpair = h("button", { type: "button", class: "link" }, "取消配对");
  unpair.addEventListener("click", async () => {
    await d.unpair().catch(() => {}); // also when the daemon is down: forget it here
    await savePairing(null);
    showPairing();
  });
  fill(app, header, site, failures, h("footer", {}, webUI, unpair));

  try {
    const s = await d.status();
    const states: Record<string, string> = { running: "运行中", starting: "启动中", crashed: "已崩溃", stopped: "已停止" };
    const modes: Record<string, string> = { rule: "分流", global: "全局", direct: "直连" };
    fill(header.querySelector(".pill")!, `${s.backend} · ${states[s.kernel.state] ?? s.kernel.state} · ${modes[s.mode] ?? s.mode}`);
  } catch (err) {
    if (err instanceof APIError && err.status === 401) {
      await savePairing(null);
      showPairing("配对已失效（可能在 Web UI 里被取消了），请重新配对。");
      return;
    }
    fill(site, h("p", { class: "error" }, message(err)));
    return;
  }
  if (page.host) {
    await showSite(d, page.host, site);
  } else {
    fill(site, h("p", { class: "muted" }, "这个页面不经过代理（浏览器内部页面或本地文件）。"));
  }
  await showFailures(d, page, site, failures);
}

async function start() {
  const p = await loadPairing();
  if (p) await showMain(p);
  else showPairing();
}

start();
