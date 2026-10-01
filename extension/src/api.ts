// The part of the daemon's API the extension uses. A paired extension
// holds a token that may explain and change routes, nothing more.

export interface Status {
  ready: boolean;
  backend: string;
  kernel: { state: string };
  mode: string;
  mixedPort: number;
}

export interface Explanation {
  target: string; // where traffic goes
  outbound: string; // that outbound, described
  matched: string; // why
  resolved?: string;
  shadowed?: string[];
  uncertain?: string[];
}

export interface Outbound {
  name: string;
  kind: "builtin" | "node" | "group" | "chain";
  type?: string;
  members?: string[];
  selected?: string;
  now?: string;
  hops?: string[];
  udp?: boolean;
}

export interface Delay {
  delay: number; // milliseconds; 0 when the test failed
  error?: string;
  hops?: { name: string; delay?: number; error?: string }[];
}

export interface Pairing {
  base: string; // e.g. http://127.0.0.1:9277
  token: string;
  id: string;
}

export class APIError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const defaultBase = "http://127.0.0.1:9277";

export async function loadPairing(): Promise<Pairing | null> {
  const { pairing } = await chrome.storage.local.get("pairing");
  return (pairing as Pairing | undefined) ?? null;
}

export async function savePairing(p: Pairing | null): Promise<void> {
  if (p) await chrome.storage.local.set({ pairing: p });
  else await chrome.storage.local.remove("pairing");
}

async function send(base: string, method: string, path: string, body?: unknown, token?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = "Bearer " + token;
  try {
    return await fetch(base + "/api/v1" + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new APIError(0, `连不上 nautilus daemon（${base}），它在运行吗？`);
  }
}

async function result<T>(res: Response): Promise<T> {
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new APIError(res.status, (data as { error?: string } | null)?.error || `HTTP ${res.status}`);
  return data as T;
}

// pair trades a code from `nautilus pair` or the Web UI for a token.
export async function pair(base: string, code: string, name: string): Promise<Pairing> {
  const v = await result<{ id: string; token: string }>(await send(base, "POST", "/pair", { code, name }));
  return { base, token: v.token, id: v.id };
}

export class Daemon {
  readonly base: string;
  private token: string;

  constructor(p: Pairing) {
    this.base = p.base;
    this.token = p.token;
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    return result<T>(await send(this.base, method, path, body, this.token));
  }

  status() {
    return this.req<Status>("GET", "/status");
  }

  explain(target: string) {
    return this.req<Explanation>("GET", "/route/explain?target=" + encodeURIComponent(target));
  }

  outbounds() {
    return this.req<Outbound[]>("GET", "/outbounds");
  }

  // suggest proposes targets for a host, its registrable domain first.
  suggest(host: string) {
    return this.req<string[]>("GET", "/suggest?host=" + encodeURIComponent(host));
  }

  setRoute(target: string, via: string, ttl: string) {
    return this.req<unknown>("PUT", "/routes", { target, via, ttl });
  }

  deleteRoute(target: string) {
    return this.req<unknown>("DELETE", "/routes?target=" + encodeURIComponent(target));
  }

  delay(name: string) {
    return this.req<Delay>("POST", "/delay", { name });
  }
}
