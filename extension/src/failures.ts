// What a page failed to load, by host. The background records it as
// requests fail; the popup lists it and offers to route a host elsewhere.

export interface HostFailure {
  host: string;
  count: number;
  error: string; // as the browser reports it, e.g. net::ERR_CONNECTION_RESET
  url: string; // the last request that failed
  last: number; // milliseconds since the epoch
}

export type TabFailures = Record<string, HostFailure>;

// tabKey is where a tab's failures are kept in storage.session.
export const tabKey = (tabId: number) => `tab:${tabId}`;

// Errors that say nothing about the network: the page, the user or an ad
// blocker cancelled the request, or it was never meant to go out.
const ignored = /ABORTED|ERR_ABORT|BLOCKED_BY_CLIENT|BLOCKED_BY_ADMINISTRATOR|CACHE_MISS|UNKNOWN_URL_SCHEME|CONTENT_BLOCKED|NS_BINDING_ABORTED|NS_ERROR_ABORT/;

export function countsAsFailure(error: string, url: string): boolean {
  if (ignored.test(error)) return false;
  try {
    return ["http:", "https:", "ws:", "wss:"].includes(new URL(url).protocol);
  } catch {
    return false;
  }
}

// hostOf returns the host of a URL as nautilus writes it: IPv6 without brackets.
export function hostOf(url: string): string {
  return new URL(url).hostname.replace(/^\[(.*)\]$/, "$1");
}

export function record(failures: TabFailures, url: string, error: string, now: number): TabFailures {
  const host = hostOf(url);
  const count = (failures[host]?.count ?? 0) + 1;
  return { ...failures, [host]: { host, count, error, url, last: now } };
}

export function newestFirst(failures: TabFailures): HostFailure[] {
  return Object.values(failures).sort((a, b) => b.last - a.last);
}

const descriptions: [RegExp, string][] = [
  [/TIMED_OUT|NET_TIMEOUT/, "连接超时"],
  [/CONNECTION_RESET|NET_RESET/, "连接被重置"],
  [/CONNECTION_REFUSED/, "连接被拒绝"],
  [/CONNECTION_CLOSED|EMPTY_RESPONSE|NET_INTERRUPT/, "连接被关闭"],
  [/NAME_NOT_RESOLVED|UNKNOWN_HOST/, "域名解析失败"],
  [/PROXY|TUNNEL/, "代理连接失败"],
  [/SSL|CERT|SECURE/, "TLS 握手失败"],
  [/QUIC|HTTP2/, "协议错误"],
];

// describe says what an error means in a few words.
export function describe(error: string): string {
  for (const [re, text] of descriptions) if (re.test(error)) return text;
  return error;
}

// An outbound as far as following group selections needs.
export interface Choice {
  name: string;
  kind: string;
  now?: string; // what an automatic group uses
  selected?: string; // what a manual group uses
}

// rejects follows group selections from target to where traffic ends up and
// reports whether that is REJECT: the user's own rules block the host, so its
// failing to load is no news.
export function rejects(target: string, outbounds: Choice[]): boolean {
  const byName = new Map(outbounds.map((o) => [o.name, o]));
  const seen = new Set<string>();
  while (!seen.has(target)) {
    if (target === "REJECT" || target === "REJECT-DROP") return true;
    seen.add(target);
    const o = byName.get(target);
    const next = o?.kind === "group" ? o.now || o.selected : undefined;
    if (!next) return false;
    target = next;
  }
  return false;
}
