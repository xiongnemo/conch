// Records which hosts each tab failed to load, so the popup can offer to
// route them elsewhere (like ZeroOmega's "failed resources"). It needs
// permission for all sites, which the user grants from the popup; until
// then the browser reports no requests and nothing is recorded.

import { countsAsFailure, record, tabKey, type TabFailures } from "./failures.ts";

// Updates run one at a time: requests fail concurrently, and each update
// reads and writes the tab's record.
let queue: Promise<void> = Promise.resolve();

function update(tabId: number, change: (t: TabFailures) => TabFailures | null) {
  queue = queue
    .then(async () => {
      const key = tabKey(tabId);
      const stored = (await chrome.storage.session.get(key))[key] as TabFailures | undefined;
      const next = change(stored ?? {});
      if (next) await chrome.storage.session.set({ [key]: next });
      else await chrome.storage.session.remove(key);
      const n = next ? Object.keys(next).length : 0;
      await chrome.action.setBadgeText({ tabId, text: n ? String(n) : "" });
    })
    .catch(() => {}); // the tab may be gone
}

chrome.webRequest.onErrorOccurred.addListener(
  (d) => {
    // The extension's own requests (to the daemon) have no tab.
    if (d.tabId >= 0 && countsAsFailure(d.error, d.url)) update(d.tabId, (t) => record(t, d.url, d.error, Date.now()));
  },
  { urls: ["<all_urls>"] },
);

// A new page starts with a clean record.
chrome.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.tabId >= 0) update(d.tabId, () => null);
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
);

chrome.tabs.onRemoved.addListener((tabId) => update(tabId, () => null));

chrome.action.setBadgeBackgroundColor({ color: "#b91c1c" });
