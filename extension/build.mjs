// Builds the extension for Chrome/Edge and Firefox into dist/<browser>.
// Usage: node build.mjs [--watch]
import * as esbuild from "esbuild";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync("package.json", "utf8"));
const base = {
  manifest_version: 3,
  name: "Nautilus",
  version: pkg.version,
  description: "看当前网站经由 nautilus 走哪个出口、为什么，一键改走别的出口；记录网页加载失败的网站。",
  icons: { 16: "icons/16.png", 32: "icons/32.png", 48: "icons/48.png", 128: "icons/128.png" },
  action: { default_popup: "popup.html", default_icon: { 16: "icons/16.png", 32: "icons/32.png" } },
  permissions: ["storage", "activeTab", "webRequest"],
  // The daemon's API. Watching other sites for failed requests is
  // optional and asked for from the popup.
  host_permissions: ["http://127.0.0.1/*", "http://localhost/*"],
  optional_host_permissions: ["<all_urls>"],
};
const browsers = {
  chrome: { ...base, background: { service_worker: "background.js" }, minimum_chrome_version: "116" },
  firefox: {
    ...base,
    background: { scripts: ["background.js"] },
    browser_specific_settings: { gecko: { id: "nautilus@nautilus.invalid", strict_min_version: "128.0" } },
  },
};

const watch = process.argv.includes("--watch");
for (const [browser, manifest] of Object.entries(browsers)) {
  const out = `dist/${browser}`;
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  cpSync("static", out, { recursive: true });
  writeFileSync(`${out}/manifest.json`, JSON.stringify(manifest, null, 2) + "\n");
  const ctx = await esbuild.context({
    entryPoints: ["src/background.ts", "src/popup.ts"],
    outdir: out,
    bundle: true,
    format: "iife",
    target: browser === "chrome" ? "chrome116" : "firefox128",
    logLevel: "warning",
  });
  if (watch) await ctx.watch();
  else {
    await ctx.rebuild();
    await ctx.dispose();
  }
}
if (!watch) console.log("built dist/chrome and dist/firefox");
