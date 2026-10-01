// Draws the toolbar icons (a white spiral shell on blue) into static/icons.
// Usage: node icons.mjs
import { mkdirSync, writeFileSync } from "node:fs";
import { deflateSync } from "node:zlib";

function crc32(buf) {
  let c, crc = 0xffffffff;
  for (const b of buf) {
    c = (crc ^ b) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function png(size, pixel) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = pixel(x, y);
      raw.set([r, g, b, a], y * (size * 4 + 1) + 1 + x * 4);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

// coverage of the shape at a point in [0,1]²: 0 outside, 1 for the shell, 2 for the background.
function shape(u, v) {
  const dx = u - 0.5, dy = v - 0.5;
  // Rounded square background.
  const q = 0.5 - 0.06, rad = 0.2;
  const ax = Math.max(Math.abs(dx) - (q - rad), 0), ay = Math.max(Math.abs(dy) - (q - rad), 0);
  if (Math.hypot(ax, ay) > rad) return 0;
  // A logarithmic spiral, thicker as it grows.
  const r = Math.hypot(dx, dy - 0.02), t = Math.atan2(dy - 0.02, dx);
  const a = 0.035, b = 0.2;
  for (let k = -1; k < 4; k++) {
    const th = t + 2 * Math.PI * k;
    if (th < 0) continue;
    const rs = a * Math.exp(b * th);
    if (rs > 0.36) continue;
    if (Math.abs(r - rs) < 0.025 + rs * 0.12) return 1;
  }
  return 2;
}

mkdirSync("static/icons", { recursive: true });
for (const size of [16, 32, 48, 128]) {
  const n = 4; // supersampling
  writeFileSync(`static/icons/${size}.png`, png(size, (x, y) => {
    let shell = 0, bg = 0;
    for (let i = 0; i < n; i++)
      for (let j = 0; j < n; j++) {
        const s = shape((x + (i + 0.5) / n) / size, (y + (j + 0.5) / n) / size);
        if (s === 1) shell++;
        else if (s === 2) bg++;
      }
    const cover = (shell + bg) / (n * n), white = shell / Math.max(1, shell + bg);
    const mix = (c) => Math.round(c + (255 - c) * white);
    return [mix(37), mix(99), mix(235), Math.round(255 * cover)];
  }));
}
console.log("icons written");
