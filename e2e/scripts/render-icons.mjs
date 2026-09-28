// Render the SVG app icons to the PNG sizes browsers and iOS need.
// Usage: node scripts/render-icons.mjs   (uses the local Chrome, or Playwright's Chromium)
import { chromium } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const icons = resolve(here, "../../service/web/public/icons");
const jobs = [
  ["icon.svg", "icon-192.png", 192],
  ["icon.svg", "icon-512.png", 512],
  ["maskable.svg", "icon-maskable-512.png", 512],
  ["maskable.svg", "apple-touch-icon.png", 180],
  ["badge.svg", "badge-96.png", 96],
];

const browser = await chromium.launch({ channel: process.env.PW_CHANNEL ?? "chrome" }).catch(() => chromium.launch());
const page = await browser.newPage();
for (const [src, out, size] of jobs) {
  const svg = readFileSync(resolve(icons, src), "utf8");
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`<html><body style="margin:0;background:transparent">${svg.replace("<svg ", `<svg width="${size}" height="${size}" `)}</body></html>`);
  await page.screenshot({ path: resolve(icons, out), omitBackground: true, clip: { x: 0, y: 0, width: size, height: size } });
  console.log(`${out} (${size}px)`);
}
await browser.close();
