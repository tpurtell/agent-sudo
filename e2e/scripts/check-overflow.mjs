// Fail if any page overflows horizontally at phone width.
import { chromium, devices } from "@playwright/test";
const DIR = process.env.STATE;
const browser = await chromium.launch({ channel: "chrome" });
const context = await browser.newContext({ viewport: { width: 360, height: 780 }, isMobile: true, hasTouch: true, userAgent: devices["iPhone 14 Pro"].userAgent, storageState: `${DIR}/state.json` });
const page = await context.newPage();
let bad = 0;
for (const path of process.argv.slice(2)) {
  await page.goto(`http://localhost:8787${path}`);
  await page.waitForTimeout(1200);
  const r = await page.evaluate(() => ({ w: document.documentElement.scrollWidth, inner: innerWidth, wide: [...document.querySelectorAll("body *")].filter((e) => e.getBoundingClientRect().right > innerWidth + 1 && !e.closest(".segmented, .cmd, .copy-box")).slice(0, 3).map((e) => e.outerHTML.slice(0, 70)) }));
  const ok = r.w <= r.inner && r.inner <= 361;
  if (!ok) bad++;
  console.log(ok ? "ok  " : "WIDE", path, r.inner, r.w, ok ? "" : r.wide);
}
await browser.close();
process.exit(bad ? 1 : 0);
