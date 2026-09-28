// Drive first-run setup against a running service and save screenshots.
// Usage: BASE=http://localhost:8787 TOKEN=... OUT=dir node scripts/dev-walkthrough.mjs
import { chromium, devices } from "@playwright/test";
import { writeFileSync, mkdirSync } from "node:fs";

const BASE = process.env.BASE ?? "http://localhost:8787";
const OUT = process.env.OUT ?? "./shots";
mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch({ channel: "chrome" });
const context = await browser.newContext({ ...devices["iPhone 14 Pro"], browserName: undefined, defaultBrowserType: undefined, userAgent: devices["iPhone 14 Pro"].userAgent, colorScheme: process.env.SCHEME ?? "dark" });
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});
const shot = async (name) => page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true });

await page.goto(`${BASE}/setup#${process.env.TOKEN}`);
await page.getByLabel("Username").fill("tj");
await page.getByLabel("Display name").fill("TJ");
await page.getByLabel("Password").fill("correct horse battery staple");
await shot("01-setup");
await page.getByRole("button", { name: "Create administrator" }).click();
await page.getByRole("button", { name: "Create a passkey" }).waitFor();
await shot("02-passkey");
await page.getByRole("button", { name: "Create a passkey" }).click();
await page.getByText("Get notified").waitFor();
await shot("03-notify");
await page.getByRole("button", { name: "Skip for now" }).click();
await page.getByText("You're set").waitFor();
await shot("04-done");
await page.getByRole("link", { name: "Go to requests" }).click();
await page.getByText("All clear").waitFor();
await shot("05-empty");

const tokens = await page.evaluate(async () => {
  const s = await (await fetch("/api/session")).json();
  const out = [];
  for (const [name, groups] of [["moa", ["sparks"]], ["emu", ["sparks"]], ["raptor", ["workstation"]]]) {
    const r = await fetch("/api/hosts/tokens", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": s.csrf }, body: JSON.stringify({ name, groups }) });
    out.push({ name, ...(await r.json()) });
  }
  return out;
});
writeFileSync(`${OUT}/tokens.json`, JSON.stringify(tokens, null, 2));
const creds = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
writeFileSync(`${OUT}/credentials.json`, JSON.stringify(creds.credentials));
await context.storageState({ path: `${OUT}/state.json` });
console.log("tokens:", tokens.map((t) => t.name).join(", "));
await browser.close();
