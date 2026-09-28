// Shared helpers for dev scripts: a browser context with a saved session and a
// virtual passkey whose signature counter is persisted between runs.
import { chromium, devices } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";

export async function open(dir, { phone = true, scheme = "dark" } = {}) {
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL ?? "chrome" });
  const context = await browser.newContext({
    ...(phone
      ? { viewport: { width: 393, height: 852 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, userAgent: devices["iPhone 14 Pro"].userAgent }
      : { viewport: { width: 1360, height: 900 } }),
    colorScheme: scheme,
    storageState: `${dir}/state.json`,
  });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  for (const c of JSON.parse(readFileSync(`${dir}/credentials.json`, "utf8"))) await cdp.send("WebAuthn.addCredential", { authenticatorId, credential: c });
  const close = async () => {
    const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
    writeFileSync(`${dir}/credentials.json`, JSON.stringify(credentials));
    await context.storageState({ path: `${dir}/state.json` });
    await browser.close();
  };
  return { browser, context, page, close };
}
