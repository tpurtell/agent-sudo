// Approve a request and delegate similar work, through the real UI.
import { open } from "./lib.mjs";
const BASE = process.env.BASE ?? "http://localhost:8787";
const DIR = process.env.STATE;
const { page, close } = await open(DIR, { phone: true, scheme: "dark" });
await page.goto(`${BASE}/r/${process.env.ID}`);
await page.getByRole("radio", { name: /This command/ }).click();
await page.getByRole("radio", { name: /Group/ }).first().click();
await page.getByLabel("Delegate similar requests").check({ force: true });
await page.getByLabel("What work should it approve?").fill("Installing kernel headers and NVIDIA driver packages needed for the RDMA module build on the sparks");
await page.waitForTimeout(300);
await page.screenshot({ path: `${DIR}/delegate-form.png`, fullPage: true });
await page.getByRole("button", { name: /Approve & delegate/ }).click();
await page.getByText("All clear").or(page.locator(".req").first()).waitFor();
await page.waitForTimeout(800);
await page.screenshot({ path: `${DIR}/after-delegate.png`, fullPage: false });
await close();
console.log("done");
