// Stop existing delegations and start a new one from the Authority page.
import { open } from "./lib.mjs";
const DIR = process.env.STATE;
const { page, close } = await open(DIR, { phone: true, scheme: "dark" });
await page.goto("http://localhost:8787/authority");
await page.getByRole("heading", { name: "Delegations" }).waitFor();
while (await page.getByRole("button", { name: "Stop" }).count()) {
  await page.getByRole("button", { name: "Stop" }).first().click();
  await page.getByRole("dialog").getByRole("button", { name: "Stop" }).click();
  await page.waitForTimeout(600);
}
await page.getByRole("button", { name: "New" }).click();
await page.getByLabel("Expected work").fill("Installing kernel headers and NVIDIA driver packages for the RDMA module build on the sparks");
await page.getByRole("dialog").screenshot({ path: `${DIR}/new-delegation.png` });
await page.getByRole("button", { name: "Start delegation" }).click();
await page.waitForTimeout(800);
await page.screenshot({ path: `${DIR}/authority.png`, fullPage: true });
await close();
console.log("done");
