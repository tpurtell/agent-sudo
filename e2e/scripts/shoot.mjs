// Screenshot pages of a running service using a saved session.
// Usage: STATE=dir BASE=... VIEW=phone|desktop SCHEME=dark|light node scripts/shoot.mjs /path1 /path2 ...
import { open } from "./lib.mjs";

const BASE = process.env.BASE ?? "http://localhost:8787";
const DIR = process.env.STATE;
const { page, close } = await open(DIR, { phone: (process.env.VIEW ?? "phone") === "phone", scheme: process.env.SCHEME ?? "dark" });
for (const [i, path] of process.argv.slice(2).entries()) {
  await page.goto(BASE + path);
  await page.waitForTimeout(Number(process.env.WAIT ?? 1200));
  const name = `${DIR}/shot-${process.env.VIEW ?? "phone"}-${process.env.SCHEME ?? "dark"}-${i}.png`;
  await page.screenshot({ path: name, fullPage: process.env.FULL !== "0" });
  console.log(name);
}
await close();
