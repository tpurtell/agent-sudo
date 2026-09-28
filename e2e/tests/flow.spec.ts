// The whole product, end to end: a real setuid agent-sudo under PAM and sudoers, a
// real hostd, the service behind TLS, and the browser UI with a virtual passkey.
import { test, expect, type BrowserContext, type Page } from "@playwright/test";
import { addAuthenticator, api, hr, requestByCode, requestState, run } from "./helpers";

test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let page: Page;

async function openRequest(id: string) {
  await page.goto(`/r/${id}`);
  await expect(page.getByRole("heading", { name: /Request/ })).toBeVisible();
}

async function approveOnce(id: string) {
  await openRequest(id);
  await page.locator(".decision-bar").getByRole("button", { name: /Approve/ }).click();
  await expect(page).toHaveURL(/\/$/);
}

async function deny(id: string, opts: { hard?: boolean } = {}) {
  await openRequest(id);
  if (opts.hard) {
    await page.getByText("More options").click();
    await page.getByText("If denying, also block the password prompt").click();
  }
  await page.locator(".decision-bar").getByRole("button", { name: "Deny" }).click();
  await expect(page).toHaveURL(/\/$/);
}

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext({ baseURL: process.env.BASE_URL });
  page = await context.newPage();
  await addAuthenticator(context, page);
});

test.afterAll(async () => {
  await context.close();
});

test("first-run setup creates an admin with a passkey", async () => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup/);
  await page.goto("/setup#e2e-setup-token-0123456789");
  await page.getByLabel("Username").fill("tj");
  await page.getByLabel("Display name").fill("TJ");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create administrator" }).click();
  await page.getByRole("button", { name: "Create a passkey" }).click();
  await expect(page.getByText("Get notified")).toBeVisible();
  await page.getByRole("button", { name: "Skip for now" }).click();
  await page.getByRole("link", { name: "Add a host" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
});

test("a host enrolls with a one-time token", async () => {
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Name").fill("e2e");
  await dialog.getByLabel("Groups").fill("lab");
  await dialog.getByRole("button", { name: "Create enrollment command" }).click();
  const commands = (await dialog.locator(".cmd").allTextContents()).join("\n");
  expect(commands).toContain("brew install tpurtell/local-ai/agent-sudo");
  const token = commands.match(/--token (\S+)/)![1]!;
  await hr("/enroll", { token, name: "e2e" });
  await dialog.getByRole("button", { name: "Done" }).click();
  await expect(page.locator(".host-row").filter({ hasText: "e2e" })).toBeVisible();
  // Tokens are single use.
  const again = await fetch(`${process.env.BASE_URL}/api/v1/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, hostname: "x", public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", hostd_version: "t" }),
  });
  expect(again.status).toBe(401);
});

test("sudoers denial never reaches the service", async () => {
  const before = (await api<any>(page, "GET", "/api/requests?quiet=true")).json.items.length;
  const job = await run(["agent-sudo", "true"], { user: "stranger" });
  const r = await job.finish(10_000);
  expect(r.exit).not.toBe(0);
  expect(r.output).toMatch(/not allowed|Sorry|not in the sudoers/i);
  const after = (await api<any>(page, "GET", "/api/requests?quiet=true")).json.items.length;
  expect(after).toBe(before);
});

test("NOPASSWD commands run without asking anyone", async () => {
  const job = await run(["agent-sudo", "id", "-u"]);
  const r = await job.finish(10_000);
  expect(r.exit).toBe(0);
  expect(r.output.trim()).toBe("0");
  expect((await api<any>(page, "GET", "/api/requests?quiet=true")).json.items.length).toBe(0);
});

test("a headless request waits for approval in the browser", async () => {
  const job = await run(["agent-sudo", "--agent-context", "Checking who I am as root", "whoami"]);
  const out = await job.waitFor(/waiting for approval \[[A-Z0-9]{4}\] https:\/\/sudo\.e2e\.test\/r\/req_/);
  const id = out.match(/\/r\/(req_[a-z0-9]+)/)![1]!;
  await page.goto("/");
  const card = page.locator(`.req[data-id="${id}"]`);
  await expect(card).toContainText("whoami");
  await expect(card).toContainText("Checking who I am as root");
  await expect(card.locator(".code-tag")).toHaveText(out.match(/\[([A-Z0-9]{4})\]/)![1]!);
  // The mock model's assessment arrives live.
  await expect(card.locator(".risk-score")).toHaveText("22");
  await card.getByRole("button", { name: "Approve once" }).click();
  const r = await job.finish();
  expect(r.exit).toBe(0);
  expect(r.output).toContain("approved by tj");
  expect(r.output.trim().split("\n").pop()).toBe("root");
  await expect(card).toHaveCount(0);
});

test("a denial fails the command", async () => {
  const job = await run(["agent-sudo", "whoami"]);
  const id = await requestByCode(page, await job.requestId());
  await deny(id);
  const r = await job.finish();
  expect(r.exit).not.toBe(0);
  expect(r.output).toContain("denied by tj");
  expect((await requestState(page, id)).state).toBe("denied");
});

test("grants are scoped: session grants don't leak, user grants are reused", async () => {
  const first = await run(["agent-sudo", "ls", "/var/log"]);
  let id = await requestByCode(page, await first.requestId());
  await openRequest(id);
  await page.getByRole("radio", { name: /This command/ }).click();
  await page.getByRole("radio", { name: /This session/ }).click();
  await page.locator(".decision-bar").getByRole("button", { name: /Approve for/ }).click();
  expect((await first.finish()).exit).toBe(0);

  // Every runner command is its own session, so a session grant must not match.
  const second = await run(["agent-sudo", "ls", "/var/log"]);
  id = await requestByCode(page, await second.requestId());
  await openRequest(id);
  await page.getByRole("radio", { name: /This command/ }).click();
  await page.getByRole("radio", { name: /Any session/ }).click();
  await page.locator(".decision-bar").getByRole("button", { name: /Approve for/ }).click();
  expect((await second.finish()).exit).toBe(0);

  const third = await run(["agent-sudo", "ls", "/var/log"]);
  const r = await third.finish(15_000);
  expect(r.exit).toBe(0);
  expect(r.output).toContain("approved by standing grant");
  // Different arguments are not covered.
  const other = await run(["agent-sudo", "ls", "/root"]);
  const otherId = await requestByCode(page, await other.requestId());
  await deny(otherId);
  await other.finish();

  await page.goto("/authority");
  const grant = page.locator(".grant").filter({ hasText: "/usr/bin/ls /var/log" }).filter({ hasText: "user agent" });
  await expect(grant).toContainText("1 use");
  await grant.getByRole("button", { name: "Revoke" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByText("Grant revoked")).toBeVisible();
});

test("sudo -n never blocks: no grant means an immediate failure", async () => {
  const job = await run(["agent-sudo", "-n", "true"]);
  const r = await job.finish(10_000);
  expect(r.exit).not.toBe(0);
  expect(r.output).toMatch(/interactive authentication is required/);
  const pending = (await api<any>(page, "GET", "/api/requests?view=pending")).json.items;
  expect(pending).toHaveLength(0);
});

test("the approval timeout withdraws the request", async () => {
  const job = await run(["agent-sudo", "--approval-timeout", "3s", "true"]);
  const id = await requestByCode(page, await job.requestId());
  const r = await job.finish(20_000);
  expect(r.exit).not.toBe(0);
  expect(r.output).toContain("timed out waiting for approval");
  await expect.poll(async () => (await requestState(page, id)).state).toBe("withdrawn");
});

test("Ctrl-C withdraws a waiting request", async () => {
  const job = await run(["agent-sudo", "true"]);
  const id = await requestByCode(page, await job.requestId());
  await job.signal("SIGINT");
  await job.finish(10_000);
  await expect.poll(async () => (await requestState(page, id)).state).toBe("withdrawn");
});

test.describe("with a terminal", () => {
  const script = "agent-sudo whoami; agent-sudo -n true && echo NOPROMPT || echo NEEDAUTH";

  test("typing the password wins the race and refreshes the timestamp", async () => {
    const job = await run(["bash", "-c", script], { tty: true });
    const out = await job.waitFor(/approval requested \[([A-Z0-9]{4})\][\s\S]*authenticate\] Password/);
    const id = await requestByCode(page, out.match(/\[([A-Z0-9]{4})\]/)![1]!);
    await job.send("agent-password\n");
    const r = await job.finish();
    expect(r.output).toContain("root");
    expect(r.output).toContain("NOPROMPT");
    await expect.poll(async () => (await requestState(page, id)).decision?.decision.reason).toBe("password");
    await hr("/run", { user: "agent", argv: ["agent-sudo", "-K"] });
  });

  test("a remote approval wins the race but does not unlock ordinary sudo", async () => {
    const job = await run(["bash", "-c", script], { tty: true });
    const out = await job.waitFor(/authenticate\] Password/);
    const id = await requestByCode(page, out.match(/\[([A-Z0-9]{4})\]/)![1]!);
    await approveOnce(id);
    const r = await job.finish();
    expect(r.output).toContain("approved by tj");
    expect(r.output).toContain("root");
    expect(r.output).toContain("NEEDAUTH");
  });

  test("…unless the approver explicitly refreshes the timestamp", async () => {
    const job = await run(["bash", "-c", script], { tty: true });
    const out = await job.waitFor(/authenticate\] Password/);
    const id = await requestByCode(page, out.match(/\[([A-Z0-9]{4})\]/)![1]!);
    await openRequest(id);
    await page.getByText("More options").click();
    await page.getByText("Also unlock ordinary sudo on this host").click();
    await page.locator(".decision-bar").getByRole("button", { name: /Approve/ }).click();
    const r = await job.finish();
    expect(r.output).toContain("NOPROMPT");
    await hr("/run", { user: "agent", argv: ["agent-sudo", "-K"] });
  });

  test("a soft denial keeps the password prompt available", async () => {
    const job = await run(["agent-sudo", "whoami"], { tty: true });
    const out = await job.waitFor(/authenticate\] Password/);
    const id = await requestByCode(page, out.match(/\[([A-Z0-9]{4})\]/)![1]!);
    await deny(id);
    await job.waitFor(/you can still authenticate with your password[\s\S]*authenticate\] Password/);
    await job.send("agent-password\n");
    const r = await job.finish();
    expect(r.exit).toBe(0);
    expect(r.output).toContain("root");
    await hr("/run", { user: "agent", argv: ["agent-sudo", "-K"] });
  });

  test("a hard denial also blocks the password", async () => {
    const job = await run(["agent-sudo", "whoami"], { tty: true });
    const out = await job.waitFor(/authenticate\] Password/);
    const id = await requestByCode(page, out.match(/\[([A-Z0-9]{4})\]/)![1]!);
    await deny(id, { hard: true });
    const r = await job.finish();
    expect(r.exit).not.toBe(0);
    expect(r.output).toContain("request denied");
  });

  test("Ctrl-D at the prompt switches to waiting for approval", async () => {
    const job = await run(["agent-sudo", "whoami"], { tty: true });
    const out = await job.waitFor(/authenticate\] Password/);
    const id = await requestByCode(page, out.match(/\[([A-Z0-9]{4})\]/)![1]!);
    await job.send("\x04");
    await job.waitFor(/still waiting for remote approval/);
    await approveOnce(id);
    const r = await job.finish();
    expect(r.exit).toBe(0);
    expect(r.output).toContain("root");
  });
});

test("when hostd is down, headless fails closed and a terminal falls back to the password", async () => {
  await hr("/hostd", { action: "stop" });
  try {
    const headless = await (await run(["agent-sudo", "true"])).finish(10_000);
    expect(headless.exit).not.toBe(0);
    expect(headless.output).toContain("approval service unavailable");

    const tty = await run(["agent-sudo", "whoami"], { tty: true });
    await tty.waitFor(/falling back to password[\s\S]*authenticate\] Password/);
    await tty.send("agent-password\n");
    const r = await tty.finish();
    expect(r.exit).toBe(0);
    await hr("/run", { user: "agent", argv: ["agent-sudo", "-K"] });
  } finally {
    await hr("/hostd", { action: "start" });
  }
});

test("the PATH shim makes plain `sudo` go through agent-sudo", async () => {
  expect((await (await run(["agent-sudo-hostd", "shim", "install"])).finish()).exit).toBe(0);
  const job = await run(["bash", "-c", 'PATH="$HOME/.agent-tools:$PATH" sudo --agent-context "Testing the shim" whoami']);
  const id = await requestByCode(page, await job.requestId());
  await openRequest(id);
  await expect(page.locator(".claim")).toContainText("Testing the shim");
  await page.locator(".decision-bar").getByRole("button", { name: /Approve/ }).click();
  const r = await job.finish();
  expect(r.exit).toBe(0);
  expect(r.output).toContain("root");
});

test("root shells need a fresh passkey and can never become grants", async () => {
  const job = await run(["agent-sudo", "-s", "id", "-u"]);
  const id = await requestByCode(page, await job.requestId());
  await openRequest(id);
  await expect(page.locator(".facts")).toContainText("Unrestricted root execution");
  await expect(page.getByText("Unrestricted root execution always needs a fresh decision.")).toBeVisible();
  await expect(page.getByRole("radio", { name: /This command/ })).toBeDisabled();
  await deny(id);
  await job.finish();
});

test("environment overrides and user-owned executables can't hide from the approver", async () => {
  // sudoers ALL implies SETENV in sudo-rs: the override must be visible and classified.
  const job = await run(["agent-sudo", "LD_PRELOAD=/nonexistent.so", "whoami"]);
  let id = await requestByCode(page, await job.requestId());
  await openRequest(id);
  await expect(page.locator(".cmd .envvar")).toHaveText("LD_PRELOAD=/nonexistent.so");
  await expect(page.locator(".facts")).toContainText("Unrestricted root execution");
  await deny(id);
  await job.finish();

  // A script the agent can edit is arbitrary code, whatever it is called.
  await (await run(["bash", "-c", "mkdir -p ~/bin && printf '#!/bin/sh\\nid -u\\n' > ~/bin/tidy && chmod 755 ~/bin/tidy"])).finish();
  const tidy = await run(["agent-sudo", "/home/agent/bin/tidy"]);
  id = await requestByCode(page, await tidy.requestId());
  const r = await requestState(page, id);
  expect(r.class.name).toBe("root-shell");
  expect(r.executable.writable_by_requester).toBe(true);
  await openRequest(id);
  await expect(page.getByText("The requester can modify this file")).toBeVisible();
  await deny(id);
  await tidy.finish();
});

test("delegations let the model approve related work, within limits", async () => {
  const first = await run(["agent-sudo", "echo", "install", "nvidia-headers"]);
  let id = await requestByCode(page, await first.requestId());
  await openRequest(id);
  await page.getByLabel("Delegate similar requests").check({ force: true });
  await page.getByLabel("What work should it approve?").fill("Installing NVIDIA driver packages on the lab hosts");
  await page.locator(".decision-bar").getByRole("button", { name: "Approve & delegate" }).click();
  expect((await first.finish()).exit).toBe(0);

  // Related: approved by the delegation without anyone looking.
  const related = await (await run(["agent-sudo", "echo", "install", "nvidia-dkms"])).finish(20_000);
  expect(related.exit).toBe(0);
  expect(related.output).toContain("approved by delegation");

  // Unrelated: handed to a human, with the reason recorded.
  const unrelated = await run(["agent-sudo", "echo", "install", "nginx"]);
  id = await requestByCode(page, await unrelated.requestId());
  await openRequest(id);
  await expect(page.getByText(/handed this to you/)).toBeVisible();
  await expect(page.getByText(/relevance to the delegation intent is only 5%/)).toBeVisible();
  await deny(id);
  await unrelated.finish();

  // The kill switch stops automation immediately.
  await page.goto("/authority");
  await page.getByLabel("Automated decisions").uncheck({ force: true });
  await expect(page.getByText("Automation stopped")).toBeVisible();
  const held = await run(["agent-sudo", "echo", "install", "nvidia-utils"]);
  id = await requestByCode(page, await held.requestId());
  expect((await requestState(page, id)).state).toBe("pending");
  await approveOnce(id);
  await held.finish();
  await page.goto("/authority");
  await page.getByLabel("Automated decisions").check({ force: true });
  await expect(page.getByText("Automation on")).toBeVisible();

  // Flagging an automated approval pauses the delegation.
  const auto = await (await run(["agent-sudo", "echo", "install", "cuda-toolkit"])).finish(20_000);
  expect(auto.output).toContain("approved by delegation");
  const items = (await api<any>(page, "GET", "/api/requests?limit=5")).json.items;
  const autoId = items.find((r: any) => r.decision?.decision.via === "delegation").id;
  await openRequest(autoId);
  await page.getByRole("button", { name: /shouldn't have been approved/ }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Flag and pause" }).click();
  await expect(page.getByText(/delegation paused/)).toBeVisible();
  const after = await run(["agent-sudo", "echo", "install", "nvidia-settings"]);
  id = await requestByCode(page, await after.requestId());
  expect((await requestState(page, id)).state).toBe("pending");
  await deny(id);
  await after.finish();
});

test("the service worker shows push notifications with actions", async () => {
  await context.grantPermissions(["notifications"], { origin: process.env.BASE_URL });
  await page.goto("/settings");
  await page.evaluate(() => navigator.serviceWorker.ready);
  const worker = context.serviceWorkers().find((w) => w.url().endsWith("/sw.js")) ?? (await context.waitForEvent("serviceworker"));
  const payload = { t: "request", id: "req_test", v: 1, code: "TEST", title: "claude on e2e wants sudo", body: "apt install -y jq", quick: true, url: "/r/req_test" };
  const shown = await worker.evaluate(async (data) => {
    const event = new PushEvent("push", { data: JSON.stringify(data) });
    const waits: Promise<unknown>[] = [];
    (event as any).waitUntil = (p: Promise<unknown>) => waits.push(p);
    self.dispatchEvent(event);
    await Promise.all(waits);
    const notes = await (self as any).registration.getNotifications({ tag: "req_test" });
    return notes.map((n: any) => ({ title: n.title, body: n.body, actions: n.actions?.map((a: any) => a.action) ?? [], requireInteraction: n.requireInteraction }));
  }, payload);
  expect(shown).toHaveLength(1);
  expect(shown[0].title).toBe("claude on e2e wants sudo");
  expect(shown[0].body).toBe("[TEST] apt install -y jq");
  expect(shown[0].actions).toEqual(["approve", "deny"]);
  expect(shown[0].requireInteraction).toBe(true);
});

test("signing out and back in with only the passkey", async () => {
  const before = (await api<any>(page, "GET", "/api/session")).json;
  // Password login is refused once a passkey exists.
  const pw = await api<any>(page, "POST", "/api/login/password", { name: "tj", password: "correct horse battery staple" });
  expect(pw.status).toBe(403);
  expect(pw.json.error).toBe("passkey_required");

  await page.goto("/settings");
  await page.locator("#account").getByRole("button", { name: "Sign out" }).click();
  // The login page offers passkeys through autofill (conditional mediation). The
  // virtual authenticator answers immediately, so this signs straight back in.
  await expect(page.getByRole("heading", { name: "Requests" })).toBeVisible();
  const after = (await api<any>(page, "GET", "/api/session")).json;
  expect(after.authenticated).toBe(true);
  expect(after.auth_method).toBe("passkey");
  expect(after.csrf).not.toBe(before.csrf);
});

test("the audit log records the story", async () => {
  await page.goto("/audit");
  for (const kind of ["Host enrolled", "Approved", "Denied", "Delegation created", "Delegation approved", "Flagged", "Signed in"]) {
    await expect(page.locator(".tl-item").filter({ hasText: kind }).first()).toBeVisible();
  }
});
