import { expect, type BrowserContext, type Page } from "@playwright/test";

const RUNNER = process.env.HOST_RUNNER ?? "http://host:9000";

export async function hr<T = any>(path: string, body?: unknown): Promise<T> {
  const r = await fetch(RUNNER + path, body === undefined ? {} : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`${path}: ${r.status} ${await r.text()}`);
  return (await r.json()) as T;
}

export interface Job {
  id: string;
  output(): Promise<string>;
  waitFor(re: RegExp, timeout?: number): Promise<string>;
  send(data: string): Promise<void>;
  signal(sig: string): Promise<void>;
  finish(timeout?: number): Promise<{ exit: number; output: string }>;
  requestId(): Promise<string>;
}

/** Start a command on the e2e host as a test user. */
export async function run(argv: string[], opts: { user?: string; tty?: boolean; env?: Record<string, string> } = {}): Promise<Job> {
  const { id } = await hr<{ id: string }>("/run", { user: opts.user ?? "agent", argv, tty: opts.tty ?? false, env: opts.env });
  const job: Job = {
    id,
    output: async () => (await hr(`/result/${id}`)).output,
    async waitFor(re, timeout = 30_000) {
      const deadline = Date.now() + timeout;
      let out = "";
      while (Date.now() < deadline) {
        const r = await hr(`/result/${id}?wait=0.3`);
        out = r.output;
        if (re.test(out)) return out;
        if (r.done) break;
      }
      throw new Error(`timed out waiting for ${re} in output:\n${out}`);
    },
    send: async (data) => void (await hr("/send", { id, data })),
    signal: async (sig) => void (await hr("/signal", { id, signal: sig })),
    async finish(timeout = 60_000) {
      const deadline = Date.now() + timeout;
      while (Date.now() < deadline) {
        const r = await hr(`/result/${id}?wait=1`);
        if (r.done) return { exit: r.exit, output: r.output };
      }
      throw new Error(`command did not finish:\n${await job.output()}`);
    },
    async requestId() {
      const out = await job.waitFor(/\[([A-Z0-9]{4})\]/);
      const url = out.match(/\/r\/(req_[a-z0-9]+)/);
      if (url) return url[1]!;
      // Interactive notice has the code only; look it up in the pending list.
      const code = out.match(/\[([A-Z0-9]{4})\]/)![1];
      return code!;
    },
  };
  return job;
}

export async function addAuthenticator(context: BrowserContext, page: Page) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return { cdp, authenticatorId };
}

export async function api<T = any>(page: Page, method: string, path: string, body?: unknown): Promise<T> {
  return page.evaluate(
    async ({ method, path, body }) => {
      const s = await (await fetch("/api/session")).json();
      const r = await fetch(path, { method, headers: { "content-type": "application/json", "x-csrf-token": s.csrf ?? "" }, body: body === undefined ? undefined : JSON.stringify(body) });
      return { status: r.status, json: await r.json().catch(() => null) };
    },
    { method, path, body },
  ) as Promise<T>;
}

/** Resolve a request id from the terminal code the binary printed. */
export async function requestByCode(page: Page, code: string): Promise<string> {
  if (code.startsWith("req_")) return code;
  let id: string | undefined;
  await expect
    .poll(async () => {
      const r: any = await api(page, "GET", "/api/requests?limit=50");
      id = r.json.items.find((x: any) => x.code === code)?.id;
      return id;
    })
    .toBeTruthy();
  return id!;
}

export async function requestState(page: Page, id: string): Promise<any> {
  return (await api<any>(page, "GET", `/api/requests/${id}`)).json;
}
