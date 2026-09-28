// Request-specific components.

import { h, icon, duration, timeAgo, type IconName } from "./dom";
import type { Assessment, Feature, RequestView, StoredAssessment } from "./types";

const PATHLIKE = /^(\/|~\/|\.\/)/;

/** Render a command line with light syntax emphasis, terminal style. */
export function commandBlock(r: Pick<RequestView, "display" | "command" | "argv" | "mode" | "launch" | "target"> & { env?: string[] }, opts: { compact?: boolean; clip?: boolean } = {}): HTMLElement {
  const el = h("div", { class: ["cmd", opts.compact && "compact", opts.clip && "clip"] });
  el.appendChild(h("span", { class: "prompt" }, r.target === "root" ? "# " : `${r.target}$ `));
  // Environment overrides change what runs; show them first and prominently.
  for (const v of r.env ?? []) {
    el.appendChild(h("span", { class: "envvar", title: "Environment override" }, v));
    el.appendChild(document.createTextNode(" "));
  }
  if (r.mode !== "run" || !r.command) {
    el.appendChild(h("span", { class: "exe" }, r.display));
    return el;
  }
  if (r.launch !== "direct") el.appendChild(h("span", { class: "dim" }, r.launch === "login" ? "sudo -i " : "sudo -s "));
  el.appendChild(h("span", { class: "exe" }, r.command.split("/").pop() ?? r.command));
  const dir = r.command.slice(0, r.command.lastIndexOf("/") + 1);
  if (dir && dir !== "/usr/bin/" && dir !== "/bin/" && dir !== "/usr/sbin/" && dir !== "/sbin/") {
    el.appendChild(h("span", { class: "dim" }, ` (${dir})`));
  }
  for (const arg of r.argv) {
    el.appendChild(document.createTextNode(" "));
    const shown = /[\s'"$`\;&|<>(){}]/.test(arg) || arg === "" ? `'${arg.replace(/'/g, "'\\''")}'` : arg;
    const cls = arg.startsWith("-") ? "flag" : PATHLIKE.test(arg) ? "path" : "";
    el.appendChild(cls ? h("span", { class: cls }, shown) : document.createTextNode(shown));
  }
  return el;
}

const AGENTS: Record<string, { label: string; cls: string; glyph?: IconName; letter?: string }> = {
  claude: { label: "Claude Code", cls: "claude", letter: "✳" },
  codex: { label: "Codex", cls: "codex", letter: "◎" },
  opencode: { label: "opencode", cls: "", letter: "oc" },
  aider: { label: "aider", cls: "", letter: "ai" },
  gemini: { label: "Gemini CLI", cls: "", letter: "✦" },
};

export function agentBadge(agent: string | null): HTMLElement {
  const a = agent ? AGENTS[agent] : undefined;
  if (a?.letter) return h("div", { class: ["agent-icon", a.cls], title: a.label }, a.letter);
  return h("div", { class: "agent-icon", title: agent ?? "shell" }, icon(agent ? "bot" : "terminal"));
}

export function agentName(agent: string | null): string {
  return agent ? (AGENTS[agent]?.label ?? agent) : "Shell";
}

export function riskLevel(risk: number): { lv: number; label: string } {
  if (risk < 15) return { lv: 0, label: "Routine" };
  if (risk < 35) return { lv: 1, label: "Low" };
  if (risk < 55) return { lv: 2, label: "Moderate" };
  if (risk < 75) return { lv: 3, label: "High" };
  return { lv: 4, label: "Critical" };
}

export function riskMeter(stored: StoredAssessment | null, advisorEnabled: boolean): HTMLElement | null {
  const a = stored?.assessment;
  if (!a) {
    if (!advisorEnabled) return null;
    if (stored?.failure) {
      return h("div", { class: "risk" }, h("div", { class: "risk-top" }, h("span", { class: "risk-label faint" }, "Risk analysis unavailable")));
    }
    const bar = h("div", { class: "risk-bar" }, ...Array.from({ length: 20 }, () => h("i")));
    return h("div", { class: "risk pending" }, h("div", { class: "risk-top" }, h("span", { class: "risk-label faint" }, "Analyzing…")), bar);
  }
  const { lv, label } = riskLevel(a.risk);
  const lit = Math.max(1, Math.round(a.risk / 5));
  const bar = h("div", { class: "risk-bar", "aria-hidden": "true" }, ...Array.from({ length: 20 }, (_, i) => h("i", { class: i < lit ? "on" : "" })));
  return h(
    "div",
    { class: ["risk", `lv${lv}`], role: "meter", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": String(a.risk), "aria-label": `Risk ${a.risk} of 100` },
    h("div", { class: "risk-top" }, h("span", { class: "risk-score" }, String(a.risk)), h("span", { class: "risk-label" }, label), h("span", { class: "grow" }), h("span", { class: "tiny faint" }, `${Math.round(a.confidence * 100)}% confident`)),
    bar,
  );
}

export function riskMini(a: Assessment | null | undefined): HTMLElement | null {
  if (!a) return null;
  const { lv, label } = riskLevel(a.risk);
  const colors = ["var(--ok)", "#4caf50", "var(--warn)", "#e8590c", "var(--bad)"];
  return h(
    "span",
    { class: "risk-mini", title: `Risk ${a.risk}/100 · ${label}`, style: `color:${colors[lv]}` },
    h("span", { class: "bar" }, h("i", { style: `width:${Math.max(6, a.risk)}%;background:${colors[lv]}` })),
    String(a.risk),
  );
}

const DIM_LABELS: Record<string, string> = {
  destructive: "Destructive",
  privilege_escape: "Privilege escape",
  persistence: "Persistent change",
  credential_access: "Credential access",
  network_security: "Network / security",
  availability: "Availability impact",
  unusual: "Unusual for this session",
};

export function dimensions(a: Assessment): HTMLElement {
  const order = Object.keys(DIM_LABELS);
  const entries = Object.entries(a.dimensions).sort((x, y) => order.indexOf(x[0]) - order.indexOf(y[0]));
  return h(
    "div",
    { class: "dims" },
    ...entries.map(([k, p]) => {
      const pct = Math.round(p * 100);
      const cls = p >= 0.5 ? "hi" : p >= 0.2 ? "mid" : "lo";
      return h("div", { class: ["dim", cls] }, h("span", {}, DIM_LABELS[k] ?? k), h("b", {}, `${pct}%`), h("div", { class: "track" }, h("i", { style: `width:${Math.max(2, pct)}%` })));
    }),
  );
}

export function featureChips(features: Feature[], limit = 6): HTMLElement | null {
  const shown = features.filter((f) => f.key !== "inspect").slice(0, limit);
  if (!shown.length) return null;
  const cls = (f: Feature) => (f.level === "danger" ? "bad" : f.level === "warn" ? "warn" : "");
  return h("div", { class: "row wrap", style: "gap:6px" }, ...shown.map((f) => h("span", { class: ["chip", cls(f)], title: f.label }, f.key.replace(/_/g, " "))));
}

export function agentClaim(text: string | null): HTMLElement | null {
  if (!text) return null;
  return h(
    "div",
    { class: "claim" },
    h("div", { class: "who" }, icon("bot"), "Agent says · unverified"),
    h("q", {}, text),
  );
}

/** Circular countdown until the request expires. */
export function countdown(r: Pick<RequestView, "created_at" | "deadline_at">): HTMLElement & { tick(): void } {
  const total = Math.max(1, r.deadline_at - r.created_at);
  const circ = 2 * Math.PI * 14;
  const tpl = document.createElement("template");
  tpl.innerHTML = `<svg viewBox="0 0 34 34"><circle class="track" cx="17" cy="17" r="14"/><circle class="bar" cx="17" cy="17" r="14" stroke-dasharray="${circ}"/></svg>`;
  const svg = tpl.content.firstElementChild as SVGSVGElement;
  const bar = svg.querySelector(".bar") as SVGCircleElement;
  const label = h("b");
  const el = h("div", { class: "countdown", title: "Time left before the request expires" }, svg, label) as unknown as HTMLElement & { tick(): void };
  el.tick = () => {
    const left = Math.max(0, r.deadline_at - Date.now());
    bar.style.strokeDashoffset = String(circ * (1 - left / total));
    const s = Math.round(left / 1000);
    label.textContent = s >= 3600 ? `${Math.floor(s / 3600)}h` : s >= 60 ? `${Math.floor(s / 60)}m` : `${s}s`;
    el.classList.toggle("low", left < 60_000);
  };
  el.tick();
  return el;
}

export function stateIcon(r: RequestView): { glyph: IconName; cls: string; label: string } {
  const via = r.decision?.decision.via;
  switch (r.state) {
    case "approved":
      if (via === "delegation") return { glyph: "sparkle", cls: "auto", label: "Approved by delegation" };
      if (via === "grant") return { glyph: "key", cls: "ok", label: "Approved by standing grant" };
      return { glyph: "check", cls: "ok", label: "Approved" };
    case "denied":
      return { glyph: "x", cls: "bad", label: via === "policy" ? "Denied by policy" : "Denied" };
    case "withdrawn":
      return { glyph: r.decision?.decision.reason === "password" ? "key" : "stop", cls: "gray", label: r.decision?.decision.reason === "password" ? "Password used instead" : "Withdrawn" };
    case "expired":
      return { glyph: "clock", cls: "gray", label: "Expired" };
    default:
      return { glyph: "hand", cls: "warn", label: "Waiting" };
  }
}

export function outcomeBanner(r: RequestView): HTMLElement | null {
  if (r.state === "pending" || !r.decision) return null;
  const d = r.decision.decision;
  const s = stateIcon(r);
  const when = timeAgo(r.decision.at);
  let detail = "";
  if (r.state === "approved" && d.via === "user") detail = `${d.by} · ${d.label} · ${when}`;
  else if (r.state === "approved" && d.via === "grant") detail = `${d.label} · ${when}`;
  else if (r.state === "approved" && d.via === "delegation") detail = `“${d.label}” · created by ${d.by} · ${when}`;
  else if (r.state === "denied") detail = `${d.by}${d.reason ? ` · “${d.reason}”` : ""}${d.hard ? " · password blocked" : ""} · ${when}`;
  else if (r.state === "withdrawn") detail = `${d.label} · ${when}`;
  else detail = `after ${duration((r.deadline_at - r.created_at) / 1000)} · ${when}`;
  const cls = s.cls === "warn" ? "gray" : s.cls;
  return h("div", { class: ["outcome", cls] }, icon(s.glyph), h("div", {}, s.label, h("small", {}, detail)));
}
