// One grant or delegation: what it covers, what it decided, its history, and edits.

import { ApiError, api, currentSession, onLive, strongAuthFresh } from "../api";
import { riskLevel } from "../components";
import { DELEGATION_DURATIONS, clock, duration, h, icon, timeAgo } from "../dom";
import type { Mounted } from "../router";
import type { HostView, RuleView } from "../types";
import { action, busy, confirmSheet, emptyState, field, segmented, sheet, toast } from "../ui";
import { stepUp } from "../webauthn";

const HISTORY_LABEL: Record<string, string> = {
  "delegation.created": "Created",
  "delegation.widened": "Widened from a request",
  "delegation.edited": "Edited",
  "delegation.paused": "Paused",
  "delegation.resumed": "Resumed",
  "grant.created": "Created",
  "grant.revoked": "Stopped",
};

function hostsText(s: RuleView["scope"]): string {
  const hs = s?.hosts;
  if (!hs) return "?";
  if (hs.scope === "all") return "All hosts";
  if (hs.scope === "groups") return `The ${hs.groups!.join(", ")} group${hs.groups!.length > 1 ? "s" : ""}`;
  return hs.hosts?.join(", ") ?? "One host";
}

function requesterText(s: RuleView["scope"]): string {
  const r = s?.requester;
  if (!r || r.scope === "any") return "Anyone";
  if (r.scope === "user") return `Any session of ${r.user}`;
  return `One session: ${r.label}`;
}

function expiryText(g: RuleView): string {
  if (!g.expires_at) return "No expiry";
  const left = g.expires_at - Date.now();
  return left > 0 ? `${duration(left / 1000)} left · ends ${new Date(g.expires_at).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}` : `Ended ${timeAgo(g.expires_at)}`;
}

function statusChip(g: RuleView): HTMLElement {
  if (g.revoked_at) return h("span", { class: "chip" }, `stopped by ${g.revoked_by}`);
  if (g.paused_at) return h("span", { class: "chip warn" }, icon("pause"), "paused");
  if (!g.active) return h("span", { class: "chip" }, "ended");
  return h("span", { class: ["chip", g.kind === "delegation" ? "auto" : "ok"] }, "active");
}

async function ensureStrong() {
  if (!strongAuthFresh()) await stepUp();
}

export async function rulePage(params: Record<string, string>): Promise<Mounted> {
  const el = h("div", {});
  let g: RuleView;
  let hosts: HostView[] = [];
  const load = async () => {
    const [rule, hostData] = await Promise.all([api<RuleView>("GET", `/api/grants/${params.id}`), api<{ items: HostView[] }>("GET", "/api/hosts")]);
    g = rule;
    hosts = hostData.items;
  };
  try {
    await load();
  } catch (e) {
    el.append(emptyState("alert", "Rule not found", (e as Error).message, h("a", { class: "btn", href: "/authority" }, "Back to Authority")));
    return { el };
  }
  const render = () => el.replaceChildren(...build(g!, hosts, async () => { await load(); render(); }));
  render();
  let t: number | undefined;
  const off = onLive((e) => {
    if (e.type !== "grants" && e.type !== "request") return;
    window.clearTimeout(t);
    t = window.setTimeout(() => void load().then(render).catch(() => {}), 300);
  });
  return { el, dispose: () => (off(), window.clearTimeout(t)) };
}

function build(g: RuleView, hosts: HostView[], reload: () => Promise<void>): HTMLElement[] {
  const s = currentSession();
  const delegation = g.kind === "delegation";
  const sc = g.scope;
  const canEdit = s.user?.role !== "viewer";
  const live = !g.revoked_at && !(g.expires_at && g.expires_at < Date.now());

  const head = h(
    "div",
    { class: "page-head" },
    h(
      "div",
      { class: "row", style: "min-width:0" },
      h("a", { href: "/authority", class: "btn ghost icon-btn", "aria-label": "Back" }, icon("back")),
      h("div", { style: "min-width:0" }, h("h1", {}, delegation ? "Delegation" : "Standing grant"), h("p", { class: "muted small" }, `Created ${timeAgo(g.created_at)} by ${g.created_by}`)),
    ),
    statusChip(g),
  );

  const actions = h("div", { class: "row wrap", style: "gap:8px; margin-top:14px" });
  if (canEdit && live) {
    if (delegation) {
      actions.append(action([icon("edit"), "Edit"], async () => editSheet(g, hosts, reload), "sm"));
      if (g.paused_at) actions.append(action([icon("play"), "Resume"], async () => { await ensureStrong(); await api("POST", `/api/grants/${g.id}/resume`, {}); toast("Delegation resumed"); await reload(); }, "sm"));
      else actions.append(action([icon("pause"), "Pause"], async () => { await api("POST", `/api/grants/${g.id}/pause`, {}); toast("Delegation paused", "info"); await reload(); }, "sm"));
    }
    actions.append(
      action([icon("stop"), delegation ? "Stop" : "Revoke"], async () => {
        const ok = await confirmSheet(delegation ? "Stop this delegation?" : "Revoke this grant?", "Matching requests will ask you again from now on.", delegation ? "Stop" : "Revoke", true);
        if (!ok) return;
        await api("POST", `/api/grants/${g.id}/revoke`, {});
        toast(delegation ? "Delegation stopped" : "Grant revoked", "info");
        await reload();
      }, "sm deny"),
    );
  }

  const facts = h(
    "dl",
    { class: "facts" },
    h("dt", {}, "Commands"),
    h("dd", {}, ...(sc?.commands.length ? sc.commands.map((c) => h("div", { class: "mono" }, c.text)) : [h("div", {}, "Any command")])),
    h("dt", {}, "Hosts"),
    h("dd", {}, hostsText(sc)),
    h("dt", {}, "Who"),
    h("dd", {}, requesterText(sc)),
    h("dt", {}, "Expires"),
    h("dd", {}, expiryText(g)),
    delegation && sc
      ? [
          h("dt", {}, "Highest risk"),
          h("dd", {}, `${sc.max_risk} · ${riskLevel(sc.max_risk!).label}`),
          h("dt", {}, "Daily limit"),
          h("dd", {}, sc.per_day ? `${sc.approved_24h} of ${sc.per_day} in the last 24 hours` : `${sc.approved_24h} in the last 24 hours, no limit`),
          h("dt", {}, "Tell me"),
          h("dd", {}, sc.notify === "each" ? "Every approval" : sc.notify === "digest" ? "A summary" : "Don't"),
        ]
      : null,
    h("dt", {}, "Used"),
    h("dd", {}, `${g.uses}${g.max_uses ? ` of ${g.max_uses}` : ""} time${g.uses === 1 ? "" : "s"}${g.last_used_at ? `, last ${timeAgo(g.last_used_at)}` : ""}`),
  );

  const main = h(
    "section",
    { class: "section" },
    h(
      "div",
      { class: "card pad" },
      delegation && sc ? h("div", { class: "intent", style: "margin-bottom:6px" }, `“${sc.intent}”`) : h("div", { class: "tl-cmd", style: "margin-bottom:6px" }, g.label),
      delegation && sc ? h("div", { class: "tiny faint", style: "margin-bottom:14px" }, sc.intent_source === "model" ? "Drafted by the model from the command, accepted by you." : sc.intent_source === "template" ? "Built from the program name." : "Written by you.") : null,
      g.pause_reason ? h("div", { class: "tip warn", style: "margin-bottom:12px" }, icon("pause"), h("div", { class: "small" }, g.pause_reason)) : null,
      facts,
      g.created_from_request ? h("a", { class: "small", style: "display:inline-block; margin-top:14px", href: `/r/${g.created_from_request}` }, "Created from a request →") : null,
      actions,
    ),
  );

  const decided = h(
    "section",
    { class: "section" },
    h("h2", {}, icon("history"), delegation ? "What it approved" : "What it allowed"),
    g.requests.length
      ? h(
          "div",
          { class: "card" },
          ...g.requests.map((r) => {
            const cls = r.state === "approved" ? (r.via === "delegation" ? "auto" : "ok") : r.state === "denied" ? "bad" : "gray";
            return h(
              "a",
              { class: "tl-item", href: `/r/${r.id}` },
              h("span", { class: ["tl-icon", cls] }, icon(r.state === "approved" ? (r.via === "delegation" ? "sparkle" : "check") : r.state === "denied" ? "x" : "clock")),
              h("div", { style: "min-width:0" }, h("div", { class: "tl-cmd" }, r.display), h("div", { class: "tl-meta" }, h("span", {}, r.host), h("span", {}, "·"), h("span", {}, r.via === "user" ? "approved by you while widening" : r.state), r.flagged ? h("span", { class: "chip bad" }, icon("flag"), "flagged") : null)),
              h("span", { class: "tiny faint nowrap" }, `${clock(r.created_at)} · ${timeAgo(r.created_at)}`),
            );
          }),
        )
      : h("div", { class: "card pad small muted" }, "Nothing yet."),
  );

  const history = h(
    "section",
    { class: "section" },
    h("h2", {}, icon("activity"), "History"),
    h(
      "div",
      { class: "card" },
      ...g.history.map((a) =>
        h(
          "div",
          { class: "tl-item" },
          h("span", { class: ["tl-icon", a.kind.endsWith("paused") || a.kind.endsWith("revoked") ? "bad" : "gray"] }, icon(a.kind.endsWith("edited") ? "edit" : a.kind.endsWith("widened") ? "plus" : a.kind.endsWith("paused") ? "pause" : "history")),
          h("div", { style: "min-width:0" }, h("div", {}, h("b", {}, HISTORY_LABEL[a.kind] ?? a.kind), h("span", { class: "faint" }, ` · ${a.actor}`)), changeSummary(a)),
          h("span", { class: "tiny faint nowrap" }, timeAgo(a.at)),
        ),
      ),
    ),
  );
  return [head, main, decided, history];
}

/** What an edit or widening changed, in a line. */
function changeSummary(a: RuleView["history"][number]): HTMLElement | null {
  const d = a.detail ?? {};
  const before = d.before;
  const after = d.after;
  if (!before || !after) return d.reason ? h("div", { class: "tl-meta" }, String(d.reason)) : null;
  const parts: string[] = [];
  if (before.intent !== after.intent) parts.push(`work: “${after.intent}”`);
  if (JSON.stringify(before.commands) !== JSON.stringify(after.commands)) parts.push(`${after.commands?.length || "any"} program filter${after.commands?.length === 1 ? "" : "s"}`);
  if (JSON.stringify(before.hosts) !== JSON.stringify(after.hosts)) parts.push(after.hosts.scope === "all" ? "all hosts" : after.hosts.scope === "groups" ? `groups ${after.hosts.groups.join(", ")}` : "one host");
  if (JSON.stringify(before.requester) !== JSON.stringify(after.requester)) parts.push(after.requester ? (after.requester.scope === "user" ? `user ${after.requester.user}` : "one session") : "anyone");
  if (before.limits?.max_risk !== after.limits?.max_risk) parts.push(`risk ≤ ${after.limits.max_risk}`);
  if (before.notify !== after.notify) parts.push(`notify: ${after.notify}`);
  if (before.per_day !== after.per_day) parts.push(`${after.per_day || "no"} daily limit`);
  if ("expires_at" in d && d.expires_at !== d.expires_before) parts.push(d.expires_at ? `ends ${new Date(d.expires_at).toLocaleDateString(undefined, { month: "short", day: "numeric" })}` : "no expiry");
  return parts.length ? h("div", { class: "tl-meta" }, parts.join(" · ")) : null;
}

function editSheet(g: RuleView, hosts: HostView[], reload: () => Promise<void>) {
  const sc = g.scope!;
  const groups = [...new Set(hosts.filter((x) => !x.revoked_at).flatMap((x) => x.groups))].sort();
  const isHost = sc.hosts.scope === "host";
  let where = sc.hosts.scope === "groups" ? "group" : sc.hosts.scope;
  const picked = new Set(sc.hosts.groups ?? []);
  const keep = new Set(sc.commands.map((_, i) => i));
  let ttl: number | null = null;
  let maxRisk = sc.max_risk!;
  let notify = sc.notify!;
  let perDay = sc.per_day!;
  const defRisk = sc.default_max_risk ?? 35;

  sheet((close) => {
    const intent = h("textarea", { class: "input", rows: "3", maxlength: "600" }, sc.intent!) as HTMLTextAreaElement;
    const groupBox = h(
      "div",
      { class: "stack tight" },
      ...groups.map((gr) => {
        const box = h("input", { type: "checkbox", checked: picked.has(gr) }) as HTMLInputElement;
        box.addEventListener("change", () => (box.checked ? picked.add(gr) : picked.delete(gr), sync()));
        return h("label", { class: "check" }, box, h("span", {}, gr));
      }),
    );
    const groupField = field("Groups", groupBox);
    const programs = sc.commands.length
      ? field(
          "Programs",
          h(
            "div",
            { class: "stack tight" },
            ...sc.commands.map((c, i) => {
              const box = h("input", { type: "checkbox", checked: true }) as HTMLInputElement;
              box.addEventListener("change", () => (box.checked ? keep.add(i) : keep.delete(i), sync()));
              return h("label", { class: "check" }, box, h("span", { class: "mono small" }, c.text));
            }),
          ),
          "Unticked programs come back to you. To cover more programs, approve one from a request and widen this rule.",
        )
      : null;
    const riskLabel = h("span", { class: "small" });
    const risk = h("input", { type: "range", min: "5", max: "60", step: "5", value: String(maxRisk), "aria-label": "Maximum risk" }) as HTMLInputElement;
    risk.addEventListener("input", () => ((maxRisk = Number(risk.value)), sync()));
    const perDayInput = h("input", { class: "input", type: "number", min: "0", max: "1000", value: String(perDay), inputmode: "numeric" }) as HTMLInputElement;
    perDayInput.addEventListener("input", () => ((perDay = Math.max(0, Math.min(1000, Number(perDayInput.value) || 0))), sync()));
    const save = h("button", { type: "button", class: "btn auto lg block" }) as HTMLButtonElement;

    // Mirrors the service: broader than before and broader than a passkey-free rule.
    const broader = () => {
      const prevGroups = sc.hosts.groups ?? [];
      const hostsBroader = where === "all" ? sc.hosts.scope !== "all" : where === "group" && (sc.hosts.scope === "host" || [...picked].some((x) => !prevGroups.includes(x)));
      const longer = ttl !== null && (ttl === 0 ? g.expires_at !== null : g.expires_at !== null && Date.now() + ttl * 60_000 > g.expires_at && ttl > 1440);
      const riskier = maxRisk > sc.max_risk! && maxRisk > defRisk;
      // 0 means no daily limit.
      const budget = (n: number) => (n === 0 ? Infinity : n);
      const busier = budget(perDay) > budget(sc.per_day!);
      return hostsBroader || longer || riskier || busier;
    };
    const sync = () => {
      groupField.classList.toggle("hidden", where !== "group");
      riskLabel.textContent = `${maxRisk} · ${riskLevel(maxRisk).label}`;
      const passkey = broader() && !strongAuthFresh();
      save.replaceChildren(passkey ? icon("fingerprint") : icon("check"), "Save changes");
    };
    const whereOptions = [
      ...(isHost ? [{ value: "host", label: sc.hosts.hosts?.[0] ?? "This host" }] : []),
      { value: "group", label: "Groups", disabled: !groups.length },
      { value: "all", label: "All hosts" },
    ];

    save.addEventListener("click", () =>
      void busy(save, async () => {
        if (intent.value.trim().length < 8) throw new Error("Describe the kind of work in a few words.");
        if (sc.commands.length && keep.size === 0) throw new Error("Keep at least one program, or stop the delegation instead.");
        if (where === "group" && picked.size === 0) throw new Error("Choose at least one group.");
        const body: Record<string, unknown> = {
          seen: g.updated_at,
          intent: intent.value.trim(),
          hosts: where,
          groups: where === "group" ? [...picked] : [],
          max_risk: maxRisk,
          notify,
          per_day: perDay,
        };
        if (sc.commands.length) body.keep_commands = [...keep].sort((a, b) => a - b);
        if (ttl !== null) body.ttl_minutes = ttl;
        if (broader()) await ensureStrong();
        const send = () => api("PATCH", `/api/delegations/${g.id}`, body);
        await send().catch(async (e) => {
          if (e instanceof ApiError && e.code === "step_up_required") {
            await stepUp();
            return send();
          }
          throw e;
        });
        toast("Delegation updated");
        close();
        await reload();
      }),
    );
    setTimeout(sync);
    return [
      h("h2", {}, "Edit delegation"),
      h("p", { class: "muted small", style: "margin-bottom:14px" }, "Narrowing a rule takes effect at once. Broadening it asks for your passkey, as creating it that way would."),
      h(
        "div",
        { class: "stack" },
        field("What this rule covers", intent, "The model approves only requests that are this kind of work."),
        programs,
        field("Hosts", segmented(whereOptions, where, (v) => ((where = v), sync()), "Hosts")),
        groupField,
        field(
          "Expiry",
          segmented([{ value: "keep", label: "Keep" }, ...DELEGATION_DURATIONS], "keep", (v) => ((ttl = v === "keep" ? null : Number(v)), sync()), "Expiry"),
          `Keep: ${g.expires_at ? `${duration((g.expires_at - Date.now()) / 1000)} left` : "no expiry"}. The others count from now.`,
        ),
        h("div", { class: "field" }, h("div", { class: "label row between" }, h("span", {}, "Highest risk it may approve"), riskLabel), risk),
        field("Most approvals a day", perDayInput, "0 means no daily limit."),
        field("Tell me", segmented([{ value: "each", label: "Every time" }, { value: "digest", label: "Summary" }, { value: "silent", label: "Don't" }], notify, (v) => ((notify = v as typeof notify), sync()))),
        save,
      ),
    ];
  }, { label: "Edit delegation" });
}

