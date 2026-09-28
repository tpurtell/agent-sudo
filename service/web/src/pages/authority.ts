// Standing grants, delegations, and the automation kill switch.

import { api, currentSession, loadSession, onLive } from "../api";
import { riskLevel } from "../components";
import { DEFAULT_DELEGATION_MINUTES, DELEGATION_DURATIONS, duration, h, icon, timeAgo } from "../dom";
import type { Mounted } from "../router";
import type { GrantView, HostView } from "../types";
import { action, confirmSheet, emptyState, field, loading, segmented, sheet, toast, toggle, busy } from "../ui";
import { stepUp } from "../webauthn";
import { strongAuthFresh } from "../api";

function remaining(g: GrantView): { text: string; pct: number } {
  if (!g.expires_at) return { text: "no expiry", pct: 100 };
  const left = g.expires_at - Date.now();
  const total = g.expires_at - g.created_at;
  return { text: left > 0 ? `${duration(left / 1000)} left` : `ended ${timeAgo(g.expires_at)}`, pct: Math.max(0, Math.min(100, (left / total) * 100)) };
}

async function ensureStrong() {
  if (!strongAuthFresh()) await stepUp();
}

function grantRow(g: GrantView, reload: () => void): HTMLElement {
  const rem = remaining(g);
  const ended = !g.active;
  const status = g.revoked_at
    ? h("span", { class: "chip" }, `revoked by ${g.revoked_by}`)
    : g.paused_at
      ? h("span", { class: "chip warn" }, icon("pause"), "paused")
      : ended
        ? h("span", { class: "chip" }, "ended")
        : h("span", { class: ["chip", g.kind === "delegation" ? "auto" : "ok"] }, "active");
  const spec = g.spec ?? {};
  const actions = h("div", { class: "row", style: "gap:6px" });
  if (!g.revoked_at && !(g.expires_at && g.expires_at < Date.now())) {
    if (g.kind === "delegation") {
      if (g.paused_at) {
        actions.append(action([icon("play"), "Resume"], async () => { await ensureStrong(); await api("POST", `/api/grants/${g.id}/resume`, {}); toast("Delegation resumed"); reload(); }, "sm"));
      } else {
        actions.append(action([icon("pause"), "Pause"], async () => { await api("POST", `/api/grants/${g.id}/pause`, {}); toast("Delegation paused", "info"); reload(); }, "sm"));
      }
    }
    actions.append(
      action([icon("stop"), g.kind === "delegation" ? "Stop" : "Revoke"], async () => {
        const ok = await confirmSheet(g.kind === "delegation" ? "Stop this delegation?" : "Revoke this grant?", "Matching requests will ask you again from now on.", g.kind === "delegation" ? "Stop" : "Revoke", true);
        if (!ok) return;
        await api("POST", `/api/grants/${g.id}/revoke`, {});
        toast(g.kind === "delegation" ? "Delegation stopped" : "Grant revoked", "info");
        reload();
      }, "sm deny"),
    );
  }
  const limit = g.kind === "delegation" && spec.limits ? `max risk ${spec.limits.max_risk} (${riskLevel(spec.limits.max_risk).label.toLowerCase()})` : "";
  return h(
    "div",
    { class: ["grant", g.kind, ended && "ended"] },
    h("div", { class: "row between top" }, h("div", { style: "min-width:0" }, g.kind === "delegation" ? h("div", { class: "intent" }, `“${g.label}”`) : h("div", { class: "tl-cmd" }, g.label), h("div", { class: "tiny faint", style: "margin-top:3px" }, g.summary)), status),
    ended ? null : h("div", { class: "ttl" }, h("i", { style: `width:${rem.pct}%` })),
    h(
      "div",
      { class: "row between wrap" },
      h("span", { class: "tiny faint" }, [rem.text, `${g.uses}${g.max_uses ? `/${g.max_uses}` : ""} ${g.kind === "delegation" ? "approved" : g.uses === 1 ? "use" : "uses"}`, `by ${g.created_by}`, limit].filter(Boolean).join(" · ")),
      actions,
    ),
    g.pause_reason ? h("div", { class: "small", style: "color:var(--warn)" }, g.pause_reason) : null,
    g.created_from_request ? h("a", { class: "tiny faint", href: `/r/${g.created_from_request}` }, "Created from a request →") : null,
  );
}

function newDelegationSheet(hosts: HostView[], reload: () => void) {
  const groups = [...new Set(hosts.flatMap((h) => h.groups))];
  let scope: "all" | "group" | "host" = groups.length ? "group" : "all";
  let group = groups[0] ?? "";
  let host = hosts.find((x) => !x.revoked_at)?.id ?? "";
  let ttl = DEFAULT_DELEGATION_MINUTES;
  let maxRisk = 30;
  let notify = "each";
  sheet((close) => {
    const intent = h("textarea", { class: "input", rows: "3", placeholder: "e.g. Upgrading CUDA and rebuilding the NCCL plugin on the sparks" }) as HTMLTextAreaElement;
    const programs = h("input", { class: "input mono", placeholder: "/usr/bin/apt /usr/bin/dpkg", autocapitalize: "off", autocorrect: "off", spellcheck: "false" }) as HTMLInputElement;
    const groupSel = h("select", { class: "input" }, ...groups.map((g) => h("option", { value: g }, g))) as HTMLSelectElement;
    groupSel.addEventListener("change", () => (group = groupSel.value));
    const hostSel = h("select", { class: "input" }, ...hosts.filter((x) => !x.revoked_at).map((x) => h("option", { value: x.id }, x.name))) as HTMLSelectElement;
    hostSel.addEventListener("change", () => (host = hostSel.value));
    const groupField = field("Group", groupSel);
    const hostField = field("Host", hostSel);
    const syncScope = () => {
      groupField.classList.toggle("hidden", scope !== "group");
      hostField.classList.toggle("hidden", scope !== "host");
    };
    const riskLabel = h("span", { class: "small" }, `${maxRisk} · ${riskLevel(maxRisk).label}`);
    const risk = h("input", { type: "range", min: "10", max: "60", step: "5", value: String(maxRisk) }) as HTMLInputElement;
    risk.addEventListener("input", () => {
      maxRisk = Number(risk.value);
      riskLabel.textContent = `${maxRisk} · ${riskLevel(maxRisk).label}`;
    });
    const create = h("button", { type: "button", class: "btn auto lg block" }, icon("sparkle"), "Start delegation") as HTMLButtonElement;
    create.addEventListener("click", () =>
      void busy(create, async () => {
        if (intent.value.trim().length < 8) throw new Error("Describe the work in a sentence.");
        await ensureStrong();
        await api("POST", "/api/delegations", {
          intent: intent.value.trim(),
          ttl_minutes: ttl,
          hosts: scope,
          groups: scope === "group" ? [group] : [],
          host_id: scope === "host" ? host : null,
          requester: "any",
          max_risk: maxRisk,
          notify,
          programs: programs.value.split(/[\s,]+/).filter(Boolean),
        });
        toast("Delegation started");
        close();
        reload();
      }),
    );
    setTimeout(syncScope);
    return [
      h("h2", {}, "New delegation"),
      h("p", { class: "muted small", style: "margin-bottom:14px" }, "The decision model may approve requests that fit this work, within these limits. Root shells, credentials, and changes to sudo always come back to you."),
      h(
        "div",
        { class: "stack" },
        field("Expected work", intent, "The model judges each request against this description."),
        field("Programs", programs, "Optional absolute paths, separated by spaces. Only these programs are considered; leave empty for any command."),
        field("Hosts", segmented([{ value: "group", label: "A group", disabled: !groups.length }, { value: "host", label: "One host" }, { value: "all", label: "All hosts" }], scope, (v) => { scope = v as typeof scope; syncScope(); })),
        groupField,
        hostField,
        field("Duration", segmented(DELEGATION_DURATIONS, String(ttl), (v) => (ttl = Number(v)))),
        h("div", { class: "field" }, h("div", { class: "label row between" }, h("span", {}, "Highest risk it may approve"), riskLabel), risk),
        field("Notifications", segmented([{ value: "each", label: "Every approval" }, { value: "digest", label: "Summary" }, { value: "silent", label: "None" }], notify, (v) => (notify = v))),
        create,
      ),
    ];
  }, { label: "New delegation" });
}

export async function authorityPage(): Promise<Mounted> {
  const s = currentSession();
  const body = h("div", {}, loading());
  let hosts: HostView[] = [];

  const load = async () => {
    const [data, hostData] = await Promise.all([
      api<{ items: GrantView[]; automation: { enabled: boolean; configured: boolean } }>("GET", "/api/grants"),
      api<{ items: HostView[] }>("GET", "/api/hosts"),
    ]);
    hosts = hostData.items;
    const delegations = data.items.filter((g) => g.kind === "delegation");
    const grants = data.items.filter((g) => g.kind === "grant");
    const activeDelegations = delegations.filter((g) => g.active);
    const auto = data.automation;

    const kill = h(
      "div",
      { class: ["killswitch", auto.enabled && activeDelegations.length > 0 && "on"] },
      h("div", { class: "kicon" }, icon("sparkle")),
      h(
        "div",
        { class: "grow" },
        h("h3", {}, "Automated decisions"),
        h("p", { class: "small muted" }, !auto.configured ? "Disabled in the service configuration." : !s.advisor ? "No decision model is configured." : auto.enabled ? `${activeDelegations.length} active delegation${activeDelegations.length === 1 ? "" : "s"}. Switch off to stop all of them at once.` : "Off. Delegations are kept but nothing is approved automatically."),
      ),
      auto.configured
        ? toggle(auto.enabled, async (v) => {
            try {
              if (v) await ensureStrong();
              await api("POST", "/api/settings/automation", { enabled: v });
              await loadSession();
              toast(v ? "Automation on" : "Automation stopped", v ? "ok" : "info");
            } catch (e) {
              toast((e as Error).message, "bad");
            }
            void load();
          }, "auto", "Automated decisions")
        : null,
    );

    const canDelegate = !!s.advisor && auto.enabled && s.user?.role !== "viewer";
    const renderList = (rows: GrantView[], emptyText: string) => {
      const active = rows.filter((g) => g.active || g.paused_at);
      const ended = rows.filter((g) => !g.active && !g.paused_at);
      if (!rows.length) return h("div", { class: "card pad small muted" }, emptyText);
      return h(
        "div",
        { class: "stack" },
        active.length ? h("div", { class: "card" }, ...active.map((g) => grantRow(g, () => void load()))) : h("div", { class: "card pad small muted" }, "Nothing active."),
        ended.length ? h("details", { class: "more" }, h("summary", {}, icon("chevron"), `Ended in the last day (${ended.length})`), h("div", { class: "card", style: "margin-top:10px" }, ...ended.map((g) => grantRow(g, () => void load())))) : null,
      );
    };

    body.replaceChildren(
      kill,
      h(
        "section",
        { class: "section" },
        h("h2", {}, icon("sparkle"), "Delegations", h("span", { class: "grow" }), canDelegate ? h("button", { type: "button", class: "btn sm", onclick: () => newDelegationSheet(hosts, () => void load()) }, icon("plus"), "New") : null),
        h("p", { class: "section-note small muted" }, "Bounded authority for the decision model: an intent, a scope, a time limit, and a risk ceiling."),
        renderList(delegations, "No delegations yet. Create one here, or from a request with “Let the model handle similar requests”."),
      ),
      h(
        "section",
        { class: "section" },
        h("h2", {}, icon("key"), "Standing grants"),
        h("p", { class: "section-note small muted" }, "Exact approvals you chose to remember: a command, where, for whom, and for how long."),
        renderList(grants, "No standing grants. Choose “This command” when approving to create one."),
      ),
    );
  };
  await load().catch((e) => body.replaceChildren(emptyState("alert", "Couldn't load", String(e.message))));
  let t: number | undefined;
  const off = onLive((e) => {
    if (e.type === "grants" || e.type === "settings") {
      window.clearTimeout(t);
      t = window.setTimeout(() => void load(), 150);
    }
  });
  const tick = window.setInterval(() => void 0, 60_000);
  return {
    el: h("div", {}, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Authority"), h("p", { class: "muted small" }, "What can run without asking you, and why."))), body),
    dispose: () => (off(), window.clearTimeout(t), window.clearInterval(tick)),
  };
}
