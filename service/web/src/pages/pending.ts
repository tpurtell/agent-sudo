// Home: requests waiting for a decision.

import { api, currentSession, onLive } from "../api";
import { agentBadge, agentClaim, agentName, commandBlock, countdown, featureChips, riskMeter } from "../components";
import { h, icon, timeAgo } from "../dom";
import { needsStepUp, submitDecision } from "../decide";
import { closeNotification, pushSupport, currentSubscription } from "../push";
import type { Mounted } from "../router";
import type { RequestView } from "../types";
import { busy, emptyState, loading } from "../ui";

export function requestCard(r: RequestView, onChanged: () => void): HTMLElement {
  const s = currentSession();
  const danger = r.features.some((f) => f.level === "danger");
  const timer = countdown(r);
  const where = [r.host?.name ?? "unknown host", `${r.user} → ${r.target}`, timeAgo(r.created_at)];
  const canDecide = s.user?.role !== "viewer";
  const approveBody = { version: r.version, decision: "approve" as const };
  const stepUp = needsStepUp(r, approveBody);
  const approve = h("button", { type: "button", class: "btn approve lg" }, stepUp ? icon("fingerprint") : icon("check"), "Approve once") as HTMLButtonElement;
  const deny = h("button", { type: "button", class: "btn deny lg" }, "Deny") as HTMLButtonElement;
  approve.addEventListener("click", (e) => {
    e.preventDefault();
    void busy(approve, async () => {
      if (await submitDecision(r, approveBody)) onChanged();
      else onChanged();
    });
  });
  deny.addEventListener("click", (e) => {
    e.preventDefault();
    void busy(deny, async () => {
      await submitDecision(r, { version: r.version, decision: "deny" });
      onChanged();
    });
  });
  const card = h(
    "article",
    { class: ["req", danger && "danger"], "data-id": r.id },
    h(
      "a",
      { href: `/r/${r.id}`, class: "req-head", style: "text-decoration:none;color:inherit", "aria-label": `Review request ${r.code}` },
      agentBadge(r.session.agent),
      h("div", { class: "who-line grow" }, h("strong", {}, agentName(r.session.agent), h("span", { class: "faint", style: "font-weight:500" }, `on ${r.host?.name ?? "?"}`)), h("span", { class: "truncate" }, where.slice(1).join(" · "))),
      h("span", { class: "code-tag", title: "Matches the code shown in the terminal" }, r.code),
      timer,
    ),
    h(
      "div",
      { class: "req-body" },
      commandBlock(r, { clip: true }),
      agentClaim(r.context),
      riskMeter(r.assessment, !!s.advisor),
      featureChips(r.features, 4),
      r.class.step_up !== "none" || r.class.require_each_time
        ? h("div", { class: "policy-note" }, icon(r.class.step_up !== "none" ? "fingerprint" : "lock"), `${r.class.title}${r.class.step_up !== "none" ? " · needs your passkey" : ""}`)
        : null,
    ),
    canDecide ? h("div", { class: "req-foot" }, deny, approve) : null,
  );
  (card as any).tick = timer.tick;
  return card;
}

export async function pendingPage(): Promise<Mounted> {
  const s = currentSession();
  const list = h("div", {}, loading());
  const stats = h("div", { class: "stats" });
  const banner = h("div");
  let items: RequestView[] = [];

  const renderStats = (c: { approved_24h: number; denied_24h: number; automated_24h: number }) => {
    stats.title = "Last 24 hours";
    stats.replaceChildren(
      h("div", { class: "stat ok" }, h("b", {}, String(c.approved_24h)), h("span", {}, "Approved")),
      h("div", { class: "stat" }, h("b", {}, String(c.denied_24h)), h("span", {}, "Denied")),
      h("div", { class: "stat auto" }, h("b", {}, String(c.automated_24h)), h("span", {}, "Automated")),
    );
  };

  const load = async () => {
    const data = await api<{ items: RequestView[]; counts: any }>("GET", "/api/requests?view=pending");
    items = data.items.sort((a, b) => a.created_at - b.created_at);
    renderStats(data.counts);
    if (!items.length) {
      list.replaceChildren(
        h("div", { class: "card all-clear" }, h("div", { class: "glyph" }, icon("shieldCheck")), h("h2", {}, "All clear"), h("p", { class: "muted small" }, "No agent is waiting for sudo. New requests appear here instantly."), h("a", { href: "/activity", class: "btn sm" }, icon("history"), "Recent activity")),
      );
      return;
    }
    list.replaceChildren(...items.map((r) => requestCard(r, () => void load())));
  };

  // Nudge toward notifications when this device doesn't have them.
  const nudge = async () => {
    if (s.has_push) return;
    const support = pushSupport();
    if (!support.ok && support.reason !== "ios-needs-install") return;
    if (await currentSubscription()) return;
    banner.replaceChildren(
      h("a", { class: "banner", href: "/settings#device", style: "text-decoration:none;color:inherit" }, icon("bell"), h("div", { class: "grow" }, h("b", {}, "Turn on notifications"), h("div", { class: "small muted" }, support.ok ? "Get an alert on this device when an agent needs sudo." : "Add agent-sudo to your Home Screen to receive alerts.")), icon("chevron")),
    );
  };

  if (s.automation.enabled) {
    void api<{ items: any[] }>("GET", "/api/grants").then((g) => {
      const live = g.items.filter((x) => x.kind === "delegation" && x.active);
      if (live.length) {
        banner.prepend(h("a", { class: "banner auto", href: "/authority", style: "text-decoration:none;color:inherit" }, icon("sparkle"), h("div", { class: "grow" }, h("b", {}, `${live.length} active delegation${live.length > 1 ? "s" : ""}`), h("div", { class: "small muted" }, live.map((d) => d.label).join(" · "))), icon("chevron")));
      }
    });
  }

  const tick = window.setInterval(() => list.querySelectorAll<HTMLElement>(".req").forEach((c) => (c as any).tick?.()), 1000);
  let reloadTimer: number | undefined;
  const off = onLive((e) => {
    if (e.type !== "request") return;
    if (e.state && e.state !== "pending") void closeNotification(e.id);
    window.clearTimeout(reloadTimer);
    reloadTimer = window.setTimeout(() => void load(), 120);
  });
  await load().catch((e) => list.replaceChildren(emptyState("alert", "Couldn't load requests", String(e.message))));
  void nudge();

  const el = h(
    "div",
    {},
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Requests"), h("p", { class: "muted small" }, "Privileged commands waiting for you."))),
    banner,
    stats,
    list,
  );
  return {
    el,
    dispose: () => {
      off();
      window.clearInterval(tick);
      window.clearTimeout(reloadTimer);
    },
  };
}
