// A single request: context, analysis, history, and the decision builder.

import { api, currentSession, onLive } from "../api";
import {
  agentBadge,
  agentClaim,
  agentName,
  commandBlock,
  countdown,
  dimensions,
  featureChips,
  outcomeBanner,
  riskLevel,
  riskMeter,
  stateIcon,
} from "../components";
import { type DecisionBody, needsStepUp, submitDecision } from "../decide";
import { basename, combineIntents, delegationLength, h, icon, minutesLabel, snapDelegation, timeAgo, clock, DELEGATION_DURATIONS } from "../dom";
import { type Mounted, navigate } from "../router";
import type { RequestView } from "../types";
import { action, busy, confirmSheet, emptyState, field, segmented, toast, type Option } from "../ui";

const TTL_CHOICES = [10, 30, 60, 240, 480];

/** Why a request can't become a standing approval, mirroring the service's rule. */
function ungrantable(r: RequestView): string | null {
  if (r.lossy) return "Some arguments aren't valid UTF-8, so this can only be approved once.";
  const has = (k: string) => r.features.some((f) => f.key === k);
  if (has("user_symlink")) return "A path goes through a symlink the requester controls, so this can only be approved once.";
  if (has("unverified_executable")) return "The host couldn't verify the executable, so this can only be approved once.";
  return null;
}

export async function requestPage(params: Record<string, string>): Promise<Mounted> {
  const el = h("div", {});
  let r: RequestView;
  try {
    r = await api<RequestView>("GET", `/api/requests/${params.id}`);
  } catch (e) {
    el.append(emptyState("alert", "Request not found", (e as Error).message, h("a", { class: "btn", href: "/" }, "Back to requests")));
    return { el };
  }
  let timer: number | undefined;
  let draft: Draft | null = null;

  const render = () => {
    // Until the approver changes something, follow the latest suggestion.
    const keep = draft?.touched ? draft : null;
    el.replaceChildren(...build(r, keep, (d) => (draft = d), reload));
  };
  const reload = async () => {
    r = await api<RequestView>("GET", `/api/requests/${params.id}`);
    render();
  };
  render();
  timer = window.setInterval(() => el.querySelectorAll<HTMLElement>(".countdown").forEach((c) => (c as any).tick?.()), 1000);
  const off = onLive((e) => {
    if (e.type === "request" && (e.id === r.id || e.id === "*")) void reload();
  });
  return { el, dispose: () => (off(), window.clearInterval(timer)) };
}

/** The rows of the Remember card. */
type Row = "once" | "exact" | "kind" | "any" | "prefix-grant" | "program-grant";
type Where = string; // "host" | "all" | `group:${name}`
type Filter = "program" | "prefix" | "exact";

interface Draft {
  touched: boolean;
  row: Row;
  // Plain grants (exact, prefix-grant, program-grant)
  prefixLen: number;
  where: Where;
  requester: "session" | "user";
  ttl: number;
  // Delegated rules (kind, any)
  widen: boolean;
  filter: Filter;
  rulePrefixLen: number;
  intent: string;
  anyIntent: string;
  ruleTtl: number;
  ruleWhere: Where;
  ruleRequester: "session" | "user" | "any";
  maxRisk: number;
  notify: "each" | "digest" | "silent";
  refresh: boolean;
  note: string;
  hard: boolean;
}

function whereFromSuggestion(r: RequestView, hosts: string | undefined): Where {
  if (hosts === "all") return "all";
  const g = r.host?.default_group ?? r.host?.groups[0];
  if (hosts === "group" && g) return `group:${g}`;
  return "host";
}

function templateIntent(r: RequestView): string {
  const kind = r.class.name === "default" ? "routine use" : `routine ${r.class.title.toLowerCase()}`;
  return `${basename(r.command)}: ${kind}`;
}

function capabilities(r: RequestView) {
  const s = currentSession();
  const maxTtl = r.class.max_ttl_minutes;
  const why = ungrantable(r);
  const grantsAllowed = !r.class.require_each_time && maxTtl > 0 && why === null && r.mode === "run" && !!r.command;
  const canDelegate = !!s.advisor && s.automation.enabled && r.class.delegable && !r.lossy && why === null;
  return { maxTtl, why, grantsAllowed, canDelegate, rules: canDelegate && grantsAllowed };
}

function initialDraft(r: RequestView): Draft {
  const a = r.assessment.assessment;
  const sug = a?.suggestion;
  const { maxTtl, grantsAllowed, rules } = capabilities(r);
  const defMax = currentSession().automation.default_max_risk ?? 35;
  const approveIt = sug?.decision === "approve" && (a?.risk ?? 100) <= defMax;
  const remember = sug?.remember ?? (sug?.command === "executable" ? "program" : sug?.command) ?? "once";
  let row: Row = "once";
  if (grantsAllowed && approveIt && remember !== "once") {
    if (rules) row = remember === "exact" ? "exact" : "kind";
    else row = remember === "exact" ? "exact" : remember === "prefix" ? "prefix-grant" : "program-grant";
  }
  const drafted = sug?.intent || templateIntent(r);
  const ttl = Math.min(sug?.ttl_minutes || 30, maxTtl) || 30;
  const ruleWhere = whereFromSuggestion(r, sug?.hosts);
  return {
    touched: false,
    row,
    prefixLen: Math.max(1, Math.min(sug?.prefix_len || 1, r.argv.length)),
    where: whereFromSuggestion(r, sug?.hosts),
    requester: sug?.hosts && sug.hosts !== "host" ? "user" : (sug?.requester ?? "session"),
    ttl: TTL_CHOICES.filter((t) => t <= maxTtl).reduce((best, t) => (Math.abs(t - ttl) < Math.abs(best - ttl) ? t : best), TTL_CHOICES[0]!),
    widen: !!r.widen,
    filter: remember === "prefix" && r.argv.length ? "prefix" : "program",
    rulePrefixLen: Math.max(1, Math.min(sug?.prefix_len || 1, r.argv.length)),
    intent: r.widen ? combineIntents(r.widen.intent, drafted) : drafted,
    anyIntent: "",
    ruleTtl: snapDelegation(sug?.duration_minutes),
    ruleWhere,
    // Rules follow the unix user across agent sessions by default.
    ruleRequester: "user",
    maxRisk: defMax,
    notify: "each",
    refresh: r.mode === "validate",
    note: "",
    hard: r.class.hard_deny,
  };
}

function build(r: RequestView, keep: Draft | null, save: (d: Draft) => void, reload: () => Promise<void>): HTMLElement[] {
  const s = currentSession();
  const pending = r.state === "pending";
  const st = stateIcon(r);
  const head = h(
    "div",
    { class: "page-head" },
    h(
      "div",
      { class: "row" },
      h("a", { href: "/", class: "btn ghost icon-btn", "aria-label": "Back" }, icon("back")),
      h("div", {}, h("h1", { class: "row", style: "gap:10px" }, "Request", h("span", { class: "code-tag" }, r.code)), h("p", { class: "muted small" }, `${clock(r.created_at)} · ${timeAgo(r.created_at)}`)),
    ),
    pending ? countdown(r) : h("span", { class: ["chip", st.cls === "warn" ? "warn" : st.cls === "gray" ? "" : st.cls] }, icon(st.glyph), st.label),
  );

  const who = h(
    "div",
    { class: "row", style: "padding-bottom:4px" },
    agentBadge(r.session.agent),
    h("div", { class: "who-line grow" }, h("strong", {}, agentName(r.session.agent), h("span", { class: "faint", style: "font-weight:500" }, `on ${r.host?.name ?? "?"}`)), h("span", {}, r.session.label)),
  );

  const facts = h(
    "dl",
    { class: "facts" },
    h("dt", {}, "Host"),
    h("dd", {}, r.host?.name ?? "?", ...(r.host?.groups ?? []).map((g) => h("span", { class: "chip plain", style: "margin-left:6px" }, g))),
    h("dt", {}, "Runs as"),
    h("dd", {}, `${r.target}`, h("span", { class: "faint" }, ` (uid ${r.target_uid}), requested by ${r.user}`)),
    r.cwd ? [h("dt", {}, "Directory"), h("dd", { class: "mono" }, r.cwd)] : null,
    r.chdir ? [h("dt", {}, "Changes to"), h("dd", { class: "mono" }, r.chdir)] : null,
    r.env?.length ? [h("dt", {}, "Environment"), h("dd", { class: "mono" }, ...r.env.map((v) => h("div", {}, v)))] : null,
    r.executable && (r.executable.real_path !== r.command || r.executable.writable_by_requester || r.executable.owner_uid !== 0)
      ? [
          h("dt", {}, "Executable"),
          h(
            "dd",
            {},
            h("span", { class: "mono" }, r.executable.real_path),
            r.executable.writable_by_requester ? h("div", { class: "small", style: "color:var(--bad)" }, "The requester can modify this file") : null,
            r.executable.owner_uid !== 0 ? h("div", { class: "small", style: "color:var(--bad)" }, `Owned by uid ${r.executable.owner_uid}, not root`) : null,
          ),
        ]
      : null,
    r.paths?.some((p) => p.resolved !== p.given)
      ? [
          h("dt", {}, "Paths"),
          h(
            "dd",
            { class: "stack tight" },
            ...r.paths
              .filter((p) => p.resolved !== p.given)
              .map((p) => h("div", { class: "small" }, h("span", { class: "mono" }, p.given), " → ", h("span", { class: "mono" }, p.resolved), p.user_symlink ? h("span", { class: "chip warn", style: "margin-left:6px" }, "your symlink") : null)),
          ),
        ]
      : null,
    h("dt", {}, "Terminal"),
    h("dd", {}, r.interactive ? `Yes (${r.tty ?? "tty"}), password also accepted` : "No, waiting only for you"),
    h("dt", {}, "Session"),
    h("dd", {}, r.session.label, r.session.ssh ? h("span", { class: "chip plain", style: "margin-left:6px" }, "ssh") : null, h("div", { class: "tiny faint mono" }, r.session.fingerprint)),
    h("dt", {}, "Policy"),
    h("dd", {}, r.class.title, h("span", { class: "faint" }, ` · ${r.class.name}`)),
  );

  const chain = r.session.chain?.length
    ? h("details", { class: "more" }, h("summary", {}, icon("chevron"), "Process ancestry"), h("div", { class: "chain", style: "margin-top:8px" }, ...r.session.chain.map((p) => h("div", { title: p.cmdline }, h("b", {}, p.name), ` ${p.pid} · ${p.cmdline}`))))
    : null;

  const main = h(
    "section",
    { class: "card pad stack" },
    who,
    commandBlock(r),
    r.lossy ? h("div", { class: "tip warn" }, icon("alert"), h("div", { class: "small" }, "Some arguments were not valid UTF-8 and are shown approximately. Standing approvals are disabled for this request.")) : null,
    agentClaim(r.context),
    featureChips(r.features, 12),
    h("div", { class: "divider", style: "margin:4px 0" }),
    facts,
    chain,
  );

  const out: HTMLElement[] = [head];
  const outcome = outcomeBanner(r);
  if (outcome) out.push(h("div", { style: "margin-bottom:14px" }, outcome));
  if (r.state === "approved" && r.decision?.decision.via === "delegation") {
    out.push(
      h(
        "div",
        { class: "row", style: "margin:-4px 0 14px;justify-content:flex-end" },
        r.flagged_at
          ? h("span", { class: "chip bad" }, icon("flag"), `Flagged ${timeAgo(r.flagged_at)}; delegation paused`)
          : action(
              [icon("flag"), "This shouldn't have been approved"],
              async () => {
                const ok = await confirmSheet("Flag this approval?", "The delegation that approved it will pause immediately, and the flag becomes part of the model's history.", "Flag and pause", true);
                if (!ok) return;
                await api("POST", `/api/requests/${r.id}/flag`, {});
                toast("Flagged; the delegation is paused", "info");
                await reload();
              },
              "sm deny",
            ),
      ),
    );
  }
  out.push(main);
  const analysis = analysisCard(r, reload);
  if (analysis) out.push(analysis);
  const history = historyCard(r);
  if (history) out.push(history);
  if (pending && s.user?.role !== "viewer") out.push(...decisionBuilder(r, keep ?? initialDraft(r), save, reload));
  return out;
}

function analysisCard(r: RequestView, reload: () => Promise<void>): HTMLElement | null {
  const s = currentSession();
  const stored = r.assessment;
  if (!s.advisor && !stored.assessment && !stored.delegation_check) return null;
  const a = stored.assessment;
  const body = h("div", { class: "stack" });
  const meter = riskMeter(stored, !!s.advisor);
  if (meter) body.append(meter);
  if (a) {
    if (a.summary) body.append(h("p", { class: "ai-summary" }, a.summary));
    if (a.reasons.length) body.append(h("ul", { class: "reasons" }, ...a.reasons.map((x) => h("li", {}, x))));
    const sug = a.suggestion;
    const remember = sug.remember ?? (sug.command === "executable" ? "program" : sug.command);
    const where = sug.hosts === "host" ? `on ${r.host?.name ?? "this host"}` : sug.hosts === "group" ? `on the ${r.host?.default_group ?? "host's"} group` : "on all hosts";
    const sugText =
      sug.decision === "approve"
        ? remember === "once"
          ? "Approve once"
          : remember === "exact"
            ? `Remember this exact command ${where} for ${minutesLabel(sug.ttl_minutes)}`
            : `Delegate “${sug.intent || basename(r.command)}” ${where} ${delegationLength(sug.duration_minutes ?? 1440)}`
        : sug.decision === "deny"
          ? "Deny"
          : "Look closely before deciding";
    body.append(h("div", { class: "row small", style: "align-items:flex-start" }, h("span", { class: "chip auto" }, icon("sparkle"), "Suggested"), h("span", {}, sugText)));
    body.append(h("details", { class: "more" }, h("summary", {}, icon("chevron"), "Risk dimensions"), h("div", { style: "margin-top:10px" }, dimensions(a))));
    if (a.clamped.length) {
      body.append(h("div", { class: "tip warn" }, icon("shield"), h("div", { class: "small" }, h("b", {}, "Policy adjusted the model's answer. "), a.clamped.join(". "), ".")));
    }
    body.append(h("div", { class: "tiny faint" }, `${a.model} · ${a.backend} · ${(a.latency_ms / 1000).toFixed(1)}s${a.cost_usd ? ` · $${a.cost_usd.toFixed(5)}` : ""}${a.model_risk !== a.risk ? ` · model said ${a.model_risk}` : ""}`));
  } else if (stored.failure) {
    body.append(h("div", { class: "tip warn" }, icon("alert"), h("div", { class: "small" }, `The decision model couldn't assess this request: ${stored.failure.error}`)));
  }
  const checks = stored.delegation_checks?.length ? stored.delegation_checks : stored.delegation_check ? [stored.delegation_check] : [];
  for (const check of checks) {
    const fit = check.relevance !== undefined && check.relevance !== null ? ` · same kind of work ${Math.round(check.relevance * 100)}%` : "";
    body.append(
      h(
        "div",
        { class: ["outcome", check.approved ? "auto" : "gray"] },
        icon("sparkle"),
        h(
          "div",
          {},
          check.approved ? `Rule “${check.label}” approved this` : `Rule “${check.label}” handed this to you`,
          h("small", {}, [...check.reasons, ...(fit && !check.reasons.some((x) => x.includes("kind of work")) ? [fit.slice(3)] : [])].join(" · ")),
        ),
      ),
    );
  }
  const rerun =
    s.advisor && r.state === "pending" && !stored.running
      ? action([icon("refresh"), "Re-assess"], async () => {
          await api("POST", `/api/requests/${r.id}/assess`, {});
          toast("Asking the model again…", "info");
          setTimeout(() => void reload(), 500);
        }, "sm ghost")
      : null;
  return h(
    "section",
    { class: "section" },
    h("h2", {}, icon("sparkle"), "Decision assistant", h("span", { class: "grow" }), rerun),
    h("div", { class: "ai-box" }, body),
  );
}

function historyCard(r: RequestView): HTMLElement | null {
  if (!r.related?.length) return null;
  const hosts = [...new Set(r.related.filter((x) => x.state === "approved").map((x) => x.host))];
  return h(
    "section",
    { class: "section" },
    h("h2", {}, icon("history"), "Same command recently"),
    hosts.length ? h("p", { class: "section-note small muted" }, `Approved on ${hosts.join(", ")} in the last day.`) : null,
    h(
      "div",
      { class: "card list" },
      ...r.related.map((x) => {
        const cls = x.state === "approved" ? (x.via === "delegation" ? "auto" : "ok") : x.state === "denied" ? "bad" : "gray";
        return h(
          "a",
          { class: "item", href: `/r/${x.id}` },
          h("span", { class: ["tl-icon", cls] }, icon(x.state === "approved" ? (x.via === "delegation" ? "sparkle" : "check") : x.state === "denied" ? "x" : "clock")),
          h("div", { class: "grow" }, h("div", {}, `${x.state} on ${x.host}`), h("div", { class: "tiny faint" }, `${x.by ?? x.via ?? ""}${x.same_session ? " · same session" : ""}`)),
          h("span", { class: "tiny faint nowrap" }, timeAgo(x.created_at)),
        );
      }),
    ),
  );
}

function whereOptions(r: RequestView): Option<Where>[] {
  const groups = [...(r.host?.groups ?? [])].sort((a, b) => (a === r.host?.default_group ? -1 : b === r.host?.default_group ? 1 : 0));
  return [
    { value: "host", label: r.host?.name ?? "This host" },
    ...groups.map((g) => ({ value: `group:${g}`, label: g, sub: "group" })),
    { value: "all", label: "All hosts" },
  ];
}

function whereWords(r: RequestView, w: Where): string {
  if (w === "all") return "all hosts";
  if (w.startsWith("group:")) return `the ${w.slice(6)} group`;
  return r.host?.name ?? "this host";
}

function whereBody(w: Where): { hosts: string; groups?: string[] } {
  if (w.startsWith("group:")) return { hosts: "group", groups: [w.slice(6)] };
  return { hosts: w };
}

function decisionBuilder(r: RequestView, d: Draft, save: (d: Draft) => void, reload: () => Promise<void>): HTMLElement[] {
  const { maxTtl, why, grantsAllowed, rules } = capabilities(r);
  const sug = r.assessment.assessment?.suggestion;
  const suggestedRow = initialDraft(r).row;
  const program = basename(r.command);
  const update = (patch: Partial<Draft>, rerender = false) => {
    Object.assign(d, patch, { touched: true });
    save(d);
    if (rerender) paint();
    else sync();
  };

  // ---- The Remember card: one radio row per choice, its scope written under it.
  const who = (req: string) => (req === "session" ? "this session" : req === "user" ? `any session of ${r.user}` : "anyone");
  const filterWords = (f: Filter, n: number) =>
    f === "program" ? `${program}, any arguments` : f === "prefix" ? `${program} ${r.argv.slice(0, n).join(" ")} …` : `${program} ${r.argv.join(" ")}`.trim();
  const grantLen = (t: number) => (t < 60 ? `${t} min` : minutesLabel(t));
  const rows: { value: Row; title: string; sub: () => string; disabled?: boolean; hidden?: boolean }[] = [
    { value: "once", title: "Just once", sub: () => "Nothing is remembered" },
    {
      value: "exact",
      title: "Exactly this command",
      sub: () => `${whereWords(r, d.where)} · ${who(d.requester)} · ${grantLen(d.ttl)}`,
      disabled: !grantsAllowed,
    },
    {
      value: "kind",
      title: d.widen && r.widen ? `Add to “${r.widen.label}”` : "This kind of work",
      sub: () =>
        `${filterWords(d.filter, d.rulePrefixLen)} · ${whereWords(r, d.ruleWhere)} · ${who(d.ruleRequester)} · ${delegationLength(d.ruleTtl)}${d.widen && r.widen?.paused ? " · resumes it" : ""}`,
      hidden: !rules,
    },
    {
      value: "any",
      title: "Anything this agent does",
      // Until it is chosen, show the defaults it would start with.
      sub: () =>
        d.row === "any"
          ? `any command · ${whereWords(r, d.ruleWhere)} · ${who(d.ruleRequester)} · ${delegationLength(d.ruleTtl)} · risk ≤ ${d.maxRisk}`
          : `any command · ${r.host?.name ?? "this host"} · this session · for an hour · risk ≤ ${d.maxRisk}`,
      hidden: !rules,
    },
    {
      value: "prefix-grant",
      title: "This command prefix",
      sub: () => `${program} ${r.argv.slice(0, d.prefixLen).join(" ")} … · ${whereWords(r, d.where)} · ${grantLen(d.ttl)}`,
      disabled: !grantsAllowed || r.argv.length === 0,
      hidden: rules,
    },
    {
      value: "program-grant",
      title: "This program, any arguments",
      sub: () => `${program} · ${whereWords(r, d.where)} · ${who(d.requester)} · ${grantLen(d.ttl)}`,
      disabled: !grantsAllowed,
      hidden: rules,
    },
  ];
  const choiceEls = rows
    .filter((x) => !x.hidden)
    .map((x) => {
      const subEl = h("span", { class: "choice-sub" });
      const btn = h(
        "button",
        { type: "button", role: "radio", class: "choice", disabled: x.disabled, "data-row": x.value },
        h("span", { class: "choice-dot", "aria-hidden": "true" }),
        h(
          "span",
          { class: "choice-text" },
          h("span", { class: "choice-title" }, x.title, x.value === suggestedRow && x.value !== "once" ? h("span", { class: "chip auto tiny-chip" }, icon("sparkle"), "Suggested") : null),
          subEl,
        ),
      ) as HTMLButtonElement;
      btn.addEventListener("click", () => {
        if (x.disabled) return;
        const patch: Partial<Draft> = { row: x.value };
        // "Anything" is session-bound and short unless the approver widens it.
        if (x.value === "any" && d.row !== "any") Object.assign(patch, { ruleRequester: "session", ruleTtl: 60, ruleWhere: "host" });
        if (x.value === "kind" && d.row === "any") Object.assign(patch, { ruleRequester: "user", ruleTtl: snapDelegation(sug?.duration_minutes) });
        update(patch, true);
      });
      return { row: x, btn, subEl };
    });
  const choices = h("div", { class: "choices", role: "radiogroup", "aria-label": "Remember" }, ...choiceEls.map((c) => c.btn));

  // ---- Details for the selected row
  const detail = h("div", { class: "stack" });

  const card = h(
    "section",
    { class: "section" },
    h("h2", {}, icon("key"), "Remember"),
    h(
      "div",
      { class: "card pad scope" },
      !grantsAllowed ? h("p", { class: "hint", style: "margin:0" }, r.class.require_each_time ? `${r.class.title} always needs a fresh decision.` : (why ?? "This request can only be approved once.")) : null,
      choices,
      detail,
      advancedOptions(r, d, update),
    ),
  );

  function ruleDetail(): HTMLElement[] {
    const kind = d.row === "kind";
    const intentValue = kind ? d.intent : d.anyIntent;
    const intent = h("textarea", { class: "input", rows: "2", maxlength: "600", placeholder: kind ? `${program}: what kind of work` : "e.g. Benchmarking the new inference build" }, intentValue) as HTMLTextAreaElement;
    intent.addEventListener("input", () => update(kind ? { intent: intent.value } : { anyIntent: intent.value }));
    const source =
      !kind
        ? "Your words. Without a program filter the model judges every command against this, so be specific."
        : d.widen && r.widen
          ? `Joined with the rule's current description. Edit if wrong.`
          : sug?.intent_source === "model" && d.intent === sug.intent
            ? "Drafted by the model from the command, never from the agent's note. Edit if wrong."
            : "Edit if wrong. The model approves only this kind of work.";
    const out: HTMLElement[] = [];
    if (kind && r.widen) {
      out.push(
        segmented(
          [
            { value: "widen", label: r.widen.paused ? "Resume & widen" : "Widen existing", sub: r.widen.label },
            { value: "new", label: "New rule", sub: "separate" },
          ],
          d.widen ? "widen" : "new",
          (v) => {
            const widen = v === "widen";
            const drafted = sug?.intent || templateIntent(r);
            update({ widen, intent: widen ? combineIntents(r.widen!.intent, drafted) : drafted }, true);
          },
          "Widen or create",
        ),
      );
    }
    out.push(field(kind ? "What this rule covers" : "What the agent is doing", intent, source));
    const risk = h("input", { type: "range", min: "10", max: "60", step: "5", value: String(d.maxRisk), "aria-label": "Maximum risk" }) as HTMLInputElement;
    const riskLabel = h("span", { class: "small" }, `${d.maxRisk} · ${riskLevel(d.maxRisk).label}`);
    risk.addEventListener("input", () => {
      riskLabel.textContent = `${risk.value} · ${riskLevel(Number(risk.value)).label}`;
      update({ maxRisk: Number(risk.value) });
    });
    const adjust = h(
      "details",
      { class: "more" },
      h("summary", {}, icon("chevron"), "Adjust scope"),
      h(
        "div",
        { class: "stack", style: "margin-top:12px" },
        kind
          ? field(
              "Commands",
              segmented(
                [
                  { value: "program", label: "Any arguments", sub: program },
                  { value: "prefix", label: "Same start", sub: r.argv.length ? `${program} ${r.argv[0]} …` : "no arguments", disabled: r.argv.length === 0 },
                  { value: "exact", label: "Exactly this", sub: "same arguments" },
                ],
                d.filter,
                (v) => update({ filter: v as Filter }, true),
                "Command filter",
              ),
            )
          : null,
        kind && d.filter === "prefix" && r.argv.length > 1 ? prefixPicker(r, d.rulePrefixLen, (n) => update({ rulePrefixLen: n }, true)) : null,
        field("Where", segmented(whereOptions(r), d.ruleWhere, (v) => update({ ruleWhere: v, ruleRequester: v !== "host" && d.ruleRequester === "session" ? "user" : d.ruleRequester }, true), "Hosts")),
        field(
          "Who",
          segmented(
            [
              { value: "session", label: "This session", sub: r.session.agent ?? "shell", disabled: d.ruleWhere !== "host" },
              { value: "user", label: `Any session`, sub: `of ${r.user}` },
              { value: "any", label: "Anyone", sub: "any user" },
            ],
            d.ruleRequester,
            (v) => update({ ruleRequester: v as Draft["ruleRequester"] }, true),
            "Requester",
          ),
        ),
        field("For how long", segmented(DELEGATION_DURATIONS, String(d.ruleTtl), (v) => update({ ruleTtl: Number(v) }, true), "Delegation duration")),
        h("div", { class: "field" }, h("div", { class: "label" }, h("span", {}, "Highest risk it may approve"), riskLabel), risk),
        field(
          "Tell me",
          segmented(
            [
              { value: "each", label: "Every time" },
              { value: "digest", label: "Summary" },
              { value: "silent", label: "Don't" },
            ],
            d.notify,
            (v) => update({ notify: v as Draft["notify"] }),
          ),
        ),
        h("p", { class: "hint", style: "margin:0" }, "Root shells, credentials and changes to sudo always come back to you. Pause any rule from the Authority page."),
      ),
    );
    out.push(adjust);
    return out;
  }

  function grantDetail(): HTMLElement[] {
    const ttlSeg = segmented(
      TTL_CHOICES.filter((t) => t <= maxTtl).map((t) => ({ value: String(t), label: t < 60 ? `${t}m` : `${t / 60}h` })),
      String(d.ttl),
      (v) => update({ ttl: Number(v) }, true),
      "Duration",
    );
    return [
      d.row === "prefix-grant" && r.argv.length > 1 ? prefixPicker(r, d.prefixLen, (n) => update({ prefixLen: n }, true)) : null,
      h(
        "details",
        { class: "more" },
        h("summary", {}, icon("chevron"), "Adjust scope"),
        h(
          "div",
          { class: "stack", style: "margin-top:12px" },
          field("Where", segmented(whereOptions(r), d.where, (v) => update({ where: v, requester: v !== "host" ? "user" : d.requester }, true), "Hosts")),
          field(
            "Who",
            segmented(
              [
                { value: "session", label: "This session", sub: r.session.agent ?? "shell", disabled: d.where !== "host" },
                { value: "user", label: "Any session", sub: `of ${r.user}` },
              ],
              d.requester,
              (v) => update({ requester: v as Draft["requester"] }, true),
              "Requester",
            ),
          ),
          field("For how long", ttlSeg),
        ),
      ),
    ].filter(Boolean) as HTMLElement[];
  }

  // ---- Sticky action bar
  const approve = h("button", { type: "button", class: "btn approve lg" }) as HTMLButtonElement;
  const once = h("button", { type: "button", class: "btn lg" }, "Once") as HTMLButtonElement;
  const deny = h("button", { type: "button", class: "btn deny lg" }, "Deny") as HTMLButtonElement;
  const bar = h("div", { class: "decision-bar" }, deny, once, approve);

  const body = (decision: "approve" | "deny", onlyOnce = false): DecisionBody => {
    const b: DecisionBody = { version: r.version, decision };
    if (decision === "approve" && !onlyOnce) {
      const grantCommand = d.row === "exact" ? "exact" : d.row === "prefix-grant" ? "prefix" : d.row === "program-grant" ? "executable" : null;
      if (grantCommand) {
        b.scope = { command: grantCommand, prefix_len: grantCommand === "prefix" ? d.prefixLen : undefined, ...whereBody(d.where), requester: d.requester, ttl_minutes: d.ttl };
      }
      if (d.row === "kind" || d.row === "any") {
        b.delegate = {
          intent: (d.row === "kind" ? d.intent : d.anyIntent).trim(),
          ttl_minutes: d.ruleTtl,
          ...whereBody(d.ruleWhere),
          requester: d.ruleRequester,
          max_risk: d.maxRisk,
          notify: d.notify,
          filter: d.row === "any" ? "any" : d.filter,
          prefix_len: d.filter === "prefix" ? d.rulePrefixLen : undefined,
          widen: d.row === "kind" && d.widen && r.widen ? r.widen.id : undefined,
        };
      }
    }
    if (decision === "approve" && d.refresh) b.refresh_timestamp = true;
    if (decision === "deny") b.hard = d.hard;
    if (d.note.trim()) b.note = d.note.trim();
    return b;
  };

  function paint() {
    detail.replaceChildren(...(d.row === "kind" || d.row === "any" ? ruleDetail() : d.row === "once" ? [] : grantDetail()));
    sync();
  }

  function sync() {
    for (const c of choiceEls) {
      const on = c.row.value === d.row;
      c.btn.classList.toggle("on", on);
      c.btn.setAttribute("aria-checked", String(on));
      c.subEl.textContent = c.row.sub();
    }
    const b = body("approve");
    const stepUp = needsStepUp(r, b);
    let text = "Approve once";
    if (b.scope) text = `Approve for ${grantLen(d.ttl)}`;
    if (b.delegate) text = b.delegate.widen ? "Approve & widen" : "Approve & delegate";
    approve.replaceChildren(stepUp ? icon("fingerprint") : icon("check"), text);
    approve.title = stepUp ? "You'll confirm with your passkey" : "";
    once.classList.toggle("hidden", d.row === "once");
    bar.classList.toggle("three", d.row !== "once");
  }
  paint();

  const go = (btn: HTMLButtonElement, b: DecisionBody) =>
    void busy(btn, async () => {
      if (b.delegate && b.delegate.intent.length < 8) {
        toast(d.row === "any" ? "Say what the agent is doing, in a few words." : "Describe the kind of work in a few words.", "bad");
        detail.querySelector<HTMLTextAreaElement>("textarea")?.focus();
        return;
      }
      const updated = await submitDecision(r, b);
      if (updated) navigate("/", { replace: false });
      else await reload();
    });
  approve.addEventListener("click", () => go(approve, body("approve")));
  once.addEventListener("click", () => go(once, body("approve", true)));
  deny.addEventListener("click", () => go(deny, body("deny")));
  return [card, bar];
}

function prefixPicker(r: RequestView, n: number, set: (n: number) => void): HTMLElement {
  const slider = h("input", { type: "range", min: "1", max: String(Math.max(1, r.argv.length)), value: String(n || 1), "aria-label": "Leading arguments" }) as HTMLInputElement;
  const info = h("div", { class: "hint mono" }, `${basename(r.command)} ${r.argv.slice(0, n).join(" ")} …`);
  slider.addEventListener("input", () => {
    info.textContent = `${basename(r.command)} ${r.argv.slice(0, Number(slider.value)).join(" ")} …`;
  });
  slider.addEventListener("change", () => set(Number(slider.value)));
  return h("div", { class: "field" }, h("div", { class: "label" }, "Leading arguments to match"), slider, info);
}

function advancedOptions(r: RequestView, d: Draft, update: (p: Partial<Draft>) => void): HTMLElement {
  const refresh = h("input", { type: "checkbox", checked: d.refresh, disabled: r.mode === "validate" }) as HTMLInputElement;
  refresh.addEventListener("change", () => update({ refresh: refresh.checked }));
  const note = h("input", { class: "input", placeholder: "Optional note shown in the terminal", value: d.note, maxlength: "200" }) as HTMLInputElement;
  note.addEventListener("input", () => update({ note: note.value }));
  const hard = h("input", { type: "checkbox", checked: d.hard, disabled: r.class.hard_deny }) as HTMLInputElement;
  hard.addEventListener("change", () => update({ hard: hard.checked }));
  return h(
    "details",
    { class: "more" },
    h("summary", {}, icon("chevron"), "More options"),
    h(
      "div",
      { class: "stack", style: "margin-top:12px" },
      h("label", { class: "check" }, refresh, h("span", {}, h("b", {}, "Also unlock ordinary sudo on this host"), h("div", { class: "small muted" }, "Refreshes the sudo timestamp, so any sudo command runs without asking until it expires. Needs your passkey."))),
      field("Note", note),
      r.interactive ? h("label", { class: "check" }, hard, h("span", {}, h("b", {}, "If denying, also block the password prompt"), h("div", { class: "small muted" }, r.class.hard_deny ? "Always on for this kind of command." : "Otherwise someone at the terminal can still type the password."))) : null,
    ),
  );
}
