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
import { h, icon, minutesLabel, timeAgo, clock, DELEGATION_DURATIONS, DEFAULT_DELEGATION_MINUTES } from "../dom";
import { type Mounted, navigate } from "../router";
import type { RequestView } from "../types";
import { action, busy, confirmSheet, emptyState, field, segmented, toast, toggle, type Option } from "../ui";

type CommandScope = "once" | "exact" | "prefix" | "executable";

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
    const keep = draft;
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

interface Draft {
  command: CommandScope;
  prefixLen: number;
  hosts: "host" | "group" | "all";
  requester: "session" | "user";
  ttl: number;
  delegate: boolean;
  intent: string;
  delegateTtl: number;
  delegateHosts: "host" | "group" | "all";
  delegateRequester: "session" | "user" | "any";
  maxRisk: number;
  notify: "each" | "digest" | "silent";
  refresh: boolean;
  note: string;
  hard: boolean;
}

function initialDraft(r: RequestView): Draft {
  const a = r.assessment.assessment;
  const maxTtl = r.class.max_ttl_minutes;
  const grantsAllowed = !r.class.require_each_time && maxTtl > 0 && ungrantable(r) === null && r.mode === "run";
  const sug = a?.suggestion;
  const command: CommandScope = grantsAllowed && sug && sug.decision === "approve" ? sug.command : "once";
  const ttl = Math.min(sug?.ttl_minutes || 30, maxTtl) || 30;
  const hasGroup = (r.host?.groups.length ?? 0) > 0;
  return {
    command,
    prefixLen: Math.min(1, r.argv.length),
    hosts: sug?.hosts === "group" && !hasGroup ? "host" : (sug?.hosts ?? "host"),
    requester: sug?.hosts && sug.hosts !== "host" ? "user" : (sug?.requester ?? "session"),
    ttl: TTL_CHOICES.filter((t) => t <= maxTtl).reduce((best, t) => (Math.abs(t - ttl) < Math.abs(best - ttl) ? t : best), TTL_CHOICES[0]!),
    delegate: false,
    intent: r.context ? r.context.slice(0, 300) : "",
    delegateTtl: DEFAULT_DELEGATION_MINUTES,
    delegateHosts: hasGroup ? "group" : "host",
    // Other hosts run other sessions, so multi-host delegations default to the user.
    delegateRequester: hasGroup ? "user" : "session",
    maxRisk: 35,
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
    const sugText =
      sug.decision === "approve"
        ? sug.command === "once"
          ? "Approve once"
          : `Approve ${sug.command === "exact" ? "this exact command" : sug.command === "prefix" ? "this command prefix" : "this program"} on ${sug.hosts === "host" ? "this host" : sug.hosts === "group" ? "the host group" : "all hosts"} for ${minutesLabel(sug.ttl_minutes)}`
        : sug.decision === "deny"
          ? "Deny"
          : "Look closely before deciding";
    body.append(h("div", { class: "row small" }, h("span", { class: "chip auto" }, icon("sparkle"), "Suggested"), h("span", {}, sugText)));
    if (a.relevance !== null && a.relevance !== undefined) body.append(h("div", { class: "small muted" }, `Fits the delegation's intent: ${Math.round(a.relevance * 100)}%`));
    body.append(h("details", { class: "more" }, h("summary", {}, icon("chevron"), "Risk dimensions"), h("div", { style: "margin-top:10px" }, dimensions(a))));
    if (a.clamped.length) {
      body.append(h("div", { class: "tip warn" }, icon("shield"), h("div", { class: "small" }, h("b", {}, "Policy adjusted the model's answer. "), a.clamped.join(". "), ".")));
    }
    body.append(h("div", { class: "tiny faint" }, `${a.model} · ${a.backend} · ${(a.latency_ms / 1000).toFixed(1)}s${a.cost_usd ? ` · $${a.cost_usd.toFixed(5)}` : ""}${a.model_risk !== a.risk ? ` · model said ${a.model_risk}` : ""}`));
  } else if (stored.failure) {
    body.append(h("div", { class: "tip warn" }, icon("alert"), h("div", { class: "small" }, `The decision model couldn't assess this request: ${stored.failure.error}`)));
  }
  const check = stored.delegation_check;
  if (check) {
    body.append(
      h(
        "div",
        { class: ["outcome", check.approved ? "auto" : "gray"] },
        icon("sparkle"),
        h(
          "div",
          {},
          check.approved ? `Delegation “${check.label}” approved this` : `Delegation “${check.label}” handed this to you`,
          check.reasons.length ? h("small", {}, check.reasons.join(" · ")) : null,
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

function decisionBuilder(r: RequestView, d: Draft, save: (d: Draft) => void, reload: () => Promise<void>): HTMLElement[] {
  const s = currentSession();
  const maxTtl = r.class.max_ttl_minutes;
  const why = ungrantable(r);
  const grantsAllowed = !r.class.require_each_time && maxTtl > 0 && why === null && r.mode === "run" && !!r.command;
  const hasGroup = (r.host?.groups.length ?? 0) > 0;
  const suggested = r.assessment.assessment?.suggestion;
  const canDelegate = !!s.advisor && s.automation.enabled && r.class.delegable && !r.lossy;
  const update = (patch: Partial<Draft>) => {
    Object.assign(d, patch);
    save(d);
    sync();
  };
  const mark = (label: string, on: boolean | undefined) => (on ? `${label} ✦` : label);

  const commandOpts: Option<CommandScope>[] = [
    { value: "once", label: "Just once" },
    { value: "exact", label: mark("This command", suggested?.command === "exact"), disabled: !grantsAllowed },
    { value: "prefix", label: mark("Command prefix", suggested?.command === "prefix"), disabled: !grantsAllowed || r.argv.length === 0 },
    { value: "executable", label: mark("Any arguments", suggested?.command === "executable"), disabled: !grantsAllowed },
  ];
  const commandSeg = segmented(commandOpts, d.command, (v) => update({ command: v }), "Approval scope");

  const prefixInfo = h("div", { class: "hint mono" });
  const prefixSlider = h("input", { type: "range", min: "1", max: String(Math.max(1, r.argv.length)), value: String(d.prefixLen || 1), "aria-label": "Prefix length" }) as HTMLInputElement;
  prefixSlider.addEventListener("input", () => update({ prefixLen: Number(prefixSlider.value) }));
  const prefixField = h("div", { class: "field" }, h("div", { class: "label" }, "Leading arguments to match"), prefixSlider, prefixInfo);

  const hostSeg = segmented(
    [
      { value: "host", label: "This host", sub: r.host?.name },
      { value: "group", label: "Group", sub: hasGroup ? r.host!.groups.join(", ") : "none", disabled: !hasGroup },
      { value: "all", label: "All hosts" },
    ],
    d.hosts,
    (v) => {
      const hosts = v as Draft["hosts"];
      // A session exists on one host only; widen "who" along with "where".
      if (hosts !== "host" && d.requester === "session") {
        whoSeg.set("user");
        update({ hosts, requester: "user" });
      } else update({ hosts });
    },
    "Hosts",
  );
  const whoSeg = segmented(
    [
      { value: "session", label: "This session", sub: r.session.agent ?? "shell" },
      { value: "user", label: `Any session`, sub: `of ${r.user}` },
    ],
    d.requester,
    (v) => update({ requester: v as Draft["requester"] }),
    "Requester",
  );
  const ttlSeg = segmented(
    TTL_CHOICES.filter((t) => t <= maxTtl).map((t) => ({ value: String(t), label: t < 60 ? `${t}m` : `${t / 60}h` })),
    String(d.ttl),
    (v) => update({ ttl: Number(v) }),
    "Duration",
  );
  const grantFields = h(
    "div",
    { class: "stack" },
    prefixField,
    field("Where", hostSeg),
    field("Who", whoSeg),
    field("For how long", ttlSeg),
  );

  // Delegation
  const delegateWho = segmented(
    [
      { value: "session", label: "This session" },
      { value: "user", label: `Any of ${r.user}` },
      { value: "any", label: "Anyone" },
    ],
    d.delegateRequester,
    (v) => update({ delegateRequester: v as Draft["delegateRequester"] }),
  );
  const intent = h("textarea", { class: "input", rows: "2", placeholder: "e.g. Installing and configuring the NVIDIA driver stack on the sparks", maxlength: "600" }, d.intent) as HTMLTextAreaElement;
  intent.addEventListener("input", () => update({ intent: intent.value }));
  const risk = h("input", { type: "range", min: "10", max: "60", step: "5", value: String(d.maxRisk), "aria-label": "Maximum risk" }) as HTMLInputElement;
  const riskLabel = h("span", { class: "small" });
  risk.addEventListener("input", () => update({ maxRisk: Number(risk.value) }));
  const delegateBox = h(
    "div",
    { class: "delegate-box" },
    h("p", { class: "small" }, h("b", {}, "The model approves similar requests for you "), "while the work continues, within the limits below. Root shells, credentials, and changes to sudo always come back to you."),
    field("What work should it approve?", intent, "Your words, given to the model as the intent. Requests that don't fit come to you."),
    field("For how long", segmented(DELEGATION_DURATIONS, String(d.delegateTtl), (v) => update({ delegateTtl: Number(v) }), "Delegation duration")),
    field(
      "Where",
      segmented(
        [
          { value: "host", label: "This host" },
          { value: "group", label: "Group", disabled: !hasGroup },
          { value: "all", label: "All hosts" },
        ],
        d.delegateHosts,
        (v) => {
          const hosts = v as Draft["delegateHosts"];
          if (hosts !== "host" && d.delegateRequester === "session") {
            delegateWho.set("user");
            update({ delegateHosts: hosts, delegateRequester: "user" });
          } else update({ delegateHosts: hosts });
        },
      ),
    ),
    field("Who", delegateWho),
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
  );
  const delegateToggle = toggle(d.delegate, (v) => update({ delegate: v }), "auto", "Delegate similar requests");
  const delegateRow = canDelegate
    ? h("div", { class: "row", style: "align-items:flex-start" }, h("div", { class: "grow" }, h("h3", { class: "row", style: "gap:6px" }, icon("sparkle"), "Let the model handle similar requests"), h("p", { class: "small muted" }, "Hands off routine follow-ups, like the same install on the other sparks.")), delegateToggle)
    : null;

  // Advanced
  const refresh = h("input", { type: "checkbox", checked: d.refresh, disabled: r.mode === "validate" }) as HTMLInputElement;
  refresh.addEventListener("change", () => update({ refresh: refresh.checked }));
  const note = h("input", { class: "input", placeholder: "Optional note shown in the terminal", value: d.note, maxlength: "200" }) as HTMLInputElement;
  note.addEventListener("input", () => update({ note: note.value }));
  const hard = h("input", { type: "checkbox", checked: d.hard, disabled: r.class.hard_deny }) as HTMLInputElement;
  hard.addEventListener("change", () => update({ hard: hard.checked }));
  const advanced = h(
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

  const card = h(
    "section",
    { class: "section" },
    h("h2", {}, icon("key"), "Decision"),
    h(
      "div",
      { class: "card pad scope" },
      field("Remember this approval", commandSeg, grantsAllowed ? undefined : r.class.require_each_time ? `${r.class.title} always needs a fresh decision.` : (why ?? "This request can only be approved once.")),
      grantFields,
      delegateRow,
      delegateBox,
      advanced,
    ),
  );

  // Sticky action bar
  const approve = h("button", { type: "button", class: "btn approve lg" }) as HTMLButtonElement;
  const deny = h("button", { type: "button", class: "btn deny lg" }, "Deny") as HTMLButtonElement;
  const bar = h("div", { class: "decision-bar" }, deny, approve);

  const body = (decision: "approve" | "deny"): DecisionBody => {
    const b: DecisionBody = { version: r.version, decision };
    if (decision === "approve") {
      if (d.command !== "once") {
        b.scope = { command: d.command, prefix_len: d.command === "prefix" ? d.prefixLen : undefined, hosts: d.hosts, requester: d.requester, ttl_minutes: d.ttl };
      }
      if (d.refresh) b.refresh_timestamp = true;
      if (d.delegate && canDelegate) {
        b.delegate = { intent: d.intent.trim(), ttl_minutes: d.delegateTtl, hosts: d.delegateHosts, requester: d.delegateRequester, max_risk: d.maxRisk, notify: d.notify };
      }
    } else {
      b.hard = d.hard;
    }
    if (d.note.trim()) b.note = d.note.trim();
    return b;
  };

  function sync() {
    const grant = d.command !== "once";
    grantFields.classList.toggle("hidden", !grant);
    prefixField.classList.toggle("hidden", d.command !== "prefix");
    prefixInfo.textContent = `${(r.command ?? "").split("/").pop()} ${r.argv.slice(0, d.prefixLen).join(" ")} …`;
    delegateBox.classList.toggle("hidden", !d.delegate || !canDelegate);
    const { label } = riskLevel(d.maxRisk);
    riskLabel.textContent = `${d.maxRisk} · ${label}`;
    const b = body("approve");
    const stepUp = needsStepUp(r, b);
    let text = "Approve once";
    if (grant) text = `Approve for ${d.ttl < 60 ? `${d.ttl}m` : `${d.ttl / 60}h`}`;
    if (d.delegate && canDelegate) text = grant ? "Approve & delegate" : "Approve & delegate";
    approve.replaceChildren(stepUp ? icon("fingerprint") : icon("check"), text);
    approve.title = stepUp ? "You'll confirm with your passkey" : "";
  }
  sync();

  approve.addEventListener("click", () =>
    void busy(approve, async () => {
      if (d.delegate && canDelegate && d.intent.trim().length < 8) {
        toast("Describe the work the model should approve.", "bad");
        intent.focus();
        return;
      }
      const updated = await submitDecision(r, body("approve"));
      if (updated) navigate("/", { replace: false });
      else await reload();
    }),
  );
  deny.addEventListener("click", () =>
    void busy(deny, async () => {
      const updated = await submitDecision(r, body("deny"));
      if (updated) navigate("/");
      else await reload();
    }),
  );
  return [card, bar];
}
