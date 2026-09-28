// Settings: this device, passkeys, signed-in devices, account, users, policy, audit.

import { api, currentSession, loadSession, onLive, strongAuthFresh } from "../api";
import { copyText, h, icon, initials, isIOS, isStandalone, timeAgo, clock, dayLabel, minutesLabel } from "../dom";
import { currentSubscription, disablePush, enablePush, pushSupport } from "../push";
import { type Mounted, navigate } from "../router";
import { action, busy, confirmSheet, field, loading, segmented, sheet, toast, errorMessage } from "../ui";
import { friendlyError, registerPasskey, stepUp } from "../webauthn";

async function ensureStrong() {
  if (!strongAuthFresh()) await stepUp();
}

function section(id: string, title: string, glyph: Parameters<typeof icon>[0], ...content: (Node | null)[]): HTMLElement {
  return h("section", { class: "section", id }, h("h2", {}, icon(glyph), title), ...content);
}

// ---------------------------------------------------------------------------

async function deviceSection(): Promise<HTMLElement> {
  const s = currentSession();
  const card = h("div", { class: "card pad stack" });
  const render = async () => {
    const support = pushSupport();
    const sub = await currentSubscription().catch(() => null);
    const on = !!sub && !!s.has_push;
    const label = h("input", { class: "input", value: s.device?.label ?? "" }) as HTMLInputElement;
    const saveLabel = action("Rename", async () => {
      await api("PATCH", `/api/devices/${s.device!.id}`, { label: label.value });
      await loadSession();
      toast("Device renamed");
    }, "sm");
    const rows: (Node | null)[] = [
      field("This device", h("div", { class: "row" }, label, saveLabel)),
      h("div", { class: "divider", style: "margin:4px 0" }),
    ];
    if (!support.ok && support.reason === "ios-needs-install") {
      rows.push(
        h("div", { class: "tip" }, icon("info"), h("div", {}, h("b", {}, "Add to Home Screen for notifications. "), "In Safari tap ", h("span", { class: "kbd" }, icon("share"), "Share"), " then ", h("span", { class: "kbd" }, icon("addHome"), "Add to Home Screen"), ", and open agent-sudo from there.")),
      );
    } else if (!support.ok) {
      const why: Record<string, string> = {
        unsupported: "This browser can't receive push notifications.",
        denied: "Notifications are blocked for this site in your browser settings.",
        "disabled-on-server": "Push is disabled in the service configuration.",
      };
      rows.push(h("div", { class: "tip warn" }, icon("bellOff"), h("div", {}, why[support.reason] ?? "Unavailable.")));
    } else {
      rows.push(
        h(
          "div",
          { class: "row" },
          h("div", { class: "grow" }, h("h3", {}, "Notifications"), h("p", { class: "small muted" }, on ? "This device is alerted when an agent needs sudo." : "Off on this device.")),
          on
            ? action("Turn off", async () => { await disablePush(); await loadSession(); toast("Notifications off", "info"); await render(); }, "sm")
            : action([icon("bell"), "Turn on"], async () => { await enablePush(); await loadSession(); toast("Notifications on"); await render(); }, "sm primary"),
        ),
        on ? action([icon("bell"), "Send a test notification"], async () => { await api("POST", "/api/push/test"); toast("Test sent. It should arrive in a few seconds."); }, "sm ghost") : null,
      );
      if (!isIOS()) rows.push(h("p", { class: "tiny faint" }, "Edge and Chrome show Approve and Deny buttons on routine requests. Anything that needs your passkey opens the app."));
    }
    if (isIOS() && isStandalone()) rows.push(h("p", { class: "tiny faint" }, "Installed on your Home Screen."));
    card.replaceChildren(...(rows.filter(Boolean) as Node[]));
  };
  await render();
  return section("device", "This device", s.device && /iPhone|Android/.test(s.device.label) ? "phone" : "laptop", card);
}

async function passkeySection(): Promise<HTMLElement> {
  const card = h("div", { class: "card" });
  const render = async () => {
    const data = await api<{ items: { id: string; name: string; created_at: number; last_used_at: number | null }[] }>("GET", "/api/passkeys");
    const add = h("button", { type: "button", class: "btn sm primary" }, icon("plus"), "Add a passkey") as HTMLButtonElement;
    add.addEventListener("click", () =>
      void busy(add, async () => {
        try {
          if (data.items.length) await ensureStrong();
          await registerPasskey(currentSession().device?.label ?? "Passkey");
          await loadSession();
          toast("Passkey added");
          await render();
        } catch (e) {
          throw new Error(e instanceof DOMException ? friendlyError(e) : errorMessage(e));
        }
      }),
    );
    card.replaceChildren(
      ...data.items.map((pk) =>
        h(
          "div",
          { class: "host-row" },
          h("div", { class: "host-glyph" }, icon("fingerprint")),
          h("div", {}, h("b", {}, pk.name), h("div", { class: "tiny faint" }, `added ${timeAgo(pk.created_at)} · ${pk.last_used_at ? `used ${timeAgo(pk.last_used_at)}` : "never used"}`)),
          action(icon("trash"), async () => {
            const ok = await confirmSheet("Remove this passkey?", data.items.length === 1 ? "It's your only passkey. You'd sign in with your password until you add another." : "You can still sign in with your other passkeys.", "Remove", true);
            if (!ok) return;
            await ensureStrong();
            await api("DELETE", `/api/passkeys/${pk.id}`);
            toast("Passkey removed", "info");
            await render();
          }, "sm ghost", { "aria-label": `Remove ${pk.name}` }),
        ),
      ),
      h("div", { class: "host-row", style: "grid-template-columns:1fr auto" }, h("span", { class: "small muted" }, data.items.length ? "Approvals for root shells and delegations ask for one of these." : "No passkeys yet. Add one to protect sensitive approvals."), add),
    );
  };
  await render();
  return section("passkeys", "Passkeys", "fingerprint", card);
}

async function devicesSection(): Promise<HTMLElement> {
  const card = h("div", { class: "card" });
  const render = async () => {
    const data = await api<{ items: any[] }>("GET", "/api/devices");
    card.replaceChildren(
      ...data.items.map((d) =>
        h(
          "div",
          { class: "host-row" },
          h("div", { class: "host-glyph" }, icon(d.kind === "mobile" ? "phone" : "laptop")),
          h(
            "div",
            { style: "min-width:0" },
            h("div", { class: "row", style: "gap:6px" }, h("b", {}, d.label), d.current ? h("span", { class: "chip brand" }, "this device") : null, d.push ? h("span", { class: "chip", title: "Receives notifications" }, icon("bell")) : null),
            h("div", { class: "tiny faint" }, `${d.signed_in ? "signed in" : "signed out"} · active ${timeAgo(d.last_seen_at)}`),
          ),
          action(d.current ? "Sign out" : "Revoke", async () => {
            const ok = await confirmSheet(d.current ? "Sign out this device?" : `Revoke ${d.label}?`, d.current ? "You'll need your passkey to sign in again." : "Its sessions end now and it stops receiving notifications.", d.current ? "Sign out" : "Revoke", !d.current);
            if (!ok) return;
            const r = await api<{ signed_out?: boolean }>("POST", `/api/devices/${d.id}/revoke`, {});
            if (r.signed_out) {
              await loadSession();
              navigate("/login", { replace: true });
              return;
            }
            toast("Device revoked", "info");
            await render();
          }, "sm"),
        ),
      ),
    );
  };
  await render();
  return section("devices", "Signed-in devices", "laptop", card);
}

async function accountSection(): Promise<HTMLElement> {
  const s = currentSession();
  const display = h("input", { class: "input", value: s.user?.display_name ?? "" }) as HTMLInputElement;
  const pw = h("input", { class: "input", type: "password", autocomplete: "new-password", placeholder: "New password (12+ characters)" }) as HTMLInputElement;
  const card = h(
    "div",
    { class: "card pad stack" },
    h("div", { class: "row" }, h("span", { class: "avatar", style: "width:44px;height:44px;font-size:16px" }, initials(s.user?.display_name ?? "?")), h("div", {}, h("b", {}, s.user?.display_name), h("div", { class: "tiny faint" }, `${s.user?.name} · ${s.user?.role}`))),
    field("Display name", h("div", { class: "row" }, display, action("Save", async () => { await api("PATCH", "/api/account", { display_name: display.value }); await loadSession(); toast("Saved"); }, "sm"))),
    field("Recovery password", h("div", { class: "row" }, pw, action("Change", async () => { await ensureStrong(); await api("POST", "/api/account/password", { password: pw.value }); pw.value = ""; toast("Password changed"); }, "sm")), "Used only when you can't use a passkey."),
    h("div", { class: "divider", style: "margin:2px 0" }),
    action([icon("logout"), "Sign out"], async () => {
      await api("POST", "/api/logout", {});
      await loadSession();
      navigate("/login", { replace: true });
    }, "deny"),
  );
  return section("account", "Account", "user", card);
}

async function usersSection(): Promise<HTMLElement | null> {
  const s = currentSession();
  if (s.user?.role !== "admin") return null;
  const card = h("div", { class: "card" });
  const showInvite = (url: string, who: string) =>
    sheet((close) => [
      h("h2", {}, `Invitation for ${who}`),
      h("p", { class: "muted small", style: "margin:6px 0 14px" }, "Send this link privately. It works once and expires in 48 hours."),
      h("div", { class: "copy-box" }, h("div", { class: "cmd compact" }, url), h("button", { type: "button", onclick: async () => { if (await copyText(url)) toast("Copied"); } }, icon("copy"))),
      h("button", { type: "button", class: "btn block", style: "margin-top:14px", onclick: close }, "Done"),
    ]);
  const render = async () => {
    const data = await api<{ items: any[] }>("GET", "/api/users");
    const add = h("button", { type: "button", class: "btn sm primary" }, icon("plus"), "Invite") as HTMLButtonElement;
    add.addEventListener("click", () =>
      sheet((close) => {
        const name = h("input", { class: "input", autocapitalize: "off", spellcheck: "false" }) as HTMLInputElement;
        const display = h("input", { class: "input" }) as HTMLInputElement;
        let role = "approver";
        const create = h("button", { type: "button", class: "btn primary block" }, "Create invitation") as HTMLButtonElement;
        create.addEventListener("click", () =>
          void busy(create, async () => {
            await ensureStrong();
            const r = await api<{ invite_url: string }>("POST", "/api/users", { name: name.value.trim(), display_name: display.value.trim(), role });
            close();
            await render();
            showInvite(r.invite_url, name.value.trim());
          }),
        );
        return [
          h("h2", {}, "Invite someone"),
          h("div", { class: "stack", style: "margin-top:12px" }, field("Username", name), field("Display name", display), field("Role", segmented([{ value: "approver", label: "Approver" }, { value: "admin", label: "Admin" }, { value: "viewer", label: "Viewer" }], role, (v) => (role = v))), h("p", { class: "tiny faint" }, "Approvers decide requests. Admins also manage hosts and people. Viewers can only look."), create),
        ];
      }),
    );
    card.replaceChildren(
      ...data.items.map((u) =>
        h(
          "div",
          { class: "host-row", style: u.disabled ? "opacity:.55" : "" },
          h("span", { class: "avatar" }, initials(u.display_name)),
          h("div", { style: "min-width:0" }, h("div", { class: "row", style: "gap:6px" }, h("b", {}, u.display_name), h("span", { class: "chip" }, u.role), u.disabled ? h("span", { class: "chip bad" }, "disabled") : null), h("div", { class: "tiny faint" }, `${u.name} · ${u.passkeys} passkey${u.passkeys === 1 ? "" : "s"}${u.has_password ? "" : " · invitation pending"}`)),
          u.id === s.user?.id
            ? h("span", { class: "tiny faint" }, "you")
            : h(
                "div",
                { class: "row", style: "gap:4px" },
                action(icon("link"), async () => { await ensureStrong(); const r = await api<{ invite_url: string }>("POST", `/api/users/${u.id}/invite`, {}); showInvite(r.invite_url, u.name); }, "sm ghost", { title: "New invitation link" }),
                action(u.disabled ? "Enable" : "Disable", async () => { await ensureStrong(); await api("PATCH", `/api/users/${u.id}`, { disabled: !u.disabled }); await render(); }, "sm"),
              ),
        ),
      ),
      h("div", { class: "host-row", style: "grid-template-columns:1fr auto" }, h("span", { class: "small muted" }, "Everyone with approver or admin role receives notifications."), add),
    );
  };
  await render();
  return section("users", "People", "users", card);
}

async function modelSection(): Promise<HTMLElement> {
  const data = await api<any>("GET", "/api/settings");
  const a = data.advisor;
  const auto = data.automation;
  const card = h(
    "div",
    { class: "card pad stack" },
    a
      ? h(
          "dl",
          { class: "facts" },
          h("dt", {}, "Model"),
          h("dd", { class: "mono" }, a.model),
          h("dt", {}, "Backend"),
          h("dd", {}, a.backend === "decisions" ? "OpenRouter Decisions API" : "OpenAI-compatible chat"),
          h("dt", {}, "Endpoint"),
          h("dd", { class: "mono small" }, a.url),
          h("dt", {}, "History"),
          h("dd", {}, `last ${a.history_max_requests} requests within ${a.history_max_age_minutes} min`),
          h("dt", {}, "Assess"),
          h("dd", {}, a.auto_assess ? "every pending request" : "on demand"),
        )
      : h("p", { class: "muted small" }, "No decision model is configured. Requests still work; they just arrive without a risk score. Add an [advisor] section to the service configuration."),
    h("div", { class: "divider", style: "margin:2px 0" }),
    h(
      "dl",
      { class: "facts" },
      h("dt", {}, "Automation"),
      h("dd", {}, auto.configured ? (auto.enabled ? "on" : "switched off") : "disabled in configuration"),
      h("dt", {}, "Longest"),
      h("dd", {}, `${auto.max_ttl_minutes ? `Up to ${minutesLabel(auto.max_ttl_minutes)}` : "No time limit"}, ${auto.max_decisions} approvals per delegation`),
      h("dt", {}, "Pauses after"),
      h("dd", {}, `${auto.pause_after_declines} declines in a row`),
      h("dt", {}, "Never automated"),
      h("dd", {}, ...auto.forbidden_features.map((f: string) => h("span", { class: "chip", style: "margin:0 4px 4px 0" }, f.replace(/_/g, " ")))),
    ),
  );
  const classes = h(
    "div",
    { class: "card" },
    ...data.classes.map((c: any) =>
      h(
        "div",
        { class: "grant" },
        h("div", { class: "row between" }, h("b", {}, c.title || c.name), h("span", { class: "chip plain mono" }, c.name)),
        h(
          "div",
          { class: "row wrap", style: "gap:6px" },
          c.require_each_time ? h("span", { class: "chip warn" }, "every time") : h("span", { class: "chip" }, `grants ≤ ${c.max_ttl_minutes}m`),
          c.step_up !== "none" ? h("span", { class: "chip warn" }, icon("fingerprint"), c.step_up === "always" ? "fresh passkey" : "recent passkey") : null,
          c.delegable ? h("span", { class: "chip auto" }, "delegable") : h("span", { class: "chip" }, "never automated"),
          c.hard_deny ? h("span", { class: "chip bad" }, "deny blocks password") : null,
          c.always_deny ? h("span", { class: "chip bad" }, "always denied") : null,
        ),
        c.executables.length || c.features.length || c.modes.length
          ? h("div", { class: "tiny faint mono" }, [c.executables.join(" "), c.argv_prefix.join(" "), c.features.map((f: string) => `+${f}`).join(" "), c.modes.map((m: string) => `mode:${m}`).join(" ")].filter(Boolean).join("  "))
          : h("div", { class: "tiny faint" }, "Everything else"),
      ),
    ),
  );
  return h("div", {}, section("model", "Decision model", "sparkle", card), section("policy", "Policy classes", "shield", h("p", { class: "section-note small muted" }, "First match wins. Configured in the service's policy file."), classes));
}

export async function settingsPage(): Promise<Mounted> {
  const s = currentSession();
  const el = h("div", {}, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Settings"), h("p", { class: "muted small" }, `${s.name} · v${s.version}`))), loading());
  const parts = await Promise.all([deviceSection(), passkeySection(), devicesSection(), accountSection(), usersSection(), modelSection()]).catch((e) => [h("div", { class: "error-text" }, errorMessage(e))]);
  el.lastChild!.remove();
  parts.forEach((p) => p && el.append(p));
  el.append(section("audit-link", "Audit log", "history", h("a", { class: "card pad row", href: "/audit", style: "text-decoration:none" }, h("div", { class: "grow" }, h("b", {}, "Every decision, sign-in, and change"), h("div", { class: "small muted" }, "Append-only. Admins can export it as JSON lines.")), icon("chevron"))));
  if (location.hash) setTimeout(() => document.getElementById(location.hash.slice(1))?.scrollIntoView({ behavior: "smooth" }), 50);
  const off = onLive((e) => {
    if (e.type === "devices" || e.type === "users") void 0;
  });
  return { el, dispose: off };
}

// ---------------------------------------------------------------------------

const KIND_LABEL: Record<string, string> = {
  "request.submitted": "Request",
  "request.approved": "Approved",
  "request.denied": "Denied",
  "request.withdrawn": "Withdrawn",
  "request.expired": "Expired",
  "request.flagged": "Flagged",
  "delegation.approved": "Delegation approved",
  "delegation.declined": "Delegation declined",
  "delegation.created": "Delegation created",
  "delegation.paused": "Delegation paused",
  "delegation.resumed": "Delegation resumed",
  "grant.created": "Grant created",
  "grant.revoked": "Revoked",
  "host.enrolled": "Host enrolled",
  "host.revoked": "Host revoked",
  "session.created": "Signed in",
  "login.failed": "Sign-in failed",
};

export async function auditPage(): Promise<Mounted> {
  const s = currentSession();
  const list = h("div", { class: "card" }, loading());
  let items: any[] = [];
  const more = h("button", { type: "button", class: "btn block", style: "margin-top:12px" }, "Load older") as HTMLButtonElement;
  const render = () => {
    let lastDay = "";
    const rows: Node[] = [];
    for (const a of items) {
      const day = dayLabel(a.at);
      if (day !== lastDay) {
        rows.push(h("div", { class: "day-label", style: "margin:14px 16px 6px" }, day));
        lastDay = day;
      }
      const detail = a.detail ?? {};
      const summary = detail.command ?? detail.reason ?? detail.name ?? detail.hostname ?? (Array.isArray(detail.reasons) ? detail.reasons.join("; ") : "");
      const bad = /denied|failed|revoked|flagged|paused/.test(a.kind);
      rows.push(
        h(
          a.subject?.startsWith("req_") ? "a" : "div",
          { class: "tl-item", href: a.subject?.startsWith("req_") ? `/r/${a.subject}` : undefined },
          h("span", { class: ["tl-icon", bad ? "bad" : a.kind.startsWith("delegation") ? "auto" : "gray"] }, icon(bad ? "alert" : a.kind.startsWith("delegation") ? "sparkle" : "history")),
          h("div", { style: "min-width:0" }, h("div", {}, h("b", {}, KIND_LABEL[a.kind] ?? a.kind), h("span", { class: "faint" }, ` · ${a.actor}`)), summary ? h("div", { class: "tl-meta mono truncate" }, String(summary)) : null),
          h("span", { class: "tiny faint nowrap" }, clock(a.at)),
        ),
      );
    }
    list.replaceChildren(...rows);
  };
  const load = async (older = false) => {
    const before = older && items.length ? `&before=${items[items.length - 1].seq}` : "";
    const data = await api<{ items: any[] }>("GET", `/api/audit?limit=100${before}`);
    items = older ? items.concat(data.items) : data.items;
    more.classList.toggle("hidden", data.items.length < 100);
    render();
  };
  more.addEventListener("click", () => void load(true));
  await load();
  return {
    el: h(
      "div",
      {},
      h("div", { class: "page-head" }, h("div", { class: "row" }, h("a", { href: "/settings", class: "btn ghost icon-btn", "aria-label": "Back" }, icon("back")), h("div", {}, h("h1", {}, "Audit log"), h("p", { class: "muted small" }, "Append-only record of every decision and change."))), s.user?.role === "admin" ? h("a", { class: "btn sm", href: "/api/audit/export", download: "agent-sudo-audit.jsonl" }, icon("download"), "Export") : null),
      list,
      more,
    ),
  };
}
