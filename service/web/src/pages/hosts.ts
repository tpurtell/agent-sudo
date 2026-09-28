// Enrolled hosts and enrollment.

import { api, currentSession, onLive, strongAuthFresh } from "../api";
import { copyText, duration, h, icon, timeAgo } from "../dom";
import type { Mounted } from "../router";
import type { HostView } from "../types";
import { action, busy, confirmSheet, emptyState, field, loading, sheet, toast } from "../ui";
import { stepUp } from "../webauthn";

async function ensureStrong() {
  if (!strongAuthFresh()) await stepUp();
}

function copyBox(text: string): HTMLElement {
  const btn = h("button", { type: "button", "aria-label": "Copy" }, icon("copy")) as HTMLButtonElement;
  btn.addEventListener("click", async () => {
    if (await copyText(text)) toast("Copied");
  });
  return h("div", { class: "copy-box" }, h("div", { class: "cmd compact" }, text), btn);
}

function addHostSheet(existingGroups: string[], reload: () => void) {
  sheet((close) => {
    const name = h("input", { class: "input", placeholder: "e.g. moa", autocapitalize: "off", spellcheck: "false" }) as HTMLInputElement;
    const groups = h("input", { class: "input", placeholder: "e.g. sparks, gpu", value: existingGroups[0] ?? "" }) as HTMLInputElement;
    const body = h("div", { class: "stack" });
    const create = h("button", { type: "button", class: "btn primary lg block" }, "Create enrollment command") as HTMLButtonElement;
    create.addEventListener("click", () =>
      void busy(create, async () => {
        await ensureStrong();
        const t = await api<{ token: string; command: string; expires_at: number }>("POST", "/api/hosts/tokens", {
          name: name.value.trim() || null,
          groups: groups.value.split(",").map((g) => g.trim()).filter(Boolean),
          ttl_minutes: 60,
        });
        const left = h("span", {});
        const tick = () => (left.textContent = `Expires in ${duration((t.expires_at - Date.now()) / 1000)} · single use`);
        tick();
        const timer = window.setInterval(tick, 1000);
        body.replaceChildren(
          h("p", { class: "small muted" }, "With agent-sudo installed on the host (install.sh from the host bundle), run:"),
          copyBox(t.command),
          h("p", { class: "small muted" }, "It registers the host and starts its relay. Then, in each agent's environment: ", h("code", {}, "agent-sudo-hostd shim install"), " and put ", h("code", {}, "~/.agent-tools"), " first on its PATH."),
          h("div", { class: "tiny faint" }, left),
          h("button", { type: "button", class: "btn block", onclick: () => { window.clearInterval(timer); close(); reload(); } }, "Done"),
        );
      }),
    );
    body.append(
      field("Name", name, "Optional. Defaults to the machine's hostname."),
      field("Groups", groups, "Comma separated. Grants and delegations can cover a whole group."),
      create,
    );
    return [h("h2", {}, "Add a host"), h("p", { class: "muted small", style: "margin-bottom:14px" }, "Creates a one-time token that registers the machine's key with this service."), body];
  }, { label: "Add a host" });
}

function editHostSheet(host: HostView, reload: () => void) {
  sheet((close) => {
    const name = h("input", { class: "input", value: host.name }) as HTMLInputElement;
    const groups = h("input", { class: "input", value: host.groups.join(", ") }) as HTMLInputElement;
    const save = h("button", { type: "button", class: "btn primary block" }, "Save") as HTMLButtonElement;
    save.addEventListener("click", () =>
      void busy(save, async () => {
        await api("PATCH", `/api/hosts/${host.id}`, { name: name.value.trim(), groups: groups.value.split(",").map((g) => g.trim()).filter(Boolean) });
        toast("Host updated");
        close();
        reload();
      }),
    );
    const revoke = action([icon("trash"), "Revoke host"], async () => {
      const ok = await confirmSheet(`Revoke ${host.name}?`, "Its key stops working immediately. Agents there fall back to the password prompt or fail.", "Revoke", true);
      if (!ok) return;
      await ensureStrong();
      await api("POST", `/api/hosts/${host.id}/revoke`, {});
      toast(`${host.name} revoked`, "info");
      close();
      reload();
    }, "deny block");
    return [h("h2", {}, host.name), h("p", { class: "muted small mono", style: "margin-bottom:14px" }, host.hostname), h("div", { class: "stack" }, field("Name", name), field("Groups", groups, "Comma separated."), save, revoke)];
  }, { label: `Edit ${host.name}` });
}

export async function hostsPage(_: Record<string, string>, query: URLSearchParams): Promise<Mounted> {
  const s = currentSession();
  const admin = s.user?.role === "admin";
  const body = h("div", {}, loading());
  let groups: string[] = [];
  const load = async () => {
    const data = await api<{ items: HostView[]; groups: string[]; pending_tokens: any[] }>("GET", "/api/hosts");
    groups = data.groups;
    if (!data.items.length) {
      body.replaceChildren(emptyState("server", "No hosts yet", "Enroll a machine to start receiving its sudo requests.", admin ? h("button", { type: "button", class: "btn primary", onclick: () => addHostSheet(groups, () => void load()) }, icon("plus"), "Add a host") : null));
      return;
    }
    const online = data.items.filter((x) => x.online).length;
    body.replaceChildren(
      ...([
      h("p", { class: "small muted", style: "margin:-8px 0 12px" }, `${online} of ${data.items.filter((x) => !x.revoked_at).length} online`),
      h(
        "div",
        { class: "card" },
        ...data.items.map((x) =>
          h(
            "div",
            { class: "host-row", style: x.revoked_at ? "opacity:.5" : "" },
            h("div", { class: "host-glyph" }, icon("server"), h("span", { class: ["dot", x.revoked_at ? "bad" : x.online ? "ok" : ""] })),
            h(
              "div",
              { style: "min-width:0" },
              h("div", { class: "row", style: "gap:8px" }, h("b", {}, x.name), ...x.groups.map((g) => h("span", { class: "chip" }, g)), x.revoked_at ? h("span", { class: "chip bad" }, "revoked") : null),
              h("div", { class: "tiny faint truncate" }, `${x.hostname} · hostd ${x.hostd_version || "?"} · ${x.last_seen_at ? `seen ${timeAgo(x.last_seen_at)}` : "never seen"}`),
            ),
            h("div", { class: "row", style: "gap:6px" }, h("a", { class: "btn sm ghost", href: `/activity?host=${x.id}`, title: "Activity" }, icon("history")), admin && !x.revoked_at ? h("button", { type: "button", class: "btn sm ghost", onclick: () => editHostSheet(x, () => void load()), "aria-label": `Edit ${x.name}` }, icon("edit")) : null),
          ),
        ),
      ),
      data.pending_tokens.length
        ? h("section", { class: "section" }, h("h2", {}, "Waiting to enroll"), h("div", { class: "card list" }, ...data.pending_tokens.map((t) => h("div", { class: "item" }, icon("link"), h("div", { class: "grow" }, h("div", {}, t.name ?? "unnamed host"), h("div", { class: "tiny faint" }, `expires ${timeAgo(t.expires_at).replace(" ago", "")} from now`.replace("just now from now", "soon")))))))
        : null,
      ].filter(Boolean) as Node[]),
    );
  };
  await load().catch((e) => body.replaceChildren(emptyState("alert", "Couldn't load hosts", String(e.message))));
  if (admin && query.get("add")) setTimeout(() => addHostSheet(groups, () => void load()), 100);
  let t: number | undefined;
  const off = onLive((e) => {
    if (e.type === "hosts") {
      window.clearTimeout(t);
      t = window.setTimeout(() => void load(), 150);
    }
  });
  return {
    el: h(
      "div",
      {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Hosts"), h("p", { class: "muted small" }, "Machines whose sudo requests come here.")), admin ? h("button", { type: "button", class: "btn primary", onclick: () => addHostSheet(groups, () => void load()) }, icon("plus"), "Add") : null),
      body,
    ),
    dispose: () => (off(), window.clearTimeout(t)),
  };
}
