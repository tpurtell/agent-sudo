// Recent decisions as a timeline.

import { api, onLive } from "../api";
import { riskMini, stateIcon } from "../components";
import { h, icon, clock, dayLabel } from "../dom";
import type { Mounted } from "../router";
import type { RequestView } from "../types";
import { emptyState, loading, segmented } from "../ui";

type Filter = "all" | "approved" | "automated" | "denied" | "other";

function matches(r: RequestView, f: Filter): boolean {
  const via = r.decision?.decision.via;
  switch (f) {
    case "all":
      return true;
    case "approved":
      return r.state === "approved" && via !== "delegation";
    case "automated":
      return r.state === "approved" && (via === "delegation" || via === "grant");
    case "denied":
      return r.state === "denied";
    default:
      return r.state === "expired" || r.state === "withdrawn" || r.state === "pending";
  }
}

export async function activityPage(_: Record<string, string>, query: URLSearchParams): Promise<Mounted> {
  const hostFilter = query.get("host");
  let filter: Filter = "all";
  let items: RequestView[] = [];
  let quiet = false;
  const list = h("div", {}, loading());
  const more = h("button", { type: "button", class: "btn block", style: "margin-top:14px" }, "Load older") as HTMLButtonElement;

  const render = () => {
    const shown = items.filter((r) => matches(r, filter));
    if (!shown.length) {
      list.replaceChildren(emptyState("history", "Nothing here yet", "Decisions will show up here as agents request sudo."));
      more.classList.add("hidden");
      return;
    }
    const groups = new Map<string, RequestView[]>();
    for (const r of shown) {
      const key = dayLabel(r.created_at);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(r);
    }
    list.replaceChildren(
      ...[...groups.entries()].flatMap(([day, rows]) => [
        h("div", { class: "day-label" }, day),
        h(
          "div",
          { class: "card" },
          ...rows.map((r) => {
            const s = stateIcon(r);
            const d = r.decision?.decision;
            const by = d ? (d.via === "delegation" ? `delegation “${d.label}”` : d.via === "grant" ? "standing grant" : d.via === "user" ? `${d.by} · ${d.label}` : d.label) : "waiting";
            return h(
              "a",
              { class: "tl-item", href: `/r/${r.id}` },
              h("span", { class: ["tl-icon", s.cls], title: s.label }, icon(s.glyph)),
              h(
                "div",
                { style: "min-width:0" },
                h("div", { class: "tl-cmd" }, r.display),
                h("div", { class: "tl-meta" }, h("span", {}, r.host?.name ?? "?"), h("span", {}, "·"), h("span", {}, r.session.agent ?? r.user), h("span", {}, "·"), h("span", { class: "truncate" }, by), r.flagged_at ? h("span", { class: "chip bad" }, icon("flag"), "flagged") : null),
              ),
              h("div", { class: "stack tight", style: "align-items:flex-end" }, h("span", { class: "tiny faint nowrap" }, clock(r.created_at)), riskMini(r.assessment.assessment)),
            );
          }),
        ),
      ]),
    );
    more.classList.toggle("hidden", items.length < 50);
  };

  const load = async (append = false) => {
    const before = append && items.length ? `&before=${items[items.length - 1]!.created_at}` : "";
    const data = await api<{ items: RequestView[] }>("GET", `/api/requests?limit=50${before}${quiet ? "&quiet=true" : ""}${hostFilter ? `&host=${encodeURIComponent(hostFilter)}` : ""}`);
    items = append ? items.concat(data.items) : data.items;
    if (append && data.items.length < 50) more.classList.add("hidden");
    render();
  };
  more.addEventListener("click", () => void load(true));

  const seg = segmented<Filter>(
    [
      { value: "all", label: "All" },
      { value: "approved", label: "Approved" },
      { value: "automated", label: "Automatic" },
      { value: "denied", label: "Denied" },
      { value: "other", label: "Expired" },
    ],
    filter,
    (v) => {
      filter = v;
      render();
    },
    "Filter",
  );
  const quietToggle = h("label", { class: "check small muted", style: "margin-top:10px" }, h("input", { type: "checkbox", onchange: (e: Event) => { quiet = (e.target as HTMLInputElement).checked; void load(); } }), h("span", {}, "Include non-interactive checks (sudo -n)"));

  await load().catch((e) => list.replaceChildren(emptyState("alert", "Couldn't load activity", String(e.message))));
  let t: number | undefined;
  const off = onLive((e) => {
    if (e.type !== "request") return;
    window.clearTimeout(t);
    t = window.setTimeout(() => void load(), 300);
  });
  return {
    el: h("div", {}, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Activity"), h("p", { class: "muted small" }, "Every privileged request and who decided it."))), seg, quietToggle, list, more),
    dispose: () => (off(), window.clearTimeout(t)),
  };
}
