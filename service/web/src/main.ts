import "./styles.css";

import { type SessionInfo, currentSession, loadSession, onLive, onLiveStatus, onSession, startLive, stopLive } from "./api";
import { h, icon, initials, replace, type IconName } from "./dom";
import { registerServiceWorker, setAppBadge } from "./push";
import { type Mounted, type Route, dispatch, navigate, onRender, route, startRouter } from "./router";
import { toast } from "./ui";

import { inviteRoute, loginRoute, setupRoute, welcomeRoute } from "./pages/auth";
import { pendingPage } from "./pages/pending";
import { requestPage } from "./pages/request";
import { activityPage } from "./pages/activity";
import { authorityPage } from "./pages/authority";
import { hostsPage } from "./pages/hosts";
import { auditPage, settingsPage } from "./pages/settings";

route("/", pendingPage);
route("/r/:id", requestPage);
route("/activity", activityPage);
route("/authority", authorityPage);
route("/hosts", hostsPage);
route("/settings", settingsPage);
route("/audit", auditPage);
route("/login", loginRoute, { shell: false, public: true });
route("/setup", setupRoute, { shell: false, public: true });
route("/invite", inviteRoute, { shell: false, public: true });
route("/welcome", welcomeRoute, { shell: false });

const root = document.getElementById("app")!;
let mounted: Mounted | null = null;
let shell: ReturnType<typeof buildShell> | null = null;
let renderToken = 0;

interface NavItem {
  href: string;
  label: string;
  glyph: IconName;
  match: (p: string) => boolean;
}

const NAV: NavItem[] = [
  { href: "/", label: "Requests", glyph: "inbox", match: (p) => p === "/" || p.startsWith("/r/") },
  { href: "/activity", label: "Activity", glyph: "activity", match: (p) => p === "/activity" },
  { href: "/authority", label: "Authority", glyph: "key", match: (p) => p === "/authority" },
  { href: "/hosts", label: "Hosts", glyph: "server", match: (p) => p === "/hosts" },
  { href: "/settings", label: "Settings", glyph: "settings", match: (p) => p === "/settings" || p === "/audit" },
];

function buildShell(s: SessionInfo) {
  const liveEl = h("span", { class: "live", title: "Live updates" }, h("i"), "Live");
  const badge = h("span", { class: "badge hidden" });
  const links = NAV.map((n) =>
    h("a", { href: n.href, "data-nav": n.href }, icon(n.glyph), h("span", {}, n.label), n.href === "/" ? badge : null),
  );
  const nav = h("nav", { class: "nav", "aria-label": "Main" }, ...links);
  const main = h("main", { class: "main", id: "main" });
  const top = h(
    "header",
    { class: "topbar" },
    h("a", { href: "/", class: "brand", "aria-label": "agent-sudo home" }, h("span", { class: "brand-mark" }, icon("hash")), h("span", { class: "brand-name" }, "agent", h("span", {}, "-"), "sudo")),
    h("span", { class: "spacer" }),
    liveEl,
    h("a", { class: "avatar", href: "/settings", title: s.user?.display_name ?? "" }, initials(s.user?.display_name ?? "?")),
  );
  const el = h("div", { class: "app" }, top, h("div", { class: "layout" }, nav, main));
  const offLive = onLiveStatus((up) => {
    liveEl.classList.toggle("on", up);
    liveEl.classList.toggle("off", !up);
    liveEl.lastChild!.textContent = up ? "Live" : "Offline";
  });
  const setActive = (path: string) => {
    links.forEach((a, i) => a.classList.toggle("active", NAV[i]!.match(path)));
  };
  const setPending = (n: number) => {
    badge.textContent = String(n);
    badge.classList.toggle("hidden", n === 0);
    document.title = n > 0 ? `(${n}) agent-sudo` : "agent-sudo";
    setAppBadge(n);
  };
  return { el, main, setActive, setPending, dispose: offLive };
}

async function refreshCounts() {
  try {
    const s = await loadSession();
    shell?.setPending(s.counts?.pending ?? 0);
  } catch {
    /* offline */
  }
}

let countTimer: number | undefined;
onLive((e) => {
  if (e.type === "request") {
    window.clearTimeout(countTimer);
    countTimer = window.setTimeout(refreshCounts, 250);
  }
});

onRender(async (r: Route, params, query) => {
  const token = ++renderToken;
  let s: SessionInfo;
  try {
    s = currentSession();
  } catch {
    s = await loadSession();
  }
  if (s.setup_required && location.pathname !== "/setup") {
    navigate(`/setup${location.hash}`, { replace: true });
    return;
  }
  if (!r.public && !s.authenticated) {
    const next = location.pathname + location.search;
    navigate(`/login${next !== "/" ? `?next=${encodeURIComponent(next)}` : ""}`, { replace: true });
    return;
  }
  mounted?.dispose?.();
  mounted = null;
  let page: Mounted;
  try {
    page = await r.page(params, query);
  } catch (e) {
    page = { el: h("div", { class: "empty" }, h("h3", {}, "Something went wrong"), h("p", { class: "small" }, String((e as Error).message ?? e))) };
  }
  if (token !== renderToken) {
    page.dispose?.();
    return;
  }
  mounted = page;
  if (r.shell) {
    if (!shell) {
      shell = buildShell(s);
      replace(root, shell.el);
      startLive();
    }
    shell.setActive(location.pathname);
    shell.setPending(s.counts?.pending ?? 0);
    replace(shell.main, page.el);
  } else {
    shell?.dispose();
    shell = null;
    replace(root, page.el);
  }
});

onSession((s) => {
  if (!s.authenticated) {
    stopLive();
  }
});

window.addEventListener("agent-sudo:signed-out", async () => {
  await loadSession().catch(() => {});
  if (!currentSession().authenticated) {
    shell?.dispose();
    shell = null;
    toast("Your session ended. Please sign in again.", "info");
    navigate("/login", { replace: true });
  }
});

// Messages from the service worker (notification clicks, quick actions).
navigator.serviceWorker?.addEventListener("message", (e) => {
  const data = e.data ?? {};
  if (data.type === "navigate" && typeof data.url === "string") navigate(data.url);
  if (data.type === "decided") toast(data.message ?? "Done", data.ok ? "ok" : "bad");
});

async function boot() {
  startRouter();
  void registerServiceWorker();
  try {
    await loadSession();
  } catch {
    replace(root, h("div", { class: "auth-wrap" }, h("div", { class: "auth-card" }, h("h1", {}, "Can't reach agent-sudo"), h("p", { class: "lead" }, "The approval service is not responding. Check your connection and reload."), h("button", { class: "btn primary lg", onclick: () => location.reload() }, "Try again"))));
    return;
  }
  dispatch();
}

void boot();
