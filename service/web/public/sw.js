/* agent-sudo service worker: push notifications, notification actions, app shell cache. */

const SHELL = "agent-sudo-shell-v2";

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(SHELL).then((c) => c.addAll(["/", "/manifest.webmanifest", "/icons/icon-192.png"])).catch(() => {}));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys()) if (key !== SHELL) await caches.delete(key);
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/api/")) return;
  if (event.request.mode === "navigate") {
    // Network first so a deploy is picked up immediately; cached shell when offline.
    event.respondWith(
      fetch(event.request)
        .then((resp) => {
          const copy = resp.clone();
          if (resp.ok) caches.open(SHELL).then((c) => c.put("/", copy));
          return resp;
        })
        .catch(() => caches.match("/")),
    );
    return;
  }
  if (url.pathname.startsWith("/assets/") || url.pathname.startsWith("/icons/")) {
    event.respondWith(
      caches.match(event.request).then(
        (hit) =>
          hit ||
          fetch(event.request).then((resp) => {
            const copy = resp.clone();
            if (resp.ok) caches.open(SHELL).then((c) => c.put(event.request, copy));
            return resp;
          }),
      ),
    );
  }
});

// ---------------------------------------------------------------------------
// Push

function supportsActions() {
  return "actions" in Notification.prototype && (Notification.maxActions || 0) >= 2;
}

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { title: "agent-sudo", body: event.data ? event.data.text() : "" };
  }
  const options = {
    body: data.body || "",
    icon: "/icons/icon-192.png",
    badge: "/icons/badge-96.png",
    timestamp: Date.now(),
    data,
  };
  if (data.t === "request") {
    options.tag = data.id;
    // An update (the model's suggestion arrived) replaces the notification quietly.
    options.renotify = !data.update;
    options.silent = !!data.update;
    options.requireInteraction = true;
    if (!supportsActions()) options.actions = [];
    else if (data.remember) {
      options.actions = [
        { action: "remember", title: "Approve & remember" },
        { action: "deny", title: "Deny" },
      ];
    } else if (data.quick) {
      options.actions = [
        { action: "approve", title: "Approve once" },
        { action: "deny", title: "Deny" },
      ];
    } else options.actions = [{ action: "open", title: "Review" }];
    if (data.code) options.body = `[${data.code}] ${options.body}`;
  } else if (data.t === "auto") {
    // A request that was waiting when a rule approved it: replace its notification quietly.
    options.tag = data.replaces ? data.id : `auto-${data.id}`;
    options.silent = !!data.replaces;
    if (supportsActions()) {
      options.actions = data.delegation
        ? [{ action: "pause", title: "Pause rule" }, { action: "open", title: "View" }]
        : [{ action: "open", title: "View" }];
    }
  } else if (data.t === "digest") {
    options.tag = `digest-${data.delegation}`;
  }
  event.waitUntil(
    (async () => {
      await self.registration.showNotification(data.title || "agent-sudo", options);
      const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      clients.forEach((c) => c.postMessage({ type: "push", data }));
    })(),
  );
});

function readCsrf() {
  return new Promise((resolve) => {
    const req = indexedDB.open("agent-sudo", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("kv");
    req.onerror = () => resolve(null);
    req.onsuccess = () => {
      try {
        const tx = req.result.transaction("kv", "readonly");
        const get = tx.objectStore("kv").get("csrf");
        get.onsuccess = () => resolve(get.result || null);
        get.onerror = () => resolve(null);
      } catch {
        resolve(null);
      }
    };
  });
}

async function post(path, body) {
  const csrf = await readCsrf();
  if (!csrf) return { ok: false, status: 0 };
  const resp = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", "x-csrf-token": csrf },
    body: JSON.stringify(body),
  });
  let json = null;
  try {
    json = await resp.json();
  } catch {}
  return { ok: resp.ok, status: resp.status, json };
}

async function openApp(url) {
  const target = new URL(url || "/", location.origin).href;
  const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  for (const c of clients) {
    if (new URL(c.url).origin === location.origin) {
      await c.focus();
      c.postMessage({ type: "navigate", url: new URL(target).pathname });
      return;
    }
  }
  await self.clients.openWindow(target);
}

async function tell(message, ok) {
  const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  if (clients.length) clients.forEach((c) => c.postMessage({ type: "decided", message, ok }));
  else await self.registration.showNotification(message, { icon: "/icons/icon-192.png", badge: "/icons/badge-96.png", tag: "agent-sudo-result", silent: true });
}

self.addEventListener("notificationclick", (event) => {
  const note = event.notification;
  const data = note.data || {};
  note.close();
  event.waitUntil(
    (async () => {
      if ((event.action === "approve" || event.action === "deny" || event.action === "remember") && data.id) {
        try {
          const body = event.action === "remember"
            ? { version: data.v, decision: "approve", apply_suggestion: true, suggestion_at: data.suggestion_at ?? null }
            : { version: data.v, decision: event.action };
          const r = await post(`/api/requests/${data.id}/decision`, body);
          if (r.ok) {
            const verb = event.action === "deny" ? "Denied" : event.action === "remember" ? "Approved and remembered" : "Approved";
            await tell(`${verb} ${data.code || ""}`.trim(), true);
            return;
          }
          // Needs a passkey, was already decided, changed, or the session expired.
          await openApp(data.url);
        } catch {
          await openApp(data.url);
        }
        return;
      }
      if (event.action === "pause" && data.delegation) {
        const r = await post(`/api/grants/${data.delegation}/pause`, {}).catch(() => ({ ok: false }));
        if (r.ok) await tell("Delegation paused", true);
        else await openApp("/authority");
        return;
      }
      await openApp(data.url || "/");
    })(),
  );
});

self.addEventListener("pushsubscriptionchange", (event) => {
  event.waitUntil(
    (async () => {
      const old = event.oldSubscription;
      const key = old && old.options && old.options.applicationServerKey;
      if (!key) return;
      const sub = await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      const json = sub.toJSON();
      await post("/api/push/subscribe", { endpoint: json.endpoint, keys: json.keys });
    })(),
  );
});
