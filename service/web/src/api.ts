// API client, session store, and the live event stream.

export interface SessionInfo {
  name: string;
  version: string;
  authenticated: boolean;
  setup_required: boolean;
  vapid_public_key: string;
  push_enabled: boolean;
  advisor: { model: string; backend: string; auto_assess: boolean } | null;
  automation: { configured: boolean; enabled: boolean };
  strong_auth_minutes: number;
  user?: { id: string; name: string; display_name: string; role: string };
  device?: { id: string; label: string };
  csrf?: string;
  strong_auth_at?: number | null;
  auth_method?: string;
  passkeys?: number;
  has_push?: boolean;
  counts?: Counts;
}

export interface Counts {
  pending: number;
  approved_24h: number;
  denied_24h: number;
  automated_24h: number;
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

let session: SessionInfo | null = null;
const sessionListeners = new Set<(s: SessionInfo) => void>();

export function currentSession(): SessionInfo {
  if (!session) throw new Error("session not loaded");
  return session;
}

export function onSession(fn: (s: SessionInfo) => void): () => void {
  sessionListeners.add(fn);
  return () => sessionListeners.delete(fn);
}

export async function loadSession(): Promise<SessionInfo> {
  session = await api<SessionInfo>("GET", "/api/session");
  if (session.csrf) void storeCsrf(session.csrf);
  sessionListeners.forEach((fn) => fn(session!));
  return session;
}

export function strongAuthFresh(minutes?: number): boolean {
  const s = session;
  if (!s?.strong_auth_at) return false;
  return Date.now() - s.strong_auth_at < (minutes ?? s.strong_auth_minutes) * 60_000 - 15_000;
}

export function markStrong(): void {
  if (session) session.strong_auth_at = Date.now();
}

export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && session?.csrf) headers["x-csrf-token"] = session.csrf;
  let resp: Response;
  try {
    resp = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError(0, "offline", "Can't reach the approval service. Check your connection.");
  }
  const text = await resp.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!resp.ok) {
    const err = new ApiError(resp.status, data?.error ?? "error", data?.message ?? `Request failed (${resp.status})`);
    if (resp.status === 401 && path !== "/api/session" && !path.startsWith("/api/login")) {
      window.dispatchEvent(new CustomEvent("agent-sudo:signed-out"));
    }
    throw err;
  }
  return data as T;
}

// ---------------------------------------------------------------------------
// Live updates over Server-Sent Events, with reconnect and a status signal.

export type LiveEvent =
  | { type: "request"; id: string; state: string; version: number }
  | { type: "grants" | "hosts" | "devices" | "settings" | "users" };

type LiveListener = (e: LiveEvent) => void;
const liveListeners = new Set<LiveListener>();
const statusListeners = new Set<(up: boolean) => void>();
let source: EventSource | null = null;
let liveUp = false;
let retry = 1000;

export function onLive(fn: LiveListener): () => void {
  liveListeners.add(fn);
  return () => liveListeners.delete(fn);
}

export function onLiveStatus(fn: (up: boolean) => void): () => void {
  statusListeners.add(fn);
  fn(liveUp);
  return () => statusListeners.delete(fn);
}

function setLive(up: boolean) {
  if (liveUp === up) return;
  liveUp = up;
  statusListeners.forEach((fn) => fn(up));
}

export function startLive(): void {
  if (source) return;
  const es = new EventSource("/api/events", { withCredentials: true });
  source = es;
  es.onopen = () => {
    retry = 1000;
    setLive(true);
    // Anything may have changed while we were away.
    liveListeners.forEach((fn) => fn({ type: "grants" }));
    liveListeners.forEach((fn) => fn({ type: "request", id: "*", state: "", version: 0 }));
  };
  const handler = (ev: MessageEvent) => {
    try {
      const data = JSON.parse(ev.data) as LiveEvent;
      liveListeners.forEach((fn) => fn(data));
    } catch {
      /* ignore */
    }
  };
  for (const name of ["request", "grants", "hosts", "devices", "settings", "users"]) {
    es.addEventListener(name, handler as EventListener);
  }
  es.onerror = () => {
    setLive(false);
    es.close();
    source = null;
    const wait = retry;
    retry = Math.min(retry * 2, 30_000);
    setTimeout(() => {
      if (session?.authenticated) startLive();
    }, wait);
  };
}

export function stopLive(): void {
  source?.close();
  source = null;
  setLive(false);
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && !source && session?.authenticated) startLive();
});

// ---------------------------------------------------------------------------
// The CSRF token is mirrored into IndexedDB so the service worker can act on
// notification buttons (Edge/Chrome) with the same protections as the page.

function idb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("agent-sudo", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("kv");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function storeCsrf(token: string): Promise<void> {
  try {
    const db = await idb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("kv", "readwrite");
      tx.objectStore("kv").put(token, "csrf");
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  } catch {
    /* private mode or blocked storage: quick actions fall back to opening the app */
  }
}
