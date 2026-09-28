// Service worker registration and Web Push subscription.

import { api, currentSession } from "./api";
import { isIOS, isStandalone } from "./dom";

let registration: ServiceWorkerRegistration | null = null;

export async function registerServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (!("serviceWorker" in navigator)) return null;
  try {
    registration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    return registration;
  } catch (e) {
    console.warn("service worker registration failed", e);
    return null;
  }
}

export type PushSupport =
  | { ok: true }
  | { ok: false; reason: "unsupported" | "ios-needs-install" | "denied" | "disabled-on-server" };

export function pushSupport(): PushSupport {
  const s = currentSession();
  if (!s.push_enabled) return { ok: false, reason: "disabled-on-server" };
  if (isIOS() && !isStandalone()) return { ok: false, reason: "ios-needs-install" };
  if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
    return { ok: false, reason: "unsupported" };
  }
  if (Notification.permission === "denied") return { ok: false, reason: "denied" };
  return { ok: true };
}

function keyToBytes(b64url: string): Uint8Array<ArrayBuffer> {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const bin = atob((b64url + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function currentSubscription(): Promise<PushSubscription | null> {
  const reg = registration ?? (await navigator.serviceWorker?.getRegistration("/")) ?? null;
  return (await reg?.pushManager.getSubscription()) ?? null;
}

/** Ask permission (must be called from a user gesture) and register this device. */
export async function enablePush(): Promise<void> {
  const support = pushSupport();
  if (!support.ok) throw new Error(support.reason);
  const permission = await Notification.requestPermission();
  if (permission !== "granted") throw new Error("Notifications were not allowed.");
  const reg = registration ?? (await registerServiceWorker());
  if (!reg) throw new Error("Service worker unavailable.");
  await navigator.serviceWorker.ready;
  const serverKey = keyToBytes(currentSession().vapid_public_key);
  let sub = await reg.pushManager.getSubscription();
  // A subscription made with an old server key must be replaced.
  const existingKey = sub?.options.applicationServerKey;
  if (sub && existingKey && new Uint8Array(existingKey).toString() !== serverKey.toString()) {
    await sub.unsubscribe();
    sub = null;
  }
  sub ??= await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: serverKey });
  const json = sub.toJSON();
  await api("POST", "/api/push/subscribe", { endpoint: json.endpoint, keys: json.keys });
}

export async function disablePush(): Promise<void> {
  const sub = await currentSubscription();
  await api("POST", "/api/push/unsubscribe", { endpoint: sub?.endpoint ?? null });
  await sub?.unsubscribe();
}

/** Close notifications for requests that are no longer pending. */
export async function closeNotification(requestId: string): Promise<void> {
  const reg = registration ?? (await navigator.serviceWorker?.getRegistration("/"));
  const notes = (await reg?.getNotifications({ tag: requestId })) ?? [];
  notes.forEach((n) => n.close());
}

export function setAppBadge(count: number): void {
  const nav = navigator as any;
  if (typeof nav.setAppBadge !== "function") return;
  if (count > 0) nav.setAppBadge(count).catch(() => {});
  else nav.clearAppBadge?.().catch(() => {});
}
