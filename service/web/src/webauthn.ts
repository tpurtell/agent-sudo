// WebAuthn helpers: convert the server's JSON options to browser types and back.

import { api, markStrong } from "./api";

function b64urlToBuf(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function bufToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function passkeysSupported(): boolean {
  return typeof window.PublicKeyCredential !== "undefined" && !!navigator.credentials;
}

export async function conditionalMediationAvailable(): Promise<boolean> {
  const pkc = window.PublicKeyCredential as any;
  return !!pkc?.isConditionalMediationAvailable && (await pkc.isConditionalMediationAvailable());
}

function creationOptions(json: any): CredentialCreationOptions {
  const pk = json.publicKey;
  return {
    publicKey: {
      ...pk,
      challenge: b64urlToBuf(pk.challenge),
      user: { ...pk.user, id: b64urlToBuf(pk.user.id) },
      excludeCredentials: (pk.excludeCredentials ?? []).map((c: any) => ({ ...c, id: b64urlToBuf(c.id) })),
    },
  };
}

function requestOptions(json: any, mediation?: CredentialMediationRequirement, signal?: AbortSignal): CredentialRequestOptions {
  const pk = json.publicKey;
  return {
    mediation,
    signal,
    publicKey: {
      ...pk,
      challenge: b64urlToBuf(pk.challenge),
      allowCredentials: (pk.allowCredentials ?? []).map((c: any) => ({ ...c, id: b64urlToBuf(c.id) })),
    },
  };
}

function attestationJson(cred: PublicKeyCredential) {
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    extensions: cred.getClientExtensionResults?.() ?? {},
    response: {
      attestationObject: bufToB64url(r.attestationObject),
      clientDataJSON: bufToB64url(r.clientDataJSON),
      transports: typeof r.getTransports === "function" ? r.getTransports() : undefined,
    },
  };
}

function assertionJson(cred: PublicKeyCredential) {
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    extensions: cred.getClientExtensionResults?.() ?? {},
    response: {
      authenticatorData: bufToB64url(r.authenticatorData),
      clientDataJSON: bufToB64url(r.clientDataJSON),
      signature: bufToB64url(r.signature),
      userHandle: r.userHandle ? bufToB64url(r.userHandle) : null,
    },
  };
}

/** Map browser WebAuthn exceptions to something a person can act on. */
export function friendlyError(e: unknown): string {
  const err = e as DOMException & { message?: string };
  switch (err?.name) {
    case "NotAllowedError":
      return "The passkey prompt was dismissed or timed out.";
    case "InvalidStateError":
      return "This device already has a passkey for your account.";
    case "SecurityError":
      return "Passkeys need the service's exact HTTPS address. Open it by its hostname.";
    case "AbortError":
      return "The passkey prompt was cancelled.";
    default:
      return err?.message || "Passkey operation failed.";
  }
}

export async function registerPasskey(name: string): Promise<void> {
  const start = await api<{ ceremony: string; options: any }>("POST", "/api/passkeys/register/start", { name });
  const cred = (await navigator.credentials.create(creationOptions(start.options))) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was created.");
  await api("POST", "/api/passkeys/register/finish", { ceremony: start.ceremony, credential: attestationJson(cred) });
  markStrong();
}

export async function signInWithPasskey(name?: string, conditional?: AbortSignal): Promise<void> {
  const start = await api<{ ceremony: string; options: any }>("POST", "/api/login/passkey/start", { name: name || null });
  const cred = (await navigator.credentials.get(
    requestOptions(start.options, conditional ? "conditional" : undefined, conditional),
  )) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was selected.");
  await api("POST", "/api/login/passkey/finish", { ceremony: start.ceremony, credential: assertionJson(cred) });
}

/** Re-verify with a passkey to unlock sensitive actions for a few minutes. */
export async function stepUp(): Promise<void> {
  const start = await api<{ ceremony: string; options: any }>("POST", "/api/stepup/start");
  const cred = (await navigator.credentials.get(requestOptions(start.options))) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was selected.");
  await api("POST", "/api/stepup/finish", { ceremony: start.ceremony, credential: assertionJson(cred) });
  markStrong();
}
