// Submitting decisions, including passkey step-up when policy requires it.

import { ApiError, api, currentSession, strongAuthFresh } from "./api";
import { closeNotification } from "./push";
import type { RequestView } from "./types";
import { toast } from "./ui";
import { friendlyError, stepUp } from "./webauthn";

export interface DecisionBody {
  version: number;
  decision: "approve" | "deny";
  scope?: {
    command: string;
    prefix_len?: number;
    hosts: string;
    groups?: string[];
    requester: string;
    ttl_minutes: number;
  };
  refresh_timestamp?: boolean;
  hard?: boolean;
  note?: string;
  delegate?: {
    intent: string;
    /** 0 means no expiry. */
    ttl_minutes: number;
    hosts: string;
    groups?: string[];
    requester: string;
    max_risk?: number;
    notify: string;
    /** program | prefix | exact | any */
    filter?: string;
    prefix_len?: number;
    /** Widen this delegation instead of creating another. */
    widen?: string;
  };
  apply_suggestion?: boolean;
}

/**
 * Whether a delegation is broader than a passkey-free grant, mirroring the service:
 * no command filter, every host, longer than a day, or a raised risk ceiling.
 * Widening asks only when it broadens one of those, or resumes a paused rule.
 */
export function delegationNeedsPasskey(r: RequestView, d: NonNullable<DecisionBody["delegate"]>): boolean {
  const def = currentSession().automation.default_max_risk ?? 35;
  const risk = d.max_risk ?? def;
  const w = d.widen ? r.widen : null;
  if (w) {
    if (w.paused) return true;
    if (d.filter === "any" && w.covers !== "any command") return true;
    if (d.hosts === "all") return true;
    if (d.ttl_minutes === 0 && w.expires_at !== null) return true;
    if (d.ttl_minutes > 1440 && w.expires_at !== null && Date.now() + d.ttl_minutes * 60_000 > w.expires_at) return true;
    return risk > Math.max(def, w.max_risk);
  }
  return d.filter === "any" || d.hosts === "all" || d.ttl_minutes === 0 || d.ttl_minutes > 1440 || risk > def;
}

/** Whether approving will prompt for a passkey first. */
export function needsStepUp(r: RequestView, body: Pick<DecisionBody, "decision" | "refresh_timestamp" | "delegate">): boolean {
  if (body.decision !== "approve") return false;
  if (r.class.step_up === "always") return true;
  if (r.class.step_up === "recent" || body.refresh_timestamp || (body.delegate && delegationNeedsPasskey(r, body.delegate))) return !strongAuthFresh();
  return false;
}

export async function submitDecision(r: RequestView, body: DecisionBody): Promise<RequestView | null> {
  if (!currentSession().user || currentSession().user!.role === "viewer") {
    throw new Error("Your account can view requests but not decide them.");
  }
  try {
    if (needsStepUp(r, body)) await stepUp();
  } catch (e) {
    throw new Error(e instanceof DOMException ? friendlyError(e) : (e as Error).message);
  }
  const send = () => api<RequestView>("POST", `/api/requests/${r.id}/decision`, body);
  try {
    const updated = await send().catch(async (e) => {
      if (e instanceof ApiError && e.code === "step_up_required") {
        await stepUp();
        return send();
      }
      throw e;
    });
    void closeNotification(r.id);
    const verb = body.decision === "approve" ? "Approved" : "Denied";
    toast(`${verb} · ${r.host?.name ?? "host"} · ${r.code}`, body.decision === "approve" ? "ok" : "info");
    return updated;
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      toast(e.message, "info");
      return null;
    }
    throw e;
  }
}
