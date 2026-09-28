// Sign in, first-run setup, invitations, and the onboarding flow.

import { api, currentSession, loadSession } from "../api";
import { h, icon, isIOS, isStandalone } from "../dom";
import { enablePush, pushSupport } from "../push";
import { type Mounted, navigate } from "../router";
import { busy, errorMessage, field, toast } from "../ui";
import { conditionalMediationAvailable, friendlyError, passkeysSupported, registerPasskey, signInWithPasskey } from "../webauthn";

function brandHeader(title: string, lead: string) {
  return [
    h("div", { class: "brand" }, h("span", { class: "brand-mark" }, icon("hash"))),
    h("h1", {}, title),
    h("p", { class: "lead" }, lead),
  ];
}

function nextPath(query: URLSearchParams): string {
  const next = query.get("next");
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}

function wrap(...children: HTMLElement[]): Mounted {
  return { el: h("div", { class: "auth-wrap" }, h("div", { class: "auth-card" }, ...children)) };
}

// ---------------------------------------------------------------------------

export async function loginRoute(_: Record<string, string>, query: URLSearchParams): Promise<Mounted> {
  const s = currentSession();
  if (s.authenticated) {
    queueMicrotask(() => navigate(nextPath(query), { replace: true }));
  }
  const errorEl = h("div", { class: "error-text", role: "alert" });
  const name = h("input", { class: "input", name: "username", autocomplete: "username webauthn", autocapitalize: "off", spellcheck: "false", placeholder: "Username" }) as HTMLInputElement;
  const password = h("input", { class: "input", type: "password", name: "password", autocomplete: "current-password", placeholder: "Password" }) as HTMLInputElement;
  const conditional = new AbortController();

  const done = async () => {
    conditional.abort();
    await loadSession();
    navigate(nextPath(query), { replace: true });
  };

  const passkeyBtn = h("button", { type: "button", class: "btn primary lg block" }, icon("fingerprint"), "Sign in with a passkey") as HTMLButtonElement;
  passkeyBtn.addEventListener("click", () =>
    void busy(passkeyBtn, async () => {
      errorEl.textContent = "";
      conditional.abort();
      try {
        await signInWithPasskey(name.value.trim() || undefined);
        await done();
      } catch (e) {
        errorEl.textContent = e instanceof DOMException ? friendlyError(e) : errorMessage(e);
      }
    }),
  );

  const pwBtn = h("button", { type: "submit", class: "btn block" }, "Sign in with password") as HTMLButtonElement;
  const form = h(
    "form",
    { class: "stack" },
    field("Username", name),
    field("Password", password),
    pwBtn,
  ) as HTMLFormElement;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void busy(pwBtn, async () => {
      errorEl.textContent = "";
      try {
        await api("POST", "/api/login/password", { name: name.value.trim(), password: password.value });
        await done();
      } catch (err) {
        errorEl.textContent = errorMessage(err);
      }
    });
  });

  // Offer passkeys in the username field's autofill where supported.
  void conditionalMediationAvailable().then((ok) => {
    if (!ok) return;
    signInWithPasskey(undefined, conditional.signal)
      .then(done)
      .catch(() => {});
  });

  const pw = h("details", { class: "more" }, h("summary", {}, icon("chevron"), "Use a password instead"), h("div", { style: "margin-top:12px" }, form));
  const card = wrap(
    ...brandHeader(s.name, "Approve privileged commands from your agents."),
    h("div", { class: "card pad stack" }, passkeysSupported() ? passkeyBtn : h("p", { class: "muted small" }, "This browser doesn't support passkeys."), errorEl, pw),
    h("p", { class: "tiny faint", style: "text-align:center" }, "Sessions stay signed in on this device until they expire or you revoke them."),
  );
  return { el: card.el, dispose: () => conditional.abort() };
}

// ---------------------------------------------------------------------------

export async function setupRoute(): Promise<Mounted> {
  const s = currentSession();
  if (!s.setup_required) {
    queueMicrotask(() => navigate("/", { replace: true }));
  }
  const token = location.hash.slice(1);
  const errorEl = h("div", { class: "error-text", role: "alert" });
  const name = h("input", { class: "input", autocomplete: "username", autocapitalize: "off", spellcheck: "false", value: "" }) as HTMLInputElement;
  const display = h("input", { class: "input", autocomplete: "name" }) as HTMLInputElement;
  const password = h("input", { class: "input", type: "password", autocomplete: "new-password", minlength: "12" }) as HTMLInputElement;
  const submit = h("button", { type: "submit", class: "btn primary lg block" }, "Create administrator") as HTMLButtonElement;
  const form = h(
    "form",
    { class: "card pad stack" },
    field("Username", name),
    field("Display name", display, "Shown on approvals and in the audit log."),
    field("Password", password, "At least 12 characters. You'll add a passkey next; the password is for recovery."),
    errorEl,
    submit,
  ) as HTMLFormElement;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void busy(submit, async () => {
      errorEl.textContent = "";
      try {
        await api("POST", "/api/setup", { token, name: name.value.trim(), display_name: display.value.trim(), password: password.value });
        history.replaceState(null, "", "/setup");
        await loadSession();
        navigate("/welcome", { replace: true });
      } catch (err) {
        errorEl.textContent = errorMessage(err);
      }
    });
  });
  const missing = !token
    ? h("div", { class: "tip warn" }, icon("alert"), h("div", {}, "Open the setup link printed in the service log. It contains a one-time token after the ", h("code", {}, "#"), "."))
    : null;
  return wrap(...brandHeader("Welcome to agent-sudo", "Create the first administrator for this approval service."), ...(missing ? [missing] : []), form);
}

// ---------------------------------------------------------------------------

export async function inviteRoute(): Promise<Mounted> {
  const token = location.hash.slice(1);
  const errorEl = h("div", { class: "error-text", role: "alert" });
  let who: { name: string; display_name: string; role: string };
  try {
    who = await api("POST", "/api/invite/inspect", { token });
  } catch (e) {
    return wrap(...brandHeader("Invitation unavailable", errorMessage(e)), h("a", { class: "btn block", href: "/login" }, "Go to sign in"));
  }
  const password = h("input", { class: "input", type: "password", autocomplete: "new-password" }) as HTMLInputElement;
  const submit = h("button", { type: "submit", class: "btn primary lg block" }, "Continue") as HTMLButtonElement;
  const form = h(
    "form",
    { class: "card pad stack" },
    h("input", { type: "text", autocomplete: "username", value: who.name, class: "hidden", readonly: true }),
    field("Choose a password", password, "At least 12 characters. You'll add a passkey on the next screen."),
    errorEl,
    submit,
  ) as HTMLFormElement;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void busy(submit, async () => {
      errorEl.textContent = "";
      try {
        await api("POST", "/api/invite/accept", { token, password: password.value });
        history.replaceState(null, "", "/invite");
        await loadSession();
        navigate("/welcome", { replace: true });
      } catch (err) {
        errorEl.textContent = errorMessage(err);
      }
    });
  });
  return wrap(...brandHeader(`Hi ${who.display_name}`, `You've been invited as ${who.role === "admin" ? "an administrator" : `an ${who.role}`}. Set up your account.`), form);
}

// ---------------------------------------------------------------------------

/** Three steps: passkey, notifications, first host. */
export async function welcomeRoute(_: Record<string, string>, query: URLSearchParams): Promise<Mounted> {
  const card = h("div", { class: "auth-card" });
  const el = h("div", { class: "auth-wrap" }, card);
  let step = Number(query.get("step") ?? 0);
  const s = () => currentSession();

  const steps = (n: number) => h("div", { class: "steps", "aria-label": `Step ${n + 1} of 3` }, ...[0, 1, 2].map((i) => h("i", { class: i <= n ? "on" : "" })));

  const go = (n: number) => {
    step = n;
    history.replaceState(null, "", `/welcome?step=${n}`);
    render();
  };

  function passkeyStep() {
    const errorEl = h("div", { class: "error-text", role: "alert" });
    const btn = h("button", { type: "button", class: "btn primary lg block" }, icon("fingerprint"), "Create a passkey") as HTMLButtonElement;
    btn.addEventListener("click", () =>
      void busy(btn, async () => {
        errorEl.textContent = "";
        try {
          await registerPasskey(s().device?.label ?? "This device");
          await loadSession();
          toast("Passkey saved");
          go(1);
        } catch (e) {
          errorEl.textContent = e instanceof DOMException ? friendlyError(e) : errorMessage(e);
        }
      }),
    );
    const already = (s().passkeys ?? 0) > 0;
    return [
      steps(0),
      h("div", { class: "brand" }, h("span", { class: "brand-mark" }, icon("fingerprint"))),
      h("h1", {}, "Secure your account"),
      h("p", { class: "lead" }, "Approving root access should take your face, fingerprint, or device PIN, not a password. Passkeys sync through iCloud Keychain, Google Password Manager, or Windows Hello."),
      h("div", { class: "card pad stack" }, already ? h("div", { class: "tip" }, icon("check"), h("div", {}, "You already have a passkey. You can add another for this device.")) : null, btn, errorEl),
      h("button", { type: "button", class: "btn ghost block", onclick: () => go(1) }, already ? "Continue" : "Not now"),
    ];
  }

  function notifyStep() {
    const support = pushSupport();
    const errorEl = h("div", { class: "error-text", role: "alert" });
    const body = h("div", { class: "card pad stack" });
    if (!support.ok && support.reason === "ios-needs-install") {
      body.append(
        h("div", { class: "tip" }, icon("info"), h("div", {}, "On iPhone and iPad, notifications work once agent-sudo is on your Home Screen.")),
        h("ol", { class: "stack tight", style: "margin:0;padding-left:20px" },
          h("li", {}, "Tap ", h("span", { class: "kbd" }, icon("share"), "Share"), " in Safari's toolbar."),
          h("li", {}, "Choose ", h("span", { class: "kbd" }, icon("addHome"), "Add to Home Screen"), "."),
          h("li", {}, "Open agent-sudo from your Home Screen and come back to this step (Settings → This device)."),
        ),
      );
    } else if (!support.ok) {
      const why: Record<string, string> = {
        unsupported: "This browser can't receive web push notifications. Try Edge, Chrome, Firefox, or Safari 16.4+.",
        denied: "Notifications are blocked for this site. Allow them in the browser's site settings, then reload.",
        "disabled-on-server": "Push notifications are disabled in the service configuration.",
      };
      body.append(h("div", { class: "tip warn" }, icon("alert"), h("div", {}, why[support.reason] ?? "Notifications are unavailable.")));
    } else {
      const btn = h("button", { type: "button", class: "btn primary lg block" }, icon("bell"), "Enable notifications") as HTMLButtonElement;
      btn.addEventListener("click", () =>
        void busy(btn, async () => {
          errorEl.textContent = "";
          try {
            await enablePush();
            await api("POST", "/api/push/test");
            toast("Notifications enabled. A test is on its way.");
            go(2);
          } catch (e) {
            errorEl.textContent = errorMessage(e);
          }
        }),
      );
      body.append(
        h("p", { class: "muted small" }, isIOS() && isStandalone() ? "You'll get an alert on this device when an agent needs sudo." : "Edge and Chrome can approve routine requests straight from the notification. Everything else opens here."),
        btn,
        errorEl,
      );
    }
    return [
      steps(1),
      h("div", { class: "brand" }, h("span", { class: "brand-mark" }, icon("bell"))),
      h("h1", {}, "Get notified"),
      h("p", { class: "lead" }, "When an agent runs sudo, this device lights up. One tap to review, one tap to decide."),
      body,
      h("button", { type: "button", class: "btn ghost block", onclick: () => go(2) }, "Skip for now"),
    ];
  }

  function hostStep() {
    const admin = s().user?.role === "admin";
    return [
      steps(2),
      h("div", { class: "brand" }, h("span", { class: "brand-mark" }, icon("server"))),
      h("h1", {}, "You're set"),
      h("p", { class: "lead" }, admin ? "Enroll your first machine: agent-sudo-hostd connects it to this service, and agents keep typing sudo like always." : "Requests from enrolled hosts will appear on the Requests tab."),
      admin ? h("a", { class: "btn primary lg block", href: "/hosts?add=1" }, icon("plus"), "Add a host") : null,
      h("a", { class: "btn block", href: "/" }, "Go to requests"),
    ];
  }

  function render() {
    const parts = step === 0 ? passkeyStep() : step === 1 ? notifyStep() : hostStep();
    card.replaceChildren(...(parts.filter(Boolean) as Node[]));
  }
  render();
  return { el };
}
