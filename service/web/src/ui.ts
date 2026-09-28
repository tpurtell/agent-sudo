// Generic UI building blocks.

import { type Child, h, icon, type IconName } from "./dom";

// ---------------------------------------------------------------------------
// Toasts

let toastHost: HTMLElement | null = null;

export function toast(message: string, kind: "ok" | "bad" | "info" = "ok", ms = 3200): void {
  toastHost ??= document.body.appendChild(h("div", { class: "toasts", role: "status", "aria-live": "polite" }));
  const glyph: IconName = kind === "ok" ? "check" : kind === "bad" ? "alert" : "info";
  const el = h("div", { class: ["toast", kind] }, icon(glyph), h("span", {}, message));
  toastHost.appendChild(el);
  setTimeout(() => {
    el.classList.add("leaving");
    setTimeout(() => el.remove(), 260);
  }, ms);
}

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ---------------------------------------------------------------------------
// Buttons with a busy state

export function busy<T>(btn: HTMLButtonElement, work: () => Promise<T>): Promise<T | undefined> {
  if (btn.disabled) return Promise.resolve(undefined);
  const original = Array.from(btn.childNodes);
  const width = btn.getBoundingClientRect().width;
  btn.disabled = true;
  btn.style.minWidth = `${width}px`;
  btn.replaceChildren(h("span", { class: "spinner" }));
  return work()
    .catch((e) => {
      toast(errorMessage(e), "bad", 5000);
      return undefined;
    })
    .finally(() => {
      btn.disabled = false;
      btn.style.minWidth = "";
      btn.replaceChildren(...original);
    });
}

export function button(label: Child, onClick: (btn: HTMLButtonElement) => void | Promise<unknown>, cls = "", attrs: Record<string, unknown> = {}): HTMLButtonElement {
  const btn = h("button", { type: "button", class: `btn ${cls}`, ...attrs }, label) as HTMLButtonElement;
  btn.addEventListener("click", () => {
    const r = onClick(btn);
    if (r instanceof Promise) void busy(btn, () => r);
  });
  return btn;
}

/** A button whose click handler is async and shows a spinner while running. */
export function action(label: Child, work: () => Promise<unknown>, cls = "", attrs: Record<string, unknown> = {}): HTMLButtonElement {
  const btn = h("button", { type: "button", class: `btn ${cls}`, ...attrs }, label) as HTMLButtonElement;
  btn.addEventListener("click", () => void busy(btn, work));
  return btn;
}

// ---------------------------------------------------------------------------
// Segmented control

export interface Option<T extends string> {
  value: T;
  label: string;
  sub?: string;
  disabled?: boolean;
  title?: string;
}

export function segmented<T extends string>(options: Option<T>[], value: T, onChange: (v: T) => void, label?: string): HTMLElement & { set(v: T): void } {
  const el = h("div", { class: "segmented", role: "radiogroup", "aria-label": label ?? "" }) as unknown as HTMLElement & { set(v: T): void };
  const buttons = options.map((o) => {
    const b = h(
      "button",
      { type: "button", role: "radio", disabled: o.disabled, title: o.title ?? "", "aria-checked": String(o.value === value) },
      o.label,
      o.sub ? h("span", { class: "sub" }, o.sub) : null,
    ) as HTMLButtonElement;
    b.classList.toggle("on", o.value === value);
    b.addEventListener("click", () => {
      if (o.disabled) return;
      el.set(o.value);
      onChange(o.value);
    });
    return b;
  });
  el.set = (v: T) => {
    buttons.forEach((b, i) => {
      const on = options[i]!.value === v;
      b.classList.toggle("on", on);
      b.setAttribute("aria-checked", String(on));
    });
  };
  buttons.forEach((b) => el.appendChild(b));
  return el;
}

export function toggle(checked: boolean, onChange: (v: boolean) => void, cls = "", label = ""): HTMLLabelElement {
  const input = h("input", { type: "checkbox", checked, "aria-label": label }) as HTMLInputElement;
  input.addEventListener("change", () => onChange(input.checked));
  return h("label", { class: `switch ${cls}` }, input, h("span")) as HTMLLabelElement;
}

// ---------------------------------------------------------------------------
// Sheets (bottom sheet on phones, dialog on desktop)

export function sheet(build: (close: () => void) => Child, opts: { label?: string } = {}): () => void {
  const scrim = h("div", { class: "scrim" });
  const panel = h("div", { class: "sheet", role: "dialog", "aria-modal": "true", "aria-label": opts.label ?? "" }, h("div", { class: "grabber" }));
  const previous = document.activeElement as HTMLElement | null;
  const close = () => {
    scrim.remove();
    document.removeEventListener("keydown", onKey);
    previous?.focus?.();
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") close();
  };
  scrim.addEventListener("click", (e) => {
    if (e.target === scrim) close();
  });
  document.addEventListener("keydown", onKey);
  const content = build(close);
  if (Array.isArray(content)) content.forEach((c) => c && panel.append(c as Node));
  else if (content instanceof Node) panel.append(content);
  scrim.appendChild(panel);
  document.body.appendChild(scrim);
  const focusable = panel.querySelector<HTMLElement>("input, textarea, button:not(.ghost)");
  setTimeout(() => focusable?.focus(), 50);
  return close;
}

export function confirmSheet(title: string, body: Child, confirmLabel: string, danger = false): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: boolean, close: () => void) => {
      if (done) return;
      done = true;
      close();
      resolve(v);
    };
    sheet((close) => [
      h("h2", {}, title),
      h("div", { class: "muted", style: "margin: 6px 0 18px" }, body),
      h(
        "div",
        { class: "row", style: "justify-content: flex-end" },
        button("Cancel", () => finish(false, close), "ghost"),
        button(confirmLabel, () => finish(true, close), danger ? "danger" : "primary"),
      ),
    ]);
  });
}

let fieldSeq = 0;

/** A labelled form field. Labels are linked to their control for assistive tech. */
export function field(label: string, input: HTMLElement, hint?: string): HTMLElement {
  const id = `f${++fieldSeq}`;
  const control = input.matches("input, textarea, select") ? input : input.querySelector<HTMLElement>("input:not([type=hidden]), textarea, select");
  const hintEl = hint ? h("div", { class: "hint", id: `${id}-hint` }, hint) : null;
  let labelEl: HTMLElement;
  if (control && !input.classList.contains("segmented")) {
    control.id ||= id;
    labelEl = h("label", { for: control.id }, label);
    if (hintEl) control.setAttribute("aria-describedby", hintEl.id);
  } else {
    labelEl = h("div", { class: "label", id: `${id}-label` }, label);
    input.setAttribute("aria-labelledby", labelEl.id);
  }
  return h("div", { class: "field" }, labelEl, input, hintEl);
}

export function emptyState(glyph: IconName, title: string, body: Child, action?: Child): HTMLElement {
  return h("div", { class: "empty" }, h("div", { class: "glyph" }, icon(glyph)), h("h3", {}, title), h("p", { class: "small" }, body), action ?? null);
}

export function loading(): HTMLElement {
  return h("div", { class: "empty" }, h("span", { class: "spinner" }));
}
