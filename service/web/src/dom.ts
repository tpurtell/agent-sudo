// Tiny DOM toolkit: hyperscript, icons, and formatting helpers.

export type Child = Node | string | number | null | undefined | false | Child[];
type Handler = (ev: any) => void;
export interface Props {
  class?: string | (string | false | null | undefined)[];
  style?: string | Partial<CSSStyleDeclaration> | Record<string, string>;
  dataset?: Record<string, string>;
  [key: string]: unknown;
}

function isProps(v: unknown): v is Props {
  return typeof v === "object" && v !== null && !(v instanceof Node) && !Array.isArray(v);
}

export function append(parent: Node, child: Child): void {
  if (child === null || child === undefined || child === false) return;
  if (Array.isArray(child)) {
    for (const c of child) append(parent, c);
  } else if (child instanceof Node) {
    parent.appendChild(child);
  } else {
    parent.appendChild(document.createTextNode(String(child)));
  }
}

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, props?: Props | Child, ...children: Child[]): HTMLElementTagNameMap[K];
export function h(tag: string, props?: Props | Child, ...children: Child[]): HTMLElement;
export function h(tag: string, props?: Props | Child, ...children: Child[]): HTMLElement {
  const el = document.createElement(tag);
  if (isProps(props)) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "class") {
        el.className = Array.isArray(value) ? value.filter(Boolean).join(" ") : String(value);
      } else if (key === "style") {
        if (typeof value === "string") el.setAttribute("style", value);
        else Object.assign(el.style, value);
      } else if (key === "dataset") {
        Object.assign(el.dataset, value as Record<string, string>);
      } else if (key.startsWith("on") && typeof value === "function") {
        el.addEventListener(key.slice(2).toLowerCase(), value as Handler);
      } else if (key === "value" && "value" in el) {
        (el as HTMLInputElement).value = String(value);
      } else if (key === "checked" || key === "disabled" || key === "selected" || key === "autofocus") {
        (el as any)[key] = Boolean(value);
        if (value) el.setAttribute(key, "");
      } else if (value === true) {
        el.setAttribute(key, "");
      } else {
        el.setAttribute(key, String(value));
      }
    }
  } else {
    append(el, props as Child);
  }
  append(el, children);
  return el;
}

export function clear(el: Element): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function replace(el: Element, ...children: Child[]): void {
  clear(el);
  append(el, children);
}

// ---------------------------------------------------------------------------
// Icons (static, trusted SVG markup)

const P: Record<string, string> = {
  hash: '<path d="M9 3 7 21M17 3l-2 18M4 8.5h17M3 15.5h17"/>',
  shield: '<path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6L12 3Z"/>',
  shieldCheck: '<path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6L12 3Z"/><path d="m8.8 12 2.2 2.2 4.4-4.6"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  terminal: '<rect x="3" y="4.5" width="18" height="15" rx="3"/><path d="m7.5 9.5 3 2.5-3 2.5M12.5 15h4"/>',
  server: '<rect x="3.5" y="4" width="17" height="7" rx="2"/><rect x="3.5" y="13" width="17" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  sparkle: '<path d="M12 3.5c.6 3.9 2.6 5.9 6.5 6.5-3.9.6-5.9 2.6-6.5 6.5-.6-3.9-2.6-5.9-6.5-6.5 3.9-.6 5.9-2.6 6.5-6.5Z"/><path d="M18.5 15.5c.3 1.7 1.1 2.5 2.8 2.8-1.7.3-2.5 1.1-2.8 2.8-.3-1.7-1.1-2.5-2.8-2.8 1.7-.3 2.5-1.1 2.8-2.8Z"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8.5-8.5M16.5 6.5l2.5 2.5M14.5 8.5l2 2"/>',
  bell: '<path d="M6 16.5V11a6 6 0 1 1 12 0v5.5l1.5 2h-15l1.5-2Z"/><path d="M10 20.5a2.2 2.2 0 0 0 4 0"/>',
  bellOff: '<path d="M8.5 5.6A6 6 0 0 1 18 11v4M6 11v5.5l-1.5 2H17M10 20.5a2.2 2.2 0 0 0 4 0M3 3l18 18"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2.8v2.4M12 18.8v2.4M4.2 7.5l2.1 1.2M17.7 15.3l2.1 1.2M4.2 16.5l2.1-1.2M17.7 8.7l2.1-1.2"/><circle cx="12" cy="12" r="7"/>',
  inbox: '<path d="M3.5 13.5 6 5.5h12l2.5 8V18a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2v-4.5Z"/><path d="M3.5 13.5H8l1.5 2.5h5l1.5-2.5h4.5"/>',
  activity: '<path d="M3 12h4l2.5-6 5 12 2.5-6H21"/>',
  user: '<circle cx="12" cy="8.5" r="4"/><path d="M4.5 20c1.2-3.6 4-5.5 7.5-5.5s6.3 1.9 7.5 5.5"/>',
  users: '<circle cx="9" cy="9" r="3.5"/><path d="M2.5 19.5c.9-3 3.3-4.5 6.5-4.5s5.6 1.5 6.5 4.5M15.5 5.8a3.5 3.5 0 0 1 0 6.4M17.5 15.3c2 .6 3.3 2 4 4.2"/>',
  fingerprint: '<path d="M7.5 5.2A8 8 0 0 1 20 12v1.5M4 12a8 8 0 0 1 1.3-4.4M4.2 16.5c.9-1.3 1.3-2.8 1.3-4.5a6.5 6.5 0 0 1 13 0v2M12 12v2c0 3-1 5.5-3 7.5M15.5 13.5c0 2.8-.5 5-1.8 7M9 12a3 3 0 0 1 6 0M18.2 17.5c-.3 1.2-.8 2.3-1.3 3.2"/>',
  copy: '<rect x="8.5" y="8.5" width="12" height="12" rx="2.5"/><path d="M15.5 8.5v-2a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  trash: '<path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13"/>',
  pause: '<rect x="6.5" y="5" width="3.5" height="14" rx="1"/><rect x="14" y="5" width="3.5" height="14" rx="1"/>',
  play: '<path d="M7 5v14l12-7L7 5Z"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="2.5"/>',
  chevron: '<path d="m9 5.5 6.5 6.5L9 18.5"/>',
  back: '<path d="M15 5.5 8.5 12l6.5 6.5"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5M12 7.8v.2"/>',
  alert: '<path d="M12 3.5 2.5 20h19L12 3.5Z"/><path d="M12 10v4.5M12 17.3v.2"/>',
  logout: '<path d="M14.5 4.5h3a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2h-3M10 16.5 14.5 12 10 7.5M14.5 12H4"/>',
  refresh: '<path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4h-4"/>',
  share: '<path d="M12 3.5v11M8 7.5l4-4 4 4M6.5 11H5v9.5h14V11h-1.5"/>',
  addHome: '<rect x="4" y="4" width="16" height="16" rx="4"/><path d="M12 8.5v7M8.5 12h7"/>',
  laptop: '<rect x="5" y="5" width="14" height="10" rx="1.5"/><path d="M3 18.5h18"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
  flag: '<path d="M5.5 21V4.5M5.5 4.5h11l-2 4 2 4h-11"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>',
  bot: '<rect x="4.5" y="8" width="15" height="11.5" rx="3.5"/><path d="M12 4.5V8M9 13.5v.5M15 13.5v.5M2.5 13v2M21.5 13v2"/>',
  history: '<path d="M4 12a8 8 0 1 0 2.4-5.7M4 4.5v4h4M12 8v4.5l3 1.5"/>',
  hand: '<path d="M8 12V6.5a1.5 1.5 0 0 1 3 0V11M11 10.5V4.5a1.5 1.5 0 0 1 3 0v6M14 10.5V6a1.5 1.5 0 0 1 3 0v7.5c0 4-2.5 7-6.5 7-2.7 0-4.2-1.3-5.8-3.8L3 13.8a1.5 1.5 0 0 1 2.4-1.8L8 14.5"/>',
  gauge: '<path d="M4 16.5a8 8 0 1 1 16 0"/><path d="m12 16.5 4-5"/>',
  download: '<path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16v4Z"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  zap: '<path d="M13 2.5 5 13.5h6l-1 8 8-11h-6l1-8Z"/>',
};

export type IconName = keyof typeof P;

export function icon(name: IconName, cls = ""): SVGSVGElement {
  const tpl = document.createElement("template");
  tpl.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="${cls}">${P[name]}</svg>`;
  return tpl.content.firstElementChild as SVGSVGElement;
}

// ---------------------------------------------------------------------------
// Formatting

export function timeAgo(ms: number, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const hr = Math.round(m / 60);
  if (hr < 24) return `${hr}h ago`;
  const d = Math.round(hr / 24);
  if (d < 7) return `${d}d ago`;
  return new Date(ms).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function duration(sec: number): string {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m`;
  const hr = Math.floor(m / 60);
  const rm = m % 60;
  if (hr < 24) return rm ? `${hr}h ${rm}m` : `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

export function minutesLabel(min: number): string {
  if (min < 60) return `${min} min`;
  const hr = min / 60;
  return Number.isInteger(hr) ? `${hr} hour${hr === 1 ? "" : "s"}` : `${hr.toFixed(1)} hours`;
}

export function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
}

export function dayLabel(ms: number): string {
  const d = new Date(ms);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86_400_000);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
  return d.toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" });
}

export function initials(name: string): string {
  return name.split(/[\s._-]+/).filter(Boolean).slice(0, 2).map((p) => p[0]!.toUpperCase()).join("") || "?";
}

export function isStandalone(): boolean {
  return window.matchMedia("(display-mode: standalone)").matches || (navigator as any).standalone === true;
}

export function isIOS(): boolean {
  return /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = h("textarea", { style: "position:fixed;opacity:0" }, text) as HTMLTextAreaElement;
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}
