// Minimal history router.

export interface Mounted {
  el: HTMLElement;
  dispose?: () => void;
}
export type Page = (params: Record<string, string>, query: URLSearchParams) => Mounted | Promise<Mounted>;

interface Route {
  pattern: RegExp;
  keys: string[];
  page: Page;
  shell: boolean;
  public: boolean;
}

const routes: Route[] = [];
let render: (route: Route, params: Record<string, string>, query: URLSearchParams) => void = () => {};

export function route(path: string, page: Page, opts: { shell?: boolean; public?: boolean } = {}): void {
  const keys: string[] = [];
  const pattern = new RegExp(
    "^" + path.replace(/\/:([a-z_]+)/g, (_, k) => (keys.push(k), "/([^/]+)")) + "/?$",
  );
  routes.push({ pattern, keys, page, shell: opts.shell ?? true, public: opts.public ?? false });
}

export function onRender(fn: typeof render): void {
  render = fn;
}

export function resolve(pathname: string): { route: Route; params: Record<string, string> } | null {
  for (const r of routes) {
    const m = r.pattern.exec(pathname);
    if (m) {
      const params: Record<string, string> = {};
      r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1]!)));
      return { route: r, params };
    }
  }
  return null;
}

export function navigate(path: string, opts: { replace?: boolean } = {}): void {
  if (opts.replace) history.replaceState(null, "", path);
  else if (path !== location.pathname + location.search) history.pushState(null, "", path);
  dispatch();
}

export function dispatch(): void {
  const found = resolve(location.pathname) ?? resolve("/")!;
  render(found.route, found.params, new URLSearchParams(location.search));
}

export function startRouter(): void {
  window.addEventListener("popstate", dispatch);
  document.addEventListener("click", (e) => {
    const a = (e.target as Element).closest?.("a");
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const href = a.getAttribute("href");
    if (!href || !href.startsWith("/") || href.startsWith("/api/") || a.target || a.hasAttribute("download")) return;
    e.preventDefault();
    navigate(href);
    window.scrollTo({ top: 0 });
  });
}

export type { Route };
