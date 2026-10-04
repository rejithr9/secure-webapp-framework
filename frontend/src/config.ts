import { createContext, useContext, type ReactNode } from "react";

/** A page the app adds to the signed-in area. */
export interface NavItem {
  /** URL path, e.g. "/notes". Must not clash with framework paths (/keys, /activity, /account, /admin, /sign-in, /welcome). */
  path: string;
  /** Label in the top navigation. Omit to add a route without a nav link. */
  label?: string;
  element: ReactNode;
  /** Only shown to and reachable by admins. */
  adminOnly?: boolean;
}

/** How an app customises the framework UI. Everything is optional except `home`. */
export interface SwfAppConfig {
  /** The page at "/" after sign-in (your dashboard). */
  home: ReactNode;
  /** Extra pages, in nav order (after "Home"). */
  nav?: NavItem[];
  /** Label for the "/" nav link. Default "Home". */
  homeLabel?: string;
  /** Logo shown next to the app name. Default: the framework mark. */
  logoSrc?: string;
  /** Rendered inside the signed-in shell, e.g. a floating assistant button. */
  shellExtras?: ReactNode;
  /** Shown under the sign-in forms, e.g. a support contact. */
  signInFooter?: ReactNode;
}

export const SwfConfigContext = createContext<SwfAppConfig | null>(null);

export function useSwfConfig(): SwfAppConfig {
  const value = useContext(SwfConfigContext);
  if (!value) throw new Error("useSwfConfig must be used inside <SwfApp>");
  return value;
}

export const FRAMEWORK_PATHS = ["/keys", "/activity", "/account", "/admin", "/sign-in", "/welcome"];

export const DEFAULT_LOGO =
  "data:image/svg+xml;base64," +
  btoa(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#1f5f8b"/>' +
      '<path d="M16 6l8 3v6c0 5-3.4 8.7-8 10.5C11.4 23.7 8 20 8 15V9z" fill="none" stroke="#fff" stroke-width="2.4" stroke-linejoin="round"/></svg>',
  );
