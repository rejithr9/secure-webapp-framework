import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { get, onSignedOut, post, put, type Me, type PublicConfig, type SessionState, type Theme } from "./api";

interface AuthContextValue {
  state: SessionState | null; // null while loading
  config: PublicConfig | null;
  notice: string | null; // e.g. "your session ended"
  refresh: () => Promise<SessionState>;
  signOut: () => Promise<void>;
  setTheme: (theme: Theme) => void;
  theme: Theme;
  clearNotice: () => void;
  showNotice: (message: string) => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const THEME_KEY = "swf-theme";

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    /* storage unavailable */
  }
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* storage unavailable */
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionState | null>(null);
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [theme, setThemeState] = useState<Theme>(initialTheme);

  useEffect(() => applyTheme(theme), [theme]);

  useEffect(() => {
    if (config) document.title = config.app_name;
  }, [config]);

  const refresh = useCallback(async () => {
    const next = await get<SessionState>("/api/auth/session");
    setState(next);
    if (next.user) setThemeState(next.user.theme);
    return next;
  }, []);

  useEffect(() => {
    get<PublicConfig>("/api/config")
      .then(setConfig)
      .catch(() => undefined);
    refresh().catch(() => setState({ stage: "signed_out", user: null }));
    return onSignedOut(() => {
      setNotice("Your session has ended. Please sign in again.");
      setState({ stage: "signed_out", user: null });
    });
  }, [refresh]);

  const signOut = useCallback(async () => {
    await post("/api/auth/logout").catch(() => undefined);
    setState({ stage: "signed_out", user: null });
  }, []);

  const setTheme = useCallback(
    (t: Theme) => {
      setThemeState(t);
      if (state?.stage === "full") {
        put<Me>("/api/me/preferences", { theme: t }).catch(() => undefined);
      }
    },
    [state?.stage],
  );

  return (
    <AuthContext.Provider
      value={{
        state,
        config,
        notice,
        refresh,
        signOut,
        setTheme,
        theme,
        clearNotice: () => setNotice(null),
        showNotice: setNotice,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <SwfApp>");
  return ctx;
}

/** The page the user must be on for their current sign-in state, or null if they are free to roam. */
export function requiredPath(state: SessionState): string | null {
  switch (state.stage) {
    case "signed_out":
      return "/sign-in";
    case "totp_setup":
      return "/sign-in/set-up-2fa";
    case "totp_verify":
      return "/sign-in/code";
    case "full":
      if (state.user?.next === "change_password") return "/welcome/password";
      if (state.user?.next === "accept_terms") return "/welcome/terms";
      return null;
  }
}
