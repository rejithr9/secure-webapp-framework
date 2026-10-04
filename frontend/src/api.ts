// Small fetch wrapper: same-origin cookies, CSRF header, plain-English errors.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

type Listener = () => void;
const signedOutListeners = new Set<Listener>();

/** Called when the server says the session has ended, so the app can go back to sign-in. */
export function onSignedOut(listener: Listener): () => void {
  signedOutListeners.add(listener);
  return () => signedOutListeners.delete(listener);
}

function readCookie(name: string): string {
  const match = document.cookie.split("; ").find((c) => c.startsWith(name + "="));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : "";
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = readCookie("swf_csrf");

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "network", "We can't reach the server. Check your internet connection and try again.");
  }

  if (response.status === 204) return undefined as T;
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const code = data?.code ?? "unknown";
    const message =
      data?.message ?? "Something went wrong on our side. Please try again in a minute.";
    if (response.status === 401 && (code === "not_signed_in" || code === "second_step_required")) {
      signedOutListeners.forEach((l) => l());
    }
    throw new ApiError(response.status, code, message);
  }
  return data as T;
}

export const get = <T>(path: string) => api<T>("GET", path);
export const post = <T>(path: string, body?: unknown) => api<T>("POST", path, body ?? {});
export const put = <T>(path: string, body: unknown) => api<T>("PUT", path, body);
export const del = <T>(path: string, body?: unknown) => api<T>("DELETE", path, body);

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  return "Something went wrong. Please reload the page and try again.";
}

// ---- Shared response types ----

export type Theme = "light" | "dark";
export type NextStep = "change_password" | "accept_terms" | "dashboard";

export interface Me {
  username: string;
  role: "user" | "admin";
  theme: Theme;
  must_change_password: boolean;
  terms_accepted: boolean;
  next: NextStep;
}

export type Stage = "signed_out" | "totp_setup" | "totp_verify" | "full";

export interface SessionState {
  stage: Stage;
  user: Me | null;
  passkey_available?: boolean;
  recovery_available?: boolean;
}

/** Public facts about the app, from GET /api/config. */
export interface PublicConfig {
  app_name: string;
  terms_enabled: boolean;
  passkeys: "off" | "second_factor";
  recovery_codes: boolean;
  keys_enabled: boolean;
  password_min_length: number;
}

export function formatWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
}
