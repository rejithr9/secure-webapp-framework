import { useState, type FormEvent } from "react";
import { errorMessage, post } from "../api";
import { useAuth } from "../auth";
import { Alert, AuthCard, CodeField, Field } from "../components/ui";
import { passkeysSupported, signInWithPasskey } from "../webauthn";

export function SignInPage() {
  const { refresh, notice, clearNotice } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    clearNotice();
    try {
      await post("/api/auth/login", { username, password });
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <AuthCard>
      <h1>Sign in</h1>
      <p className="muted">Enter your username and password. Next, you'll confirm it's you with a second step.</p>
      <Alert kind="info">{notice}</Alert>
      <Alert kind="error">{error}</Alert>
      <form onSubmit={submit}>
        <Field
          label="Username"
          autoComplete="username"
          autoFocus
          required
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <Field
          label="Password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint="First time here? Use the one-time password the administrator gave you."
        />
        <button className="primary" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Continue"}
        </button>
      </form>
    </AuthCard>
  );
}

type Method = "code" | "recovery";

export function SecondStepPage() {
  const { state, refresh, signOut, showNotice } = useAuth();
  const [method, setMethod] = useState<Method>("code");
  const [code, setCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const canPasskey = !!state?.passkey_available && passkeysSupported();

  async function attempt(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      await refresh();
    } catch (err) {
      const message = errorMessage(err);
      setCode("");
      setBusy(false);
      // After too many wrong tries the sign-in is cancelled and we go back to the first step.
      const now = await refresh().catch(() => null);
      if (now && now.stage !== "totp_verify") showNotice(message);
      else setError(message);
    }
  }

  async function submitRecovery(e: FormEvent) {
    e.preventDefault();
    await attempt(async () => {
      const r = await post<{ recovery_codes_left: number }>("/api/auth/recovery", { code: recoveryCode });
      if (r.recovery_codes_left <= 3) {
        showNotice(
          `You have ${r.recovery_codes_left} recovery code(s) left. Create new ones under My account soon.`,
        );
      }
    });
  }

  return (
    <AuthCard>
      <h1>Confirm it's you</h1>
      <Alert kind="error">{error}</Alert>
      {canPasskey && (
        <div className="passkey-choice">
          <button className="primary" disabled={busy} onClick={() => attempt(signInWithPasskey)}>
            Use my passkey
          </button>
          <p className="small muted">Uses your fingerprint, face, device PIN or security key.</p>
          <div className="divider">
            <span>or</span>
          </div>
        </div>
      )}
      {method === "code" ? (
        <form onSubmit={(e) => (e.preventDefault(), attempt(() => post("/api/auth/totp/verify", { code })))}>
          <p className="muted">Type the 6-digit code from your authenticator app.</p>
          <CodeField value={code} onChange={setCode} autoFocus={!canPasskey} />
          <div className="actions">
            <button className={canPasskey ? "" : "primary"} type="submit" disabled={busy || code.length !== 6}>
              {busy ? "Checking…" : "Sign in"}
            </button>
            <button type="button" className="link" onClick={() => signOut()}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={submitRecovery}>
          <Field
            label="Recovery code"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            required
            value={recoveryCode}
            onChange={(e) => setRecoveryCode(e.target.value)}
            hint="One of the codes you saved when you set up your account, like ABCDE-FGHJK. Each code works once."
          />
          <div className="actions">
            <button className="primary" type="submit" disabled={busy || recoveryCode.trim().length < 10}>
              {busy ? "Checking…" : "Sign in"}
            </button>
            <button type="button" className="link" onClick={() => setMethod("code")}>
              Use my authenticator app instead
            </button>
          </div>
        </form>
      )}
      <p className="small muted" style={{ marginTop: "1.2rem" }}>
        {method === "code" && state?.recovery_available ? (
          <>
            Lost your phone?{" "}
            <button className="link" onClick={() => setMethod("recovery")}>
              Use a recovery code
            </button>{" "}
            or ask the administrator to reset your sign-in.
          </>
        ) : (
          "Lost your phone or app? Ask the administrator to reset your sign-in."
        )}
      </p>
    </AuthCard>
  );
}
