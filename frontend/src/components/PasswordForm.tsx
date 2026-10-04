import { useState, type FormEvent } from "react";
import { errorMessage, post } from "../api";
import { useAuth } from "../auth";
import { Alert, CodeField, Field } from "./ui";

/** Change password: needs the current password and a fresh authenticator code. */
export function PasswordForm({
  currentLabel = "Current password",
  submitLabel = "Change password",
  onDone,
}: {
  currentLabel?: string;
  submitLabel?: string;
  onDone: () => void | Promise<void>;
}) {
  const minLength = useAuth().config?.password_min_length ?? 12;
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const mismatch = confirm.length > 0 && confirm !== next;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (next !== confirm) {
      setError("The two new passwords don't match. Type them again.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await post("/api/auth/password", { current_password: current, new_password: next, totp_code: code });
      setCurrent("");
      setNext("");
      setConfirm("");
      setCode("");
      await onDone();
    } catch (err) {
      setError(errorMessage(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <Alert kind="error">{error}</Alert>
      <Field
        label={currentLabel}
        type="password"
        autoComplete="current-password"
        required
        value={current}
        onChange={(e) => setCurrent(e.target.value)}
      />
      <Field
        label="New password"
        type="password"
        autoComplete="new-password"
        required
        minLength={minLength}
        value={next}
        onChange={(e) => setNext(e.target.value)}
        hint={`At least ${minLength} characters. A short sentence you can remember works well.`}
      />
      <Field
        label="New password again"
        type="password"
        autoComplete="new-password"
        required
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        hint={mismatch ? "This doesn't match the new password yet." : undefined}
      />
      <CodeField value={code} onChange={setCode} label="Code from your authenticator app" />
      <p className="small muted">If you just used a code, wait until your app shows a new one.</p>
      <button className="primary" type="submit" disabled={busy || code.length !== 6 || next.length < minLength || mismatch}>
        {busy ? "Saving…" : submitLabel}
      </button>
    </form>
  );
}

/** Password + fresh code, for confirming sensitive actions. */
export function ReauthFields({
  password,
  setPassword,
  code,
  setCode,
}: {
  password: string;
  setPassword: (v: string) => void;
  code: string;
  setCode: (v: string) => void;
}) {
  return (
    <>
      <Field
        label="Password"
        type="password"
        autoComplete="current-password"
        required
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <CodeField value={code} onChange={setCode} label="Code from your authenticator app" />
    </>
  );
}
