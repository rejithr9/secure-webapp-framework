import { useCallback, useEffect, useState, type FormEvent } from "react";
import { del, errorMessage, formatWhen, get, post } from "../api";
import { useAuth } from "../auth";
import { PasswordForm, ReauthFields } from "../components/PasswordForm";
import { RecoveryCodesPanel } from "../components/RecoveryCodes";
import { Alert, Field, PageHeader } from "../components/ui";
import { addPasskey, passkeysSupported } from "../webauthn";

interface PasskeyItem {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

function Passkeys() {
  const [items, setItems] = useState<PasskeyItem[]>([]);
  const [enabled, setEnabled] = useState(false);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    get<{ enabled: boolean; items: PasskeyItem[] }>("/api/me/passkeys")
      .then((r) => {
        setEnabled(r.enabled);
        setItems(r.items);
      })
      .catch((err) => setError(errorMessage(err)));
  }, []);
  useEffect(load, [load]);

  if (!enabled) return null;
  const supported = passkeysSupported();

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await addPasskey(password, code, name.trim() || "Passkey");
      setMessage("Passkey added. Next time, you can use it instead of a code.");
      setAdding(false);
      setName("");
      setPassword("");
      setCode("");
      load();
    } catch (err) {
      setError(errorMessage(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  async function remove(item: PasskeyItem) {
    if (!window.confirm(`Remove the passkey “${item.name}”? You can still sign in with your authenticator app.`)) return;
    try {
      await del(`/api/me/passkeys/${item.id}`);
      setMessage(`Passkey “${item.name}” removed.`);
      load();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <div className="card" style={{ maxWidth: "40rem" }}>
      <h2>Passkeys</h2>
      <p className="muted">
        A passkey lets you confirm it's you with your fingerprint, face, device PIN or a security key, instead of typing a
        code. You still need your password first, and your authenticator app keeps working as a backup.
      </p>
      <Alert kind="success">{message}</Alert>
      <Alert kind="error">{error}</Alert>
      {items.length > 0 && (
        <table>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <strong>{item.name}</strong>
                </td>
                <td className="small muted">
                  Added {formatWhen(item.created_at)}
                  <br />
                  {item.last_used_at ? `Last used ${formatWhen(item.last_used_at)}` : "Not used yet"}
                </td>
                <td style={{ textAlign: "right" }}>
                  <button className="danger" onClick={() => remove(item)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {!supported ? (
        <p className="small muted">This browser doesn't support passkeys.</p>
      ) : adding ? (
        <form onSubmit={submit} style={{ marginTop: "1rem" }}>
          <Field
            label="Name for this passkey"
            maxLength={64}
            placeholder="For example “Work laptop”"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <p className="small muted">To add a passkey, first confirm it's you:</p>
          <ReauthFields password={password} setPassword={setPassword} code={code} setCode={setCode} />
          <div className="actions">
            <button className="primary" type="submit" disabled={busy || !password || code.length !== 6}>
              {busy ? "Follow your device's prompts…" : "Add passkey"}
            </button>
            <button type="button" onClick={() => setAdding(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div className="actions">
          <button onClick={() => (setAdding(true), setMessage(null))}>Add a passkey</button>
        </div>
      )}
    </div>
  );
}

function RecoveryCodes() {
  const { config } = useAuth();
  const [remaining, setRemaining] = useState<number | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    get<{ enabled: boolean; remaining: number }>("/api/me/recovery-codes")
      .then((r) => {
        setEnabled(r.enabled);
        setRemaining(r.remaining);
      })
      .catch(() => undefined);
  }, []);
  useEffect(load, [load]);

  if (!enabled) return null;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ codes: string[] }>("/api/me/recovery-codes", { password, totp_code: code });
      setCodes(r.codes);
      setOpen(false);
      setPassword("");
      setCode("");
    } catch (err) {
      setError(errorMessage(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ maxWidth: "40rem" }}>
      <h2>Recovery codes</h2>
      {codes ? (
        <RecoveryCodesPanel
          codes={codes}
          appName={config?.app_name ?? "App"}
          onDone={() => {
            setCodes(null);
            load();
          }}
          doneLabel="Done"
        />
      ) : (
        <>
          <p className="muted">
            Single-use codes for signing in if you lose your authenticator app.{" "}
            {remaining !== null && (
              <strong className={remaining <= 3 ? "text-warning" : ""}>You have {remaining} left.</strong>
            )}
          </p>
          <Alert kind="error">{error}</Alert>
          {open ? (
            <form onSubmit={submit}>
              <p className="small muted">Creating new codes makes your old ones stop working. First confirm it's you:</p>
              <ReauthFields password={password} setPassword={setPassword} code={code} setCode={setCode} />
              <div className="actions">
                <button className="primary" type="submit" disabled={busy || !password || code.length !== 6}>
                  {busy ? "Creating…" : "Create new codes"}
                </button>
                <button type="button" onClick={() => setOpen(false)}>
                  Cancel
                </button>
              </div>
            </form>
          ) : (
            <button onClick={() => setOpen(true)}>Create new recovery codes</button>
          )}
        </>
      )}
    </div>
  );
}

function DeleteAccount() {
  const { state, refresh } = useAuth();
  const username = state?.user?.username ?? "";
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await del("/api/me", { password, totp_code: code });
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
      setCode("");
      setBusy(false);
    }
  }

  return (
    <div className="card danger-zone" style={{ maxWidth: "40rem" }}>
      <h2>Delete my account</h2>
      <p className="muted">This permanently deletes your account and all your data. It cannot be undone.</p>
      {!open ? (
        <button className="danger" onClick={() => setOpen(true)}>
          Delete my account…
        </button>
      ) : (
        <form onSubmit={submit} style={{ maxWidth: "28rem" }}>
          <Alert kind="error">{error}</Alert>
          <Field
            label={`Type your username (${username}) to confirm`}
            autoComplete="off"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
          />
          <ReauthFields password={password} setPassword={setPassword} code={code} setCode={setCode} />
          <div className="actions">
            <button
              className="danger solid"
              type="submit"
              disabled={busy || typed.trim().toLowerCase() !== username || code.length !== 6 || !password}
            >
              {busy ? "Deleting…" : "Delete everything permanently"}
            </button>
            <button type="button" onClick={() => setOpen(false)}>
              Keep my account
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

export function AccountPage() {
  const { state } = useAuth();
  const [done, setDone] = useState(false);
  return (
    <>
      <PageHeader title="My account">
        Signed in as <strong>{state?.user?.username}</strong>
        {state?.user?.role === "admin" ? " (administrator)" : ""}.
      </PageHeader>
      <div className="card" style={{ maxWidth: "40rem" }}>
        <h2>Change password</h2>
        <p className="muted">Changing your password signs you out on all other devices.</p>
        <Alert kind="success">{done ? "Your password has been changed." : null}</Alert>
        <PasswordForm onDone={() => setDone(true)} />
      </div>
      <Passkeys />
      <RecoveryCodes />
      <DeleteAccount />
    </>
  );
}
