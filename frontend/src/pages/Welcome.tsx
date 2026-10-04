import { useEffect, useState } from "react";
import { errorMessage, get, post } from "../api";
import { useAuth } from "../auth";
import { Markdown } from "../components/Markdown";
import { PasswordForm } from "../components/PasswordForm";
import { Alert, AuthCard } from "../components/ui";

export function ChangeInitialPasswordPage() {
  const { refresh, signOut } = useAuth();
  return (
    <AuthCard>
      <h1>Choose your own password</h1>
      <p className="muted">
        You signed in with a one-time password from the administrator. Replace it now with a password only you know.
      </p>
      <PasswordForm
        currentLabel="One-time password"
        submitLabel="Save my password"
        onDone={() => refresh().then(() => undefined)}
      />
      <p className="small" style={{ marginTop: "1rem" }}>
        <button className="link" onClick={() => signOut()}>
          Sign out and do this later
        </button>
      </p>
    </AuthCard>
  );
}

interface Terms {
  version: string;
  text: string;
}

export function TermsPage() {
  const { refresh, signOut } = useAuth();
  const [terms, setTerms] = useState<Terms | null>(null);
  const [agreed, setAgreed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    get<Terms>("/api/terms")
      .then(setTerms)
      .catch((err) => setError(errorMessage(err)));
  }, []);

  async function accept() {
    if (!terms) return;
    setBusy(true);
    setError(null);
    try {
      await post("/api/me/terms/accept", { version: terms.version });
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <AuthCard wide>
      <Alert kind="error">{error}</Alert>
      {terms ? (
        <>
          <div className="terms">
            <Markdown text={terms.text} />
          </div>
          <label className="checkbox">
            <input type="checkbox" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
            <span>I have read and accept these terms.</span>
          </label>
          <div className="actions">
            <button className="primary" disabled={!agreed || busy} onClick={accept}>
              {busy ? "Saving…" : "Accept and continue"}
            </button>
            <button className="link" onClick={() => signOut()}>
              I don't accept. Sign me out
            </button>
          </div>
        </>
      ) : (
        !error && <p className="muted">Loading the terms…</p>
      )}
    </AuthCard>
  );
}
