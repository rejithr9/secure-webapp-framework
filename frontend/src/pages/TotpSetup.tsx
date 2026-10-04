import { useEffect, useState, type FormEvent } from "react";
import { errorMessage, get, post } from "../api";
import { useAuth } from "../auth";
import { RecoveryCodesPanel } from "../components/RecoveryCodes";
import { Alert, AuthCard, CodeField } from "../components/ui";

interface Setup {
  otpauth_uri: string;
  qr_svg: string;
  secret: string;
}

export function TotpSetupPage() {
  const { config, refresh, signOut, showNotice } = useAuth();
  const [setup, setSetup] = useState<Setup | null>(null);
  const [showKey, setShowKey] = useState(false);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    get<Setup>("/api/auth/totp/setup")
      .then(setSetup)
      .catch((err) => setError(errorMessage(err)));
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ next: string; recovery_codes?: string[] }>("/api/auth/totp/enable", { code });
      if (r.recovery_codes?.length) {
        setCodes(r.recovery_codes); // show them once before moving on
        setBusy(false);
      } else {
        await refresh();
      }
    } catch (err) {
      const message = errorMessage(err);
      setCode("");
      setBusy(false);
      const state = await refresh().catch(() => null);
      if (state && state.stage !== "totp_setup") showNotice(message);
      else setError(message);
    }
  }

  if (codes) {
    return (
      <AuthCard wide>
        <h1>Save your recovery codes</h1>
        <Alert kind="success">Two-factor authentication is on.</Alert>
        <RecoveryCodesPanel codes={codes} appName={config?.app_name ?? "App"} onDone={() => refresh()} doneLabel="Continue" />
      </AuthCard>
    );
  }

  return (
    <AuthCard wide>
      <h1>Protect your account</h1>
      <p className="muted">
        Every sign-in needs your password <em>and</em> a code from an authenticator app on your phone. This keeps your
        account safe even if someone learns your password. It takes about two minutes, and you only do it once.
      </p>
      <Alert kind="error">{error}</Alert>
      <ol className="steps">
        <li>
          <strong>Install an authenticator app</strong> if you don't have one, for example Google Authenticator,
          Microsoft Authenticator, Aegis or 2FAS.
        </li>
        <li>
          <strong>Add this account to the app.</strong> In the app, choose “add account” or “+”, then scan this QR code
          with your phone's camera.
          {setup ? (
            <>
              <img className="qr" src={setup.qr_svg} alt="QR code to add this account to your authenticator app" />
              {showKey ? (
                <p className="small">
                  Type this key into the app instead:{" "}
                  <span className="secret">{setup.secret.match(/.{1,4}/g)?.join(" ")}</span>
                  <br />
                  <span className="muted">Choose “time-based” if the app asks.</span>
                </p>
              ) : (
                <button type="button" className="link small" onClick={() => setShowKey(true)}>
                  Can't scan the code? Show a key to type in instead
                </button>
              )}
            </>
          ) : (
            !error && <p className="muted">Loading the QR code…</p>
          )}
        </li>
        <li>
          <strong>Type the 6-digit code</strong> the app now shows, to confirm it works.
          <form onSubmit={submit} style={{ marginTop: "0.6rem" }}>
            <CodeField value={code} onChange={setCode} />
            <div className="actions">
              <button className="primary" type="submit" disabled={busy || code.length !== 6 || !setup}>
                {busy ? "Checking…" : "Turn on and continue"}
              </button>
              <button type="button" className="link" onClick={() => signOut()}>
                Cancel and sign out
              </button>
            </div>
          </form>
        </li>
      </ol>
    </AuthCard>
  );
}
