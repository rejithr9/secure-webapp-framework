import { useCallback, useEffect, useState, type FormEvent } from "react";
import { del, errorMessage, formatWhen, get, put } from "../api";
import { Alert, Field } from "../components/ui";

interface KeyItem {
  provider: string;
  name: string;
  unlocks: string;
  signup_url: string;
  has_key: boolean;
  masked: string | null;
  label: string | null;
  added_at: string | null;
  last_used_at: string | null;
}

function KeyForm({ item, onSaved, onCancel }: { item: KeyItem; onSaved: (msg: string) => void; onCancel: () => void }) {
  const [secret, setSecret] = useState("");
  const [label, setLabel] = useState(item.label ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await put(`/api/keys/${item.provider}`, { secret, label: label || null });
      setSecret("");
      onSaved(`${item.name} key saved. Only the last 4 characters are shown from now on.`);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <form className="key-form" onSubmit={submit}>
      {error && (
        <div style={{ gridColumn: "1 / -1" }}>
          <Alert kind="error">{error}</Alert>
        </div>
      )}
      <Field
        label={item.has_key ? "New key (replaces the old one)" : "Key"}
        type="password"
        autoComplete="off"
        spellCheck={false}
        required
        autoFocus
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
        hint="Paste it from the provider's website. It is encrypted before it is stored."
      />
      <Field
        label="Label (optional)"
        maxLength={64}
        value={label}
        onChange={(e) => setLabel(e.target.value)}
        hint="For example “personal plan”."
      />
      <button className="primary" type="submit" disabled={busy || secret.trim().length < 8}>
        {busy ? "Saving…" : "Save key"}
      </button>
      <button type="button" onClick={onCancel}>
        Cancel
      </button>
    </form>
  );
}

export function KeysPage() {
  const [items, setItems] = useState<KeyItem[] | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    get<{ items: KeyItem[] }>("/api/keys")
      .then((r) => setItems(r.items))
      .catch((err) => setError(errorMessage(err)));
  }, []);

  useEffect(load, [load]);

  async function remove(item: KeyItem) {
    if (!window.confirm(`Remove your ${item.name} key? Features that need it will switch off.`)) return;
    setError(null);
    try {
      await del(`/api/keys/${item.provider}`);
      setMessage(`${item.name} key removed.`);
      load();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <>
      <div className="page-header">
        <h1>My keys</h1>
        <p>
          Some features use your own keys for outside services. Each key is encrypted and only you can use it. Nobody
          sees a key again after you save it, not even the administrator. We only show the last 4 characters, so you can
          tell keys apart.
        </p>
      </div>
      <Alert kind="success">{message}</Alert>
      <Alert kind="error">{error}</Alert>
      <div className="card">
        {items === null && !error && <p className="muted">Loading…</p>}
        {items?.map((item) => (
          <div className="key-row" key={item.provider}>
            <div>
              <strong>{item.name}</strong>
              <div className="small">
                <a href={item.signup_url} target="_blank" rel="noreferrer noopener">
                  Get a key ↗
                </a>
              </div>
            </div>
            <div className="small muted">{item.unlocks}</div>
            <div className="small">
              {item.has_key ? (
                <>
                  <span className="badge ok">Saved {item.masked}</span>
                  {item.label && <div className="muted">{item.label}</div>}
                  <div className="muted">Added {formatWhen(item.added_at)}</div>
                  <div className="muted">
                    {item.last_used_at ? `Last used ${formatWhen(item.last_used_at)}` : "Not used yet"}
                  </div>
                </>
              ) : (
                <span className="badge">No key</span>
              )}
            </div>
            <div className="actions" style={{ marginTop: 0 }}>
              {editing !== item.provider && (
                <button
                  onClick={() => {
                    setEditing(item.provider);
                    setMessage(null);
                  }}
                >
                  {item.has_key ? "Replace" : "Add key"}
                </button>
              )}
              {item.has_key && editing !== item.provider && (
                <button className="danger" onClick={() => remove(item)}>
                  Remove
                </button>
              )}
            </div>
            {editing === item.provider && (
              <KeyForm
                item={item}
                onCancel={() => setEditing(null)}
                onSaved={(msg) => {
                  setEditing(null);
                  setMessage(msg);
                  load();
                }}
              />
            )}
          </div>
        ))}
      </div>
    </>
  );
}
