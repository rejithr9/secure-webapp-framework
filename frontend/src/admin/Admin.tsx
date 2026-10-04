import { useCallback, useEffect, useState, type FormEvent } from "react";
import { errorMessage, formatWhen, get, post, put } from "../api";
import { useAuth } from "../auth";
import { Alert, Field } from "../components/ui";

interface AdminUserRow {
  id: string;
  username: string;
  role: "user" | "admin";
  status: "active" | "setup_pending" | "locked" | "deactivated";
  created_at: string;
  last_login_at: string | null;
}

interface AdminEvent {
  id: number;
  action: string;
  actor: string;
  target: string | null;
  details: Record<string, unknown> | null;
  created_at: string;
}

const STATUS: Record<AdminUserRow["status"], [string, string]> = {
  active: ["Active", "ok"],
  setup_pending: ["Waiting for first sign-in", "info"],
  locked: ["Locked for a short while", "warn"],
  deactivated: ["Deactivated", "bad"],
};

const ACTIONS: Record<string, string> = {
  user_created: "Account created",
  user_sign_in_reset: "Sign-in reset",
  user_deactivated: "Account deactivated",
  user_reactivated: "Account reactivated",
  settings_changed: "Settings changed",
  account_self_deleted: "User deleted their own account",
  retention_purge: "Data deleted after retention period",
};

function OneTimePassword({ username, password, onClose }: { username: string; password: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="card" style={{ borderColor: "var(--accent)" }}>
      <h3>One-time password for {username}</h3>
      <div className="one-time">{password}</div>
      <p className="small muted">
        Give this to {username} in person or by a private message. It is shown only once. At first sign-in they set up
        their authenticator app and choose their own password.
      </p>
      <div className="actions">
        <button
          onClick={() => navigator.clipboard?.writeText(password).then(() => setCopied(true))}
        >
          {copied ? "Copied" : "Copy"}
        </button>
        <button className="primary" onClick={onClose}>
          I've noted it down
        </button>
      </div>
    </div>
  );
}

function Users() {
  const { state } = useAuth();
  const me = state?.user?.username;
  const [rows, setRows] = useState<AdminUserRow[]>([]);
  const [maxUsers, setMaxUsers] = useState<number | null>(null);
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<"user" | "admin">("user");
  const [oneTime, setOneTime] = useState<{ username: string; password: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    get<{ items: AdminUserRow[]; max_users: number }>("/api/admin/users")
      .then((r) => {
        setRows(r.items);
        setMaxUsers(r.max_users);
      })
      .catch((err) => setError(errorMessage(err)));
  }, []);
  useEffect(load, [load]);

  async function create(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ user: AdminUserRow; initial_password: string }>("/api/admin/users", { username, role });
      setOneTime({ username: r.user.username, password: r.initial_password });
      setUsername("");
      setRole("user");
      load();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function act(row: AdminUserRow, action: "reset" | "deactivate" | "reactivate") {
    const questions = {
      reset: `Reset sign-in for ${row.username}? Their password and authenticator app stop working. They get a new one-time password and set up 2FA again.`,
      deactivate: `Deactivate ${row.username}? They are signed out and can't sign in. Their data is deleted automatically after the retention period.`,
      reactivate: `Reactivate ${row.username}? They can sign in again.`,
    };
    if (!window.confirm(questions[action])) return;
    setError(null);
    try {
      const r = await post<{ user: AdminUserRow; initial_password?: string }>(`/api/admin/users/${row.id}/${action}`);
      if (r.initial_password) setOneTime({ username: row.username, password: r.initial_password });
      load();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <>
      {oneTime && <OneTimePassword {...oneTime} onClose={() => setOneTime(null)} />}
      <Alert kind="error">{error}</Alert>
      <div className="card">
        <h2>Accounts</h2>
        <p className="muted small">
          {maxUsers !== null && `${rows.length} of at most ${maxUsers} accounts. `}You see account details only, never
          anyone's data.
        </p>
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th>Last sign-in</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>
                  <strong>{row.username}</strong>
                </td>
                <td>{row.role === "admin" ? "Admin" : "User"}</td>
                <td>
                  <span className={`badge ${STATUS[row.status][1]}`}>{STATUS[row.status][0]}</span>
                </td>
                <td className="small">{formatWhen(row.created_at)}</td>
                <td className="small">{row.last_login_at ? formatWhen(row.last_login_at) : "Never"}</td>
                <td>
                  {row.username === me ? (
                    <span className="small muted">You (use My account)</span>
                  ) : (
                  <div className="actions" style={{ marginTop: 0, justifyContent: "flex-end" }}>
                    <button onClick={() => act(row, "reset")}>Reset sign-in</button>
                    {row.status === "deactivated" ? (
                      <button onClick={() => act(row, "reactivate")}>Reactivate</button>
                    ) : (
                      <button className="danger" onClick={() => act(row, "deactivate")}>
                        Deactivate
                      </button>
                    )}
                  </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card" style={{ maxWidth: "36rem" }}>
        <h2>Create an account</h2>
        <form onSubmit={create}>
          <Field
            label="Username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            hint="3–32 characters: lowercase letters, digits, dots, dashes or underscores."
          />
          <div className="field">
            <label htmlFor="role">Role</label>
            <select id="role" value={role} onChange={(e) => setRole(e.target.value as "user" | "admin")}>
              <option value="user">User</option>
              <option value="admin">Admin (can also manage accounts)</option>
            </select>
          </div>
          <button className="primary" type="submit" disabled={busy || username.trim().length < 3}>
            {busy ? "Creating…" : "Create account"}
          </button>
        </form>
      </div>
    </>
  );
}

function Settings() {
  const [days, setDays] = useState<number | "">("");
  const [limits, setLimits] = useState({ min: 1, max: 182, total: 182, backup: 0 });
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    get<{
      retention_days: number;
      retention_days_min: number;
      retention_days_max: number;
      retention_max_total_days: number;
      backup_days: number;
    }>("/api/admin/settings")
      .then((r) => {
        setDays(r.retention_days);
        setLimits({
          min: r.retention_days_min,
          max: r.retention_days_max,
          total: r.retention_max_total_days,
          backup: r.backup_days,
        });
      })
      .catch((err) => setError(errorMessage(err)));
  }, []);

  async function save(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    try {
      const r = await put<{ retention_days: number }>("/api/admin/settings", { retention_days: Number(days) });
      setDays(r.retention_days);
      setMessage("Saved.");
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <div className="card" style={{ maxWidth: "36rem" }}>
      <h2>Data retention</h2>
      <p className="muted">
        When an account is deactivated, all its data is deleted automatically after this many days. The maximum is{" "}
        {limits.max} days
        {limits.backup > 0
          ? `, because backups keep data for up to ${limits.backup} more days and the total may not exceed ${limits.total} days`
          : ""}
        .
      </p>
      <Alert kind="success">{message}</Alert>
      <Alert kind="error">{error}</Alert>
      <form onSubmit={save}>
        <Field
          label="Days to keep a deactivated account's data"
          type="number"
          min={limits.min}
          max={limits.max}
          required
          value={days}
          onChange={(e) => setDays(e.target.value === "" ? "" : Number(e.target.value))}
        />
        <button className="primary" type="submit">
          Save
        </button>
      </form>
    </div>
  );
}

function AdminLog() {
  const [items, setItems] = useState<AdminEvent[]>([]);
  useEffect(() => {
    get<{ items: AdminEvent[] }>("/api/admin/events")
      .then((r) => setItems(r.items))
      .catch(() => setItems([]));
  }, []);
  return (
    <div className="card">
      <h2>Admin log</h2>
      <p className="muted small">Every admin action and automatic deletion, newest first.</p>
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>What</th>
            <th>By</th>
            <th>Account</th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.id}>
              <td className="small">{formatWhen(e.created_at)}</td>
              <td>{ACTIONS[e.action] ?? e.action}</td>
              <td>{e.actor}</td>
              <td>{e.target ?? "—"}</td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                Nothing yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export function AdminPage() {
  const [tab, setTab] = useState<"users" | "settings" | "log">("users");
  return (
    <>
      <div className="page-header">
        <h1>Admin</h1>
        <p>
          Manage accounts and app settings. By design you cannot see anyone's data, keys or activity.
        </p>
        <div className="actions">
          {(
            [
              ["users", "Accounts"],
              ["settings", "Settings"],
              ["log", "Admin log"],
            ] as const
          ).map(([id, label]) => (
            <button key={id} className={tab === id ? "primary" : ""} onClick={() => setTab(id)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      {tab === "users" && <Users />}
      {tab === "settings" && <Settings />}
      {tab === "log" && <AdminLog />}
    </>
  );
}
