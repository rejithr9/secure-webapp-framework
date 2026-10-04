import { useCallback, useEffect, useState } from "react";
import { errorMessage, formatWhen, get } from "../api";
import { Alert, PageHeader } from "../components/ui";

interface AuditItem {
  id: number;
  type: string;
  label: string;
  summary: string;
  created_at: string;
}

const WARNING_TYPES = new Set(["sign_in_failed", "account_locked"]);

export function ActivityPage() {
  const [items, setItems] = useState<AuditItem[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (beforeId?: number) => {
    setLoading(true);
    try {
      const q = beforeId ? `?limit=50&before_id=${beforeId}` : "?limit=50";
      const r = await get<{ items: AuditItem[]; has_more: boolean }>(`/api/me/audit${q}`);
      setItems((prev) => (beforeId ? [...prev, ...r.items] : r.items));
      setHasMore(r.has_more);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <>
      <PageHeader title="My activity">
        A record of everything that happened on your account. Only you can see this list. If you see something you
        didn't do, change your password and tell the administrator.
      </PageHeader>
      <Alert kind="error">{error}</Alert>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th style={{ width: "13rem" }}>When</th>
              <th style={{ width: "22rem" }}>What happened</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>{formatWhen(item.created_at)}</td>
                <td>{WARNING_TYPES.has(item.type) ? <span className="badge warn">{item.label}</span> : item.label}</td>
                <td className="small muted">{item.summary}</td>
              </tr>
            ))}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={3} className="muted">
                  Nothing here yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {loading && <p className="muted">Loading…</p>}
        {hasMore && !loading && (
          <div className="actions">
            <button onClick={() => load(items[items.length - 1]?.id)}>Show older activity</button>
          </div>
        )}
      </div>
    </>
  );
}
