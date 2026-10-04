import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Alert, Card, PageHeader, del, errorMessage, formatWhen, get, post, useAuth } from "@swf/web";

interface Note {
  id: string;
  body: string;
  created_at: string;
}

export function Home() {
  const { state } = useAuth();
  return (
    <>
      <PageHeader title={`Hello, ${state?.user?.username}`}>This is the example app built on the framework.</PageHeader>
      <Card>
        <p>Your notes are encrypted and only you can read them.</p>
        <Link className="button" to="/notes">
          Open my notes
        </Link>
      </Card>
    </>
  );
}

export function NotesPage() {
  const [notes, setNotes] = useState<Note[]>([]);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    get<{ items: Note[] }>("/api/notes")
      .then((r) => setNotes(r.items))
      .catch((err) => setError(errorMessage(err)));
  }, []);
  useEffect(load, [load]);

  async function add(e: FormEvent) {
    e.preventDefault();
    try {
      await post("/api/notes", { body: text });
      setText("");
      load();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <>
      <PageHeader title="My notes">Only you can see these.</PageHeader>
      <Alert kind="error">{error}</Alert>
      <Card style={{ maxWidth: "40rem" }}>
        <form onSubmit={add} className="actions">
          <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Write a note" maxLength={10000} />
          <button className="primary" disabled={!text.trim()}>
            Add
          </button>
        </form>
      </Card>
      {notes.map((n) => (
        <Card key={n.id} style={{ maxWidth: "40rem" }}>
          <p>{n.body}</p>
          <div className="actions">
            <span className="small muted">{formatWhen(n.created_at)}</span>
            <button className="danger" onClick={() => del(`/api/notes/${n.id}`).then(load)}>
              Delete
            </button>
          </div>
        </Card>
      ))}
    </>
  );
}
