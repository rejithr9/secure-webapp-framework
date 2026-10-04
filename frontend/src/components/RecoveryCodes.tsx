import { useState } from "react";

/** Shows freshly created recovery codes once, with copy and download, and asks the user to save them. */
export function RecoveryCodesPanel({ codes, appName, onDone, doneLabel = "I've saved my codes" }: {
  codes: string[];
  appName: string;
  onDone: () => void;
  doneLabel?: string;
}) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const text = `${appName} recovery codes\nEach code works once.\n\n${codes.join("\n")}\n`;

  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div>
      <p>
        If you ever lose your phone or authenticator app, you can sign in with one of these codes instead. Each code works
        once. <strong>Save them somewhere safe now</strong>, for example in a password manager or printed at home. They
        won't be shown again.
      </p>
      <ol className="recovery-codes">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ol>
      <div className="actions">
        <button type="button" onClick={() => navigator.clipboard?.writeText(text).then(() => setCopied(true))}>
          {copied ? "Copied" : "Copy"}
        </button>
        <button type="button" onClick={download}>
          Download as a text file
        </button>
      </div>
      <label className="checkbox">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span>I have saved these codes somewhere safe.</span>
      </label>
      <button className="primary" disabled={!saved} onClick={onDone}>
        {doneLabel}
      </button>
    </div>
  );
}
