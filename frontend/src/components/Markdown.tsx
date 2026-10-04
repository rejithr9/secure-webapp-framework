import type { ReactNode } from "react";

// Minimal renderer for our own trusted text (terms): headings, numbered lists, paragraphs, **bold**.
// It builds React elements, never raw HTML.

function inline(text: string): ReactNode[] {
  return text.split(/(\*\*[^*]+\*\*)/g).map((part, i) =>
    part.startsWith("**") && part.endsWith("**") ? <strong key={i}>{part.slice(2, -2)}</strong> : part,
  );
}

export function Markdown({ text }: { text: string }) {
  const blocks: ReactNode[] = [];
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    const heading = /^(#{1,3})\s+(.*)$/.exec(line);
    if (heading) {
      const level = heading[1].length;
      const content = inline(heading[2]);
      blocks.push(level === 1 ? <h2 key={i}>{content}</h2> : <h3 key={i}>{content}</h3>);
      i++;
      continue;
    }
    if (/^\d+\.\s/.test(line)) {
      const items: string[] = [];
      while (i < lines.length) {
        if (!lines[i].trim()) {
          // A blank line ends the list unless another numbered item follows.
          let j = i;
          while (j < lines.length && !lines[j].trim()) j++;
          if (j < lines.length && /^\d+\.\s/.test(lines[j])) {
            i = j;
            continue;
          }
          break;
        }
        if (/^\d+\.\s/.test(lines[i])) items.push(lines[i].replace(/^\d+\.\s+/, ""));
        else items[items.length - 1] += " " + lines[i].trim();
        i++;
      }
      blocks.push(
        <ol key={i}>
          {items.map((item, j) => (
            <li key={j}>{inline(item)}</li>
          ))}
        </ol>,
      );
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#|\d+\.\s)/.test(lines[i])) {
      para.push(lines[i].trim());
      i++;
    }
    blocks.push(<p key={i}>{inline(para.join(" "))}</p>);
  }
  return <>{blocks}</>;
}
