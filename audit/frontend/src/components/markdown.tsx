import { Fragment } from "react";

// A small markdown renderer for blog posts and the CMS preview. It builds React elements
// directly (no HTML strings), so post bodies cannot inject markup. Supports headings,
// paragraphs, lists, fenced code, blockquotes, rules, simple tables and inline marks.

function inline(text: string, key = 0): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\s][^*]*\*|_[^_\s][^_]*_|\[[^\]]+\]\([^)\s]+\))/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(<Fragment key={`${key}-t${i++}`}>{text.slice(last, m.index)}</Fragment>);
    const t = m[0];
    if (t.startsWith("`")) out.push(<code key={`${key}-c${i++}`}>{t.slice(1, -1)}</code>);
    else if (t.startsWith("**")) out.push(<strong key={`${key}-b${i++}`}>{inline(t.slice(2, -2), key + 1)}</strong>);
    else if (t.startsWith("[")) {
      const lm = t.match(/^\[([^\]]+)\]\(([^)\s]+)\)$/)!;
      const href = /^(https?:|mailto:|\/|#)/.test(lm[2]) ? lm[2] : "#";
      const ext = href.startsWith("http");
      out.push(
        <a key={`${key}-a${i++}`} href={href} {...(ext ? { target: "_blank", rel: "noopener noreferrer" } : {})}>
          {lm[1]}
        </a>
      );
    } else out.push(<em key={`${key}-e${i++}`}>{inline(t.slice(1, -1), key + 1)}</em>);
    last = m.index + t.length;
  }
  if (last < text.length) out.push(<Fragment key={`${key}-t${i++}`}>{text.slice(last)}</Fragment>);
  return out;
}

export function Markdown({ source, className }: { source: string; className?: string }) {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: React.ReactNode[] = [];
  let i = 0;
  let k = 0;

  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) body.push(lines[i++]);
      i++;
      blocks.push(
        <pre key={k++} data-lang={lang || undefined}>
          <code>{body.join("\n")}</code>
        </pre>
      );
      continue;
    }
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      const level = Math.min(h[1].length + 1, 4);
      const Tag = `h${level}` as "h2" | "h3" | "h4";
      blocks.push(<Tag key={k++}>{inline(h[2], k)}</Tag>);
      i++;
      continue;
    }
    if (/^(-{3,}|\*{3,})$/.test(line.trim())) {
      blocks.push(<hr key={k++} />);
      i++;
      continue;
    }
    if (line.startsWith(">")) {
      const body: string[] = [];
      while (i < lines.length && lines[i].startsWith(">")) body.push(lines[i++].replace(/^>\s?/, ""));
      blocks.push(<blockquote key={k++}>{inline(body.join(" "), k)}</blockquote>);
      continue;
    }
    if (/^\s*([-*+]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*+]|\d+\.)\s+/.test(lines[i])) items.push(lines[i++].replace(/^\s*([-*+]|\d+\.)\s+/, ""));
      const L = ordered ? "ol" : "ul";
      blocks.push(
        <L key={k++}>
          {items.map((it, j) => (
            <li key={j}>{inline(it, k * 100 + j)}</li>
          ))}
        </L>
      );
      continue;
    }
    if (line.includes("|") && lines[i + 1] && /^\s*\|?\s*:?-{3,}/.test(lines[i + 1])) {
      const cells = (l: string) => l.replace(/^\s*\||\|\s*$/g, "").split("|").map((c) => c.trim());
      const head = cells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) rows.push(cells(lines[i++]));
      blocks.push(
        <table key={k++}>
          <thead>
            <tr>
              {head.map((c, j) => (
                <th key={j}>{inline(c, j)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, ri) => (
              <tr key={ri}>
                {r.map((c, j) => (
                  <td key={j}>{inline(c, ri * 100 + j)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      );
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|```|>|\s*([-*+]|\d+\.)\s+)/.test(lines[i])) para.push(lines[i++]);
    blocks.push(<p key={k++}>{inline(para.join(" "), k)}</p>);
  }

  return <div className={`prose-record ${className ?? ""}`}>{blocks}</div>;
}
