"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";
import { IconCheck, IconCopy } from "@/components/icons";
import { useToast } from "./toast";

export async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Clipboard API can be blocked (insecure origin, iframe). Fall back to a hidden textarea.
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

export function CopyButton({
  text,
  label = "Copy",
  className,
  compact,
}: {
  text: string;
  label?: string;
  className?: string;
  compact?: boolean;
}) {
  const [done, setDone] = useState(false);
  const toast = useToast();
  return (
    <button
      type="button"
      onClick={async () => {
        const ok = await copyText(text);
        if (ok) {
          setDone(true);
          setTimeout(() => setDone(false), 1600);
        } else {
          toast({ title: "Copy failed", description: "Select the text and copy it manually.", tone: "error" });
        }
      }}
      aria-label={compact ? `${label} to clipboard` : undefined}
      className={cn(
        "inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3 transition-colors duration-micro hover:text-ink",
        className
      )}
    >
      {done ? <IconCheck size={14} /> : <IconCopy size={14} />}
      {!compact && (done ? "Copied" : label)}
    </button>
  );
}

/** Code set like an engineering drawing: numbered lines, filename in the header rule. */
export function CodeBlock({
  code,
  filename,
  className,
  maxHeight,
}: {
  code: string;
  filename?: string;
  className?: string;
  maxHeight?: number;
}) {
  const lines = code.replace(/\n$/, "").split("\n");
  return (
    <figure className={cn("min-w-0 max-w-full border border-rule bg-surface", className)}>
      <figcaption className="flex items-center justify-between border-b border-rule px-4 py-2">
        <span className="font-mono text-[11px] text-ink-2">{filename ?? "snippet"}</span>
        <CopyButton text={code} />
      </figcaption>
      <pre className="overflow-auto py-3 font-mono text-[12.5px] leading-[1.7]" style={maxHeight ? { maxHeight } : undefined}>
        <code className="grid">
          {lines.map((l, i) => (
            <span key={i} className="grid grid-cols-[3rem_1fr]">
              <span aria-hidden className="select-none pr-4 text-right text-ink-3/70 tabular">
                {i + 1}
              </span>
              <span className="whitespace-pre pr-4 text-ink">{l || " "}</span>
            </span>
          ))}
        </code>
      </pre>
    </figure>
  );
}

/** Inline command with a copy affordance, for one-liners like `pip install seqr`. */
export function CommandLine({ command, className }: { command: string; className?: string }) {
  return (
    <div className={cn("flex items-center justify-between gap-4 border border-ink bg-bg px-4 py-3", className)}>
      <code className="min-w-0 truncate font-mono text-sm text-ink">{command}</code>
      <CopyButton text={command} />
    </div>
  );
}
