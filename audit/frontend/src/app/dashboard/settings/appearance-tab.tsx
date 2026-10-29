"use client";

import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { useThemeSwitch } from "@/lib/hooks";

// Swatches are rendered with the literal theme values so each previews the real thing.
const THEMES = [
  { value: "light", label: "Paper", sub: "Light", bg: "#EFEAE0", surface: "#E6E0D3", ink: "#16140F", rule: "#C9C1B0", accent: "#A65A16" },
  { value: "dark", label: "Carbon", sub: "Dark", bg: "#13120F", surface: "#1B1A16", ink: "#ECE6D9", rule: "#3A372F", accent: "#D08A3E" },
] as const;

function Preview({ t }: { t: (typeof THEMES)[number] }) {
  return (
    <div className="h-full w-full p-4" style={{ background: t.bg }}>
      <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: t.rule }}>
        <span className="font-display text-sm" style={{ color: t.ink }}>
          SeQr
        </span>
        <span className="h-1.5 w-1.5" style={{ background: t.accent }} />
      </div>
      <p className="mt-3 font-display text-xl leading-none" style={{ color: t.ink }}>
        42
      </p>
      <div className="mt-3 space-y-1.5">
        {[80, 60, 70].map((w) => (
          <span key={w} className="block h-1.5" style={{ width: `${w}%`, background: t.surface }} />
        ))}
      </div>
    </div>
  );
}

export function AppearanceTab() {
  const { theme, setTheme } = useThemeSwitch();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const options = [
    ...THEMES.map((t) => ({ value: t.value, label: t.label, sub: t.sub, preview: <Preview t={t} /> })),
    {
      value: "system",
      label: "System",
      sub: "Follows your device",
      preview: (
        <div className="grid h-full w-full grid-cols-2">
          <Preview t={THEMES[0]} />
          <Preview t={THEMES[1]} />
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-[1.45rem] text-ink">Appearance</h2>
        <p className="mt-1 text-sm text-ink-2">Stored in this browser only.</p>
      </div>
      <div role="radiogroup" aria-label="Theme" className="grid max-w-3xl gap-4 sm:grid-cols-3">
        {options.map((o) => {
          const on = mounted && theme === o.value;
          return (
            <button
              key={o.value}
              role="radio"
              aria-checked={on}
              onClick={() => setTheme(o.value)}
              className={cn("group text-left transition-colors duration-micro", on ? "text-ink" : "text-ink-2 hover:text-ink")}
            >
              <span className={cn("block aspect-[4/3] overflow-hidden border-2", on ? "border-ink" : "border-rule group-hover:border-ink-3")}>{o.preview}</span>
              <span className="mt-2 flex items-baseline justify-between">
                <span className="text-sm font-medium">{o.label}</span>
                <span className="font-mono text-[11px] text-ink-3">{on ? "selected" : o.sub}</span>
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
