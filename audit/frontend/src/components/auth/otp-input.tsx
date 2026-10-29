"use client";

import { useRef } from "react";
import { cn } from "@/lib/utils";

/** Six segmented digit boxes. Paste-aware; calls onComplete when the sixth digit lands. */
export function OtpInput({
  value,
  onChange,
  onComplete,
  disabled,
  autoFocus,
}: {
  value: string;
  onChange: (v: string) => void;
  onComplete?: (v: string) => void;
  disabled?: boolean;
  autoFocus?: boolean;
}) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const digits = Array.from({ length: 6 }, (_, i) => value[i] ?? "");

  const commit = (next: string) => {
    const clean = next.replace(/\D/g, "").slice(0, 6);
    onChange(clean);
    if (clean.length === 6) onComplete?.(clean);
    return clean;
  };

  return (
    <div className="flex gap-2" role="group" aria-label="Six digit authentication code">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el;
          }}
          inputMode="numeric"
          autoComplete={i === 0 ? "one-time-code" : "off"}
          aria-label={`Digit ${i + 1}`}
          maxLength={1}
          disabled={disabled}
          autoFocus={autoFocus && i === 0}
          value={d}
          onPaste={(e) => {
            e.preventDefault();
            const clean = commit(e.clipboardData.getData("text"));
            refs.current[Math.min(clean.length, 5)]?.focus();
          }}
          onChange={(e) => {
            const ch = e.target.value.replace(/\D/g, "").slice(-1);
            const arr = digits.slice();
            arr[i] = ch;
            commit(arr.join(""));
            if (ch && i < 5) refs.current[i + 1]?.focus();
          }}
          onKeyDown={(e) => {
            if (e.key === "Backspace" && !digits[i] && i > 0) refs.current[i - 1]?.focus();
            if (e.key === "ArrowLeft" && i > 0) refs.current[i - 1]?.focus();
            if (e.key === "ArrowRight" && i < 5) refs.current[i + 1]?.focus();
          }}
          className={cn(
            "h-14 w-12 border bg-bg text-center font-mono text-2xl text-ink tabular transition-colors duration-micro",
            "focus-visible:border-ink focus-visible:outline-none",
            d ? "border-ink" : "border-rule"
          )}
        />
      ))}
    </div>
  );
}
