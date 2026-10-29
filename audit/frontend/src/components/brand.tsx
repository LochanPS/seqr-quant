import { cn } from "@/lib/utils";

/**
 * SeQr wordmark: set in the display serif with the Q's tail replaced by a small accent
 * square, the same square that marks the favicon. Works at any size via font-size.
 */
export function Wordmark({ className, labs = false }: { className?: string; labs?: boolean }) {
  return (
    <span className={cn("inline-flex items-baseline font-display leading-none tracking-[-0.01em] text-ink", className)}>
      <span>Se</span>
      <span className="relative">
        Q
        <span aria-hidden className="absolute -bottom-[0.06em] -right-[0.14em] h-[0.18em] w-[0.18em] bg-accent" />
      </span>
      <span>r</span>
      {labs && <span className="ml-2 font-mono text-[0.42em] uppercase tracking-[0.12em] text-ink-3">Labs</span>}
    </span>
  );
}

/** Square monogram for collapsed navigation and avatars: flat fill, no gradient. */
export function Monogram({ text, className }: { text: string; className?: string }) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-flex h-9 w-9 shrink-0 items-center justify-center bg-ink font-mono text-[12px] font-medium uppercase text-bg",
        className
      )}
    >
      {text.slice(0, 2)}
    </span>
  );
}
