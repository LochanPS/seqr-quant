"use client";

import { forwardRef } from "react";
import { Slot } from "@radix-ui/react-slot";
import { cn } from "@/lib/utils";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "accent" | "link";
type Size = "sm" | "md" | "lg" | "icon" | "icon-sm";

const VARIANTS: Record<Variant, string> = {
  primary: "bg-ink text-bg border border-ink hover:bg-ink-2 hover:border-ink-2",
  secondary: "bg-transparent text-ink border border-ink hover:bg-ink hover:text-bg",
  ghost: "bg-transparent text-ink-2 border border-transparent hover:text-ink hover:bg-surface",
  danger:
    "bg-transparent text-immediate border border-immediate hover:bg-immediate hover:text-bg",
  accent: "bg-accent text-bg border border-accent hover:bg-ink hover:border-ink",
  link: "bg-transparent text-ink border-0 px-0 h-auto link-underline",
};

const SIZES: Record<Size, string> = {
  sm: "h-8 px-3 text-[13px] gap-1.5",
  md: "h-10 px-4 text-sm gap-2",
  lg: "h-12 px-6 text-[15px] gap-2.5",
  icon: "h-10 w-10 justify-center",
  "icon-sm": "h-8 w-8 justify-center",
};

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  asChild?: boolean;
  /** While true the button is disabled and shows `pendingLabel` in place of its children. */
  pending?: boolean;
  pendingLabel?: React.ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "primary", size = "md", asChild, pending, pendingLabel, disabled, children, ...props },
  ref
) {
  const Comp = asChild ? Slot : "button";
  return (
    <Comp
      ref={ref}
      disabled={disabled || pending}
      aria-busy={pending || undefined}
      className={cn(
        "inline-flex select-none items-center whitespace-nowrap font-medium transition-colors duration-micro ease-instrument",
        "disabled:pointer-events-none disabled:opacity-45",
        VARIANTS[variant],
        variant !== "link" && SIZES[size],
        className
      )}
      {...props}
    >
      {pending && pendingLabel && !asChild ? (
        <>
          <PendingTick />
          {pendingLabel}
        </>
      ) : (
        children
      )}
    </Comp>
  );
});

/** A small square that fills left to right while work is in flight. Not a spinner. */
function PendingTick() {
  return (
    <span aria-hidden className="relative inline-block h-2 w-3 overflow-hidden border border-current">
      <span className="absolute inset-y-0 left-0 w-full origin-left animate-skeleton bg-current" />
    </span>
  );
}
