"use client";

import { forwardRef, useId } from "react";
import { cn } from "@/lib/utils";
import { IconChevronDown } from "@/components/icons";

const control =
  "w-full bg-bg border border-rule px-3 text-sm text-ink placeholder:text-ink-3 rounded-xs " +
  "transition-colors duration-micro ease-instrument hover:border-ink-3 " +
  "focus-visible:outline-none focus-visible:border-ink focus-visible:ring-0 " +
  "disabled:opacity-50 aria-[invalid=true]:border-immediate";

export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...props }, ref) {
    return <input ref={ref} className={cn(control, "h-10", className)} {...props} />;
  }
);

export const Textarea = forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  function Textarea({ className, ...props }, ref) {
    return <textarea ref={ref} className={cn(control, "min-h-[96px] py-2.5 leading-relaxed", className)} {...props} />;
  }
);

export const Select = forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, children, ...props }, ref) {
    return (
      <span className="relative block">
        <select ref={ref} className={cn(control, "h-10 appearance-none pr-9", className)} {...props}>
          {children}
        </select>
        <IconChevronDown size={16} className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-ink-3" />
      </span>
    );
  }
);

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("mb-1.5 block text-[13px] font-medium text-ink-2", className)} {...props} />;
}

/** Label + control + hint/error, wired with ids for assistive tech. */
export function Field({
  label,
  hint,
  error,
  children,
  className,
}: {
  label: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  children: (ids: { id: string; describedBy?: string; invalid: boolean }) => React.ReactNode;
  className?: string;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  return (
    <div className={className}>
      <Label htmlFor={id}>{label}</Label>
      {children({ id, describedBy: hint || error ? hintId : undefined, invalid: !!error })}
      {(error || hint) && (
        <p id={hintId} className={cn("mt-1.5 text-xs", error ? "text-immediate" : "text-ink-3")}>
          {error || hint}
        </p>
      )}
    </div>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
  id,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: React.ReactNode;
  id?: string;
  disabled?: boolean;
}) {
  const auto = useId();
  const cid = id ?? auto;
  return (
    <label htmlFor={cid} className={cn("flex cursor-pointer items-start gap-2.5 text-sm text-ink-2", disabled && "opacity-50")}>
      <span className="relative mt-[2px] inline-flex h-4 w-4 shrink-0 items-center justify-center border border-ink">
        <input
          id={cid}
          type="checkbox"
          className="peer absolute inset-0 cursor-pointer opacity-0"
          checked={checked}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span
          aria-hidden
          className={cn(
            "h-2 w-2 bg-ink transition-transform duration-micro ease-press",
            checked ? "scale-100" : "scale-0"
          )}
        />
      </span>
      <span>{label}</span>
    </label>
  );
}

export function Switch({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: React.ReactNode;
  description?: React.ReactNode;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="flex w-full items-start justify-between gap-6 py-1 text-left disabled:opacity-50"
    >
      <span>
        <span className="block text-sm font-medium text-ink">{label}</span>
        {description && <span className="mt-0.5 block text-xs text-ink-3">{description}</span>}
      </span>
      <span
        aria-hidden
        className={cn(
          "relative mt-0.5 inline-flex h-5 w-9 shrink-0 border transition-colors duration-ui ease-instrument",
          checked ? "border-ink bg-ink" : "border-rule bg-surface"
        )}
      >
        <span
          className={cn(
            "absolute top-[3px] h-3 w-3 transition-transform duration-ui ease-press",
            checked ? "translate-x-[19px] bg-bg" : "translate-x-[3px] bg-ink-3"
          )}
        />
      </span>
    </button>
  );
}
